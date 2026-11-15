//! TSP (Trust Spanning Protocol) transport binding for the Trust Registry.
//!
//! Feature-gated behind `tsp` (off by default — `affinidi-tsp` is a moving 0.x
//! dependency). TSP frames arrive **multiplexed on the same mediator websocket**
//! as DIDComm: the mediator allows one websocket per DID, so the registry never
//! opens a second one for TSP.
//!
//! ## Receive path
//!
//! With `ENABLE_TSP=true` the registry receives through the SDK's
//! `DidCommTransport` ([`crate::messaging::service`]) for both
//! `DidCommSource::Managed` and `DidCommSource::SharedAtm`. The transport
//! unpacks each TSP frame, records relationship-control frames (Rev 3
//! §7.2.2) and hands application frames to [`dispatch_tsp_application`],
//! which feeds the same [`TaskHandler`] as DIDComm. With TSP disabled the
//! DIDComm pickup listener ([`crate::didcomm::listener`]) receives instead and
//! drops any TSP frame it sees.
//!
//! ## Wire format
//!
//! A Trust Task travels as the `trust-tasks-tsp` binding envelope — a JSON object
//! `{ "type": ENVELOPE_TYPE, "document": <TrustTask> }` — sealed inside a TSP
//! `Direct` message. The mediator's TSP relay delivers the sealed bytes; the
//! SDK's [`atm.tsp()`](affinidi_tdk::messaging::ATM) accessor performs all TSP
//! crypto and key management (the DID's Ed25519/X25519 keys serve as the VID
//! material), returning the decrypted envelope payload plus the authenticated
//! sender VID. We therefore build/parse the envelope JSON here and never handle
//! raw VID keys — staying wire-compatible with peers using the official
//! `trust-tasks-tsp` crate (e.g. VTC/OpenVTC).
//!
//! ## Validation
//!
//! End-to-end this path can only be exercised against a live TSP-capable
//! mediator (like the DIDComm integration tests). The pure logic — envelope
//! framing, §4.8.1 party resolution, freshness checks, and the record-write ACL
//! — is unit-tested here; the websocket transport is not.

use std::sync::Arc;

use affinidi_tdk::messaging::{ATM, profiles::ATMProfile};
use serde_json::Value;
use tracing::{error, info, warn};
use trust_tasks_rs::TrustTask;
use trust_tasks_tsp::ENVELOPE_TYPE;

use crate::trust_tasks::TaskHandler;

/// Parse a `trust-tasks-tsp` binding envelope (`{type, document}`) into a
/// framework document. Rejects a wrong or missing envelope type.
fn parse_envelope(payload: &[u8]) -> Result<TrustTask<Value>, String> {
    let envelope: Value =
        serde_json::from_slice(payload).map_err(|e| format!("invalid TSP envelope JSON: {e}"))?;
    match envelope.get("type").and_then(Value::as_str) {
        Some(t) if t == ENVELOPE_TYPE => {}
        other => return Err(format!("unexpected TSP envelope type: {other:?}")),
    }
    let document = envelope
        .get("document")
        .cloned()
        .ok_or_else(|| "TSP envelope missing `document`".to_string())?;
    serde_json::from_value(document).map_err(|e| format!("invalid Trust Task document: {e}"))
}

/// Serialise a response document into a `trust-tasks-tsp` binding envelope.
fn build_envelope<T: serde::Serialize>(doc: &T) -> Vec<u8> {
    let document = serde_json::to_value(doc).unwrap_or_else(|_| serde_json::json!({}));
    let envelope = serde_json::json!({ "type": ENVELOPE_TYPE, "document": document });
    serde_json::to_vec(&envelope).unwrap_or_default()
}

/// Route one decrypted inbound document (already authenticated by the TSP layer)
/// and produce the response envelope bytes to return to `sender_did`.
///
/// `sender_did` is the TSP-authenticated peer VID. Only envelope packing is
/// TSP's business; everything else, party resolution included, is the shared
/// [`TaskHandler`], which is what keeps this transport's write ACL, proof
/// verification and dedup identical to DIDComm's.
///
/// Also returns the outcome, so the caller can decide, once it knows whether
/// the reply was sent, whether the frame is acked ([`finality`]).
async fn handle_inbound(
    tasks: &TaskHandler,
    sender_did: &str,
    doc: TrustTask<Value>,
) -> (
    Vec<u8>,
    Result<TrustTask<Value>, trust_tasks_rs::ErrorResponse>,
) {
    let outcome = tasks.handle(doc, Some(sender_did)).await;
    let reply = match &outcome {
        Ok(response) => build_envelope(response),
        Err(err) => build_envelope(err),
    };
    (reply, outcome)
}

/// Whether the frame answered with `outcome` is acked, given whether the
/// reply was sent ([`crate::trust_tasks::leave_queued`]).
///
/// R1.6, handoff to the sender: a retryable refusal that was sent hands the
/// retry to the sender, so the frame is acked (the registry retrying it too
/// could apply the same mutation twice, under the sender's new document id,
/// or land it after a later write); one that could not be sent is kept. The
/// DIDComm binding applies the same rule.
fn finality(
    outcome: &Result<TrustTask<Value>, trust_tasks_rs::ErrorResponse>,
    reply_sent: bool,
) -> TspDispatch {
    if crate::trust_tasks::leave_queued(outcome, reply_sent) {
        TspDispatch::Retryable
    } else {
        TspDispatch::Answered
    }
}

/// How [`dispatch_tsp_application`] ended, which decides whether the receive
/// loop acks the frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TspDispatch {
    /// Ack the frame: a final answer (a response, or a refusal that will not
    /// change on a retry: permission denied, a bad proof, …), sent or not, or
    /// a retryable refusal that reached the sender, which now owns the retry.
    Answered,
    /// Keep the frame queued: the registry could not decide now (the refusal
    /// is `retryable`: storage unavailable, an internal error, the same
    /// document still being handled, the issuer's DID failing to resolve
    /// transiently) and the refusal could not be sent, so the sender does
    /// not know to retry. The registry tries it again under the delivery
    /// give-up bounds; a write is still applied at most once per document
    /// id, through the dedup store.
    Retryable,
}

/// Dispatch one **already-unpacked** inbound TSP application frame, and seal
/// the reply back to the sender over the shared mediator socket.
///
/// The SDK's `DidCommTransport` unpacked the frame (and retried a transient
/// unpack failure) before it reached here, so only the envelope parse, the
/// dispatch and the reply remain.
///
/// Returns `Err` when the payload is not a Trust Task envelope: a property of
/// the frame, which the receive loop acks as poison; otherwise whether to ack
/// it ([`TspDispatch`]). A reply that cannot be sent is logged. It changes
/// nothing for a final answer, which has been recorded (a write applied): a
/// client that retries with the same document id gets it replayed. A
/// retryable refusal that cannot be sent keeps the frame queued.
pub async fn dispatch_tsp_application(
    atm: &Arc<ATM>,
    profile: &Arc<ATMProfile>,
    tasks: &TaskHandler,
    payload: &[u8],
    sender_did: &str,
) -> Result<TspDispatch, String> {
    let alias = &profile.inner.alias;
    let doc = match parse_envelope(payload) {
        Ok(doc) => doc,
        Err(e) => {
            warn!("[profile = {alias}] Dropping TSP message from {sender_did}: {e}");
            return Err(e);
        }
    };
    info!(
        "[profile = {alias}, type = {}, from = {sender_did}] Trust Task (TSP)",
        doc.type_uri.slug()
    );
    let (reply, outcome) = handle_inbound(tasks, sender_did, doc).await;
    let reply_sent = match atm.tsp().send(profile, sender_did, &reply).await {
        Ok(_) => true,
        Err(e) => {
            error!("[profile = {alias}] Failed to send TSP response to {sender_did}: {e}");
            false
        }
    };
    // R1.6, handoff to the sender: see `finality`.
    Ok(finality(&outcome, reply_sent))
}

#[cfg(test)]
// `deprecated`: the queries are the superseded 0.1 versions, which this
// registry still serves.
#[allow(clippy::unwrap_used, clippy::expect_used, deprecated)]
mod tests {
    use super::*;

    // The write ACL these tests used to cover moved to
    // `crate::trust_tasks::handler`, along with `authorize_write` itself — it is
    // now shared with the DIDComm binding rather than duplicated here, and is
    // tested once at its new home.

    use crate::trust_tasks::payloads::{AuthorizationResponse, RecognitionResponse};
    use crate::trust_tasks::test_support::{CLIENT_DID, query_doc, seeded_handler};
    use crate::trust_tasks::type_uris;

    /// Route `type_uri` as the TSP binding does, through the same shared
    /// handler as DIDComm: envelope bytes in, envelope bytes out.
    async fn query_over_tsp(type_uri: &str) -> TrustTask<Value> {
        let tasks = seeded_handler();
        let inbound = parse_envelope(&build_envelope(&query_doc(type_uri))).expect("envelope");
        let (reply, outcome) = handle_inbound(&tasks, CLIENT_DID, inbound).await;
        assert_eq!(finality(&outcome, true), TspDispatch::Answered);
        assert_eq!(finality(&outcome, false), TspDispatch::Answered);
        parse_envelope(&reply).expect("reply envelope")
    }

    /// R1.6, handoff to the sender: a refusal that may change on a retry
    /// (storage unavailable, an internal error) is acked once it reached the
    /// sender, which owns the retry, and leaves the frame queued only when it
    /// could not be sent; a final refusal is acked either way.
    #[test]
    fn a_retryable_refusal_is_kept_only_when_it_was_not_sent() {
        use trust_tasks_rs::RejectReason;
        let doc = query_doc(type_uris::RECOGNITION);
        let unavailable =
            Err(doc.reject_with("r1", RejectReason::Unavailable { retry_after: None }));
        assert_eq!(finality(&unavailable, false), TspDispatch::Retryable);
        assert_eq!(finality(&unavailable, true), TspDispatch::Answered);
        let internal = Err(doc.reject_with(
            "r2",
            RejectReason::InternalError {
                reason: "storage connection failed".into(),
            },
        ));
        assert_eq!(finality(&internal, false), TspDispatch::Retryable);
        assert_eq!(finality(&internal, true), TspDispatch::Answered);
        let denied = Err(doc.reject_with(
            "r3",
            RejectReason::PermissionDenied {
                reason: "not an admin".into(),
            },
        ));
        assert_eq!(finality(&denied, false), TspDispatch::Answered);
        assert_eq!(finality(&denied, true), TspDispatch::Answered);
    }

    #[tokio::test]
    async fn registry_recognition_over_tsp() {
        let reply = query_over_tsp(type_uris::RECOGNITION).await;
        assert!(reply.type_uri.is_response());
        assert_eq!(reply.type_uri.slug(), "registry/recognition");
        let answer: RecognitionResponse = serde_json::from_value(reply.payload).unwrap();
        assert!(answer.recognized);
    }

    #[tokio::test]
    async fn registry_authorization_over_tsp() {
        let reply = query_over_tsp(type_uris::AUTHORIZATION).await;
        assert!(reply.type_uri.is_response());
        assert_eq!(reply.type_uri.slug(), "registry/authorization");
        let answer: AuthorizationResponse = serde_json::from_value(reply.payload).unwrap();
        assert!(answer.authorized);
    }

    #[test]
    fn envelope_round_trips() {
        let doc = query_doc(type_uris::RECOGNITION);
        let bytes = build_envelope(&doc);
        let parsed = parse_envelope(&bytes).expect("round-trips");
        assert_eq!(parsed.type_uri.slug(), "registry/recognition");
    }

    #[test]
    fn envelope_rejects_wrong_type() {
        // Raw JSON: a binding envelope of the wrong type, which no generated
        // type expresses.
        let bytes = serde_json::to_vec(&serde_json::json!({
            "type": "https://example.com/not-tsp",
            "document": {}
        }))
        .unwrap();
        assert!(parse_envelope(&bytes).is_err());
    }
}
