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
async fn handle_inbound(tasks: &TaskHandler, sender_did: &str, doc: TrustTask<Value>) -> Vec<u8> {
    match tasks.handle(doc, Some(sender_did)).await {
        Ok(response) => build_envelope(&response),
        Err(err) => build_envelope(&err),
    }
}

/// Dispatch one **already-unpacked** inbound TSP application frame, and seal
/// the reply back to the sender over the shared mediator socket.
///
/// The SDK's `DidCommTransport` unpacked the frame (and retried a transient
/// unpack failure) before it reached here, so only the envelope parse, the
/// dispatch and the reply remain.
///
/// Returns `Err` when the payload is not a Trust Task envelope: a property of
/// the frame, which the receive loop acks as poison. A reply that cannot be
/// sent is logged and the frame still counts as handled: the request (a write
/// included) has been applied, and a client that retries with the same
/// document id gets the recorded outcome replayed.
pub async fn dispatch_tsp_application(
    atm: &Arc<ATM>,
    profile: &Arc<ATMProfile>,
    tasks: &TaskHandler,
    payload: &[u8],
    sender_did: &str,
) -> Result<(), String> {
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
    let reply = handle_inbound(tasks, sender_did, doc).await;
    if let Err(e) = atm.tsp().send(profile, sender_did, &reply).await {
        error!("[profile = {alias}] Failed to send TSP response to {sender_did}: {e}");
    }
    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    fn doc_with(type_uri: &str, proof: bool) -> TrustTask<Value> {
        let mut doc = TrustTask::new(
            uuid::Uuid::new_v4().to_string(),
            type_uri.parse().expect("valid type uri"),
            serde_json::json!({}),
        );
        if proof {
            doc.proof = Some(
                serde_json::from_value(serde_json::json!({
                    "type": "DataIntegrityProof",
                    "cryptosuite": "eddsa-jcs-2022",
                    "created": "2026-07-07T00:00:00Z",
                    "proofPurpose": "authentication",
                    "verificationMethod": "did:example:admin#key-1",
                    "proofValue": "z0000"
                }))
                .expect("valid proof fixture"),
            );
        }
        doc
    }

    const RECOGNITION: &str = "https://trusttasks.org/spec/registry/recognition/0.1";

    // The write ACL these tests used to cover moved to
    // `crate::trust_tasks::handler`, along with `authorize_write` itself — it is
    // now shared with the DIDComm binding rather than duplicated here, and is
    // tested once at its new home.

    use crate::trust_tasks::test_support::{CLIENT_DID, query_doc, seeded_handler};
    use crate::trust_tasks::type_uris;

    /// Route `type_uri` as the TSP binding does, through the same shared
    /// handler as DIDComm: envelope bytes in, envelope bytes out.
    async fn query_over_tsp(type_uri: &str) -> TrustTask<Value> {
        let tasks = seeded_handler();
        let inbound = parse_envelope(&build_envelope(&query_doc(type_uri))).expect("envelope");
        let reply = handle_inbound(&tasks, CLIENT_DID, inbound).await;
        parse_envelope(&reply).expect("reply envelope")
    }

    #[tokio::test]
    async fn registry_recognition_over_tsp() {
        let reply = query_over_tsp(type_uris::RECOGNITION).await;
        assert!(reply.type_uri.is_response());
        assert_eq!(reply.type_uri.slug(), "registry/recognition");
        assert_eq!(reply.payload["recognized"], serde_json::json!(true));
    }

    #[tokio::test]
    async fn registry_authorization_over_tsp() {
        let reply = query_over_tsp(type_uris::AUTHORIZATION).await;
        assert!(reply.type_uri.is_response());
        assert_eq!(reply.type_uri.slug(), "registry/authorization");
        assert_eq!(reply.payload["authorized"], serde_json::json!(true));
    }

    #[test]
    fn envelope_round_trips() {
        let doc = doc_with(RECOGNITION, false);
        let bytes = build_envelope(&doc);
        let parsed = parse_envelope(&bytes).expect("round-trips");
        assert_eq!(parsed.type_uri.slug(), "registry/recognition");
    }

    #[test]
    fn envelope_rejects_wrong_type() {
        let bytes = serde_json::to_vec(&serde_json::json!({
            "type": "https://example.com/not-tsp",
            "document": {}
        }))
        .unwrap();
        assert!(parse_envelope(&bytes).is_err());
    }
}
