//! TSP (Trust Spanning Protocol) transport binding for the Trust Registry.
//!
//! Feature-gated behind `tsp` (off by default — `affinidi-tsp` is a moving 0.x
//! dependency). TSP frames arrive **multiplexed on the same mediator websocket**
//! as DIDComm (the DIDComm listener pulls both via `live_stream_next_frame` and
//! routes `InboundFrame::Tsp` frames here) and feed the same
//! [`RegistryDispatcher`](crate::trust_tasks::RegistryDispatcher). The registry
//! must not open a second websocket: the mediator allows only one per DID.
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
use std::time::Duration;

use affinidi_tdk::messaging::{ATM, errors::ATMError, profiles::ATMProfile};
use chrono::Utc;
use serde_json::Value;
use tracing::{error, info, warn};
use trust_tasks_rs::{RejectReason, TransportHandler, TrustTask};
use trust_tasks_tsp::{ENVELOPE_TYPE, TspHandler};
use uuid::Uuid;

use crate::dedup::{MessageIdStore, dispatch_idempotent};
use crate::trust_tasks::RegistryDispatcher;

fn new_id() -> String {
    Uuid::new_v4().to_string()
}

/// Attempts (including the first) for an unpack whose failure looks transient.
const UNPACK_MAX_ATTEMPTS: u32 = 3;
/// Backoff before the second attempt; doubles up to [`UNPACK_MAX_BACKOFF`].
const UNPACK_INITIAL_BACKOFF: Duration = Duration::from_millis(200);
/// Ceiling on the backoff. The receive loop has already moved on (each frame is
/// handled on its own task), but a stuck resolver should not pin a task for long.
const UNPACK_MAX_BACKOFF: Duration = Duration::from_millis(1_000);

/// Is this unpack failure worth retrying, or is the frame poison?
///
/// The distinction matters because the frame has **already been deleted from
/// the mediator** by the time we unpack it (R1.6): whatever we drop here is
/// gone for good. A transient failure is therefore the dangerous case — a
/// momentary resolver outage would otherwise discard a valid signed registry
/// write — so anything resolution- or network-shaped is retried, and only
/// failures that are deterministic properties of the bytes are treated as
/// poison.
///
/// Mapping (see `affinidi-messaging-sdk` `protocols/tsp.rs`):
///
/// - [`ATMError::DIDError`] — resolving the sender's VID or our own DID failed.
///   The overwhelmingly common transient case.
/// - [`ATMError::TransportError`] / [`ATMError::Disconnected`] /
///   [`ATMError::TDKError`] — network or resolver-cache trouble underneath.
/// - [`ATMError::MsgReceiveError`] — envelope parse failure, a message addressed
///   to another DID, or decrypt/verify failure. Retrying identical bytes cannot
///   change any of these.
/// - Everything else (notably [`ATMError::SecretsError`], our own key material
///   missing) is a local misconfiguration that retrying will not fix; it is
///   logged at error level rather than silently dropped.
///
/// `DIDError` does conflate "the resolver is briefly unreachable" with "this DID
/// does not exist", and the SDK gives us only a string to go on. Treating both
/// as transient is the deliberate choice: retrying a genuinely bad DID costs a
/// few hundred milliseconds on a task that has already been spawned, while
/// dropping a good one loses a signed write permanently.
fn is_transient_unpack_error(err: &ATMError) -> bool {
    matches!(
        err,
        ATMError::DIDError(_)
            | ATMError::TransportError(_)
            | ATMError::Disconnected(_)
            | ATMError::TDKError(_)
    )
}

/// Run `op`, retrying with exponential backoff while it fails transiently.
///
/// Returns the first success, or the final error once attempts are exhausted or
/// a non-transient error is seen. Generic over the operation so the retry policy
/// is testable without a live mediator.
async fn retry_transient<T, F, Fut>(
    attempts: u32,
    initial_backoff: Duration,
    max_backoff: Duration,
    mut op: F,
) -> Result<T, ATMError>
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = Result<T, ATMError>>,
{
    let mut backoff = initial_backoff;
    let mut attempt = 1;
    loop {
        match op().await {
            Ok(value) => return Ok(value),
            Err(err) => {
                if attempt >= attempts || !is_transient_unpack_error(&err) {
                    return Err(err);
                }
                warn!(
                    "TSP unpack failed transiently (attempt {attempt}/{attempts}), \
                     retrying in {backoff:?}: {err}"
                );
                tokio::time::sleep(backoff).await;
                backoff = (backoff * 2).min(max_backoff);
                attempt += 1;
            }
        }
    }
}

/// Slugs whose operations mutate the registry (admin ACL + proof required).
use crate::trust_tasks::proof::is_write_slug;

/// Write-only preconditions the transport-agnostic dispatcher does not enforce:
/// proof presence + admin-DID ACL. Reads pass through.
fn authorize_write(
    doc: &TrustTask<Value>,
    sender_did: &str,
    admin_dids: &[String],
) -> Result<(), RejectReason> {
    if !is_write_slug(doc.type_uri.slug()) {
        return Ok(());
    }
    if doc.proof.is_none() {
        return Err(RejectReason::ProofRequired);
    }
    if !admin_dids.iter().any(|d| d == sender_did) {
        return Err(RejectReason::PermissionDenied {
            reason: format!("DID {sender_did} is not authorised to modify the registry"),
        });
    }
    Ok(())
}

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
/// `sender_did` is the TSP-authenticated peer VID; `my_vid` is our own DID.
#[allow(clippy::too_many_arguments)]
async fn handle_inbound(
    dispatcher: &RegistryDispatcher,
    dedup: &dyn MessageIdStore,
    admin_dids: &[String],
    verifier: &std::sync::Arc<dyn trust_tasks_rs::DynProofVerifier>,
    my_vid: &str,
    sender_did: &str,
    doc: TrustTask<Value>,
) -> Vec<u8> {
    // §4.8.1 party resolution: TSP-authenticated sender -> issuer, us -> recipient.
    let transport = TspHandler::new(Some(my_vid.to_string()), Some(sender_did.to_string()));
    if let Err(consistency) = transport.resolve_parties(&doc) {
        let err = doc.reject_with_recipient(
            new_id(),
            RejectReason::from(consistency),
            Some(sender_did.to_string()),
        );
        return build_envelope(&err);
    }
    if let Err(reason) = doc.validate_basic(Utc::now(), my_vid) {
        return build_envelope(&doc.reject_with(new_id(), reason));
    }
    if let Err(reason) = authorize_write(&doc, sender_did, admin_dids) {
        return build_envelope(&doc.reject_with(new_id(), reason));
    }
    // Cryptographically verify the write's Data Integrity proof.
    if let Err(reason) = crate::trust_tasks::verify_write_proof(verifier, &doc).await {
        return build_envelope(&doc.reject_with(new_id(), reason));
    }
    match dispatch_idempotent(dispatcher, dedup, doc).await {
        Ok(response) => build_envelope(&response),
        Err(err) => build_envelope(&err),
    }
}

/// Process one inbound TSP frame delivered on the **shared** mediator pickup
/// socket (the same websocket the DIDComm listener drives via
/// `live_stream_next_frame`). Decrypts it via `atm.tsp()`, routes it through the
/// shared dispatcher (proof-verifying writes), and seals the response back to the
/// sender.
///
/// `packed` is the CESR/qb64 stored string carried by `InboundFrame::Tsp` — so we
/// unpack with `atm.tsp().unpack` (which base64url-decodes first), **not**
/// `unpack_bytes` (that is for the raw `connect_websocket` path, which yields
/// already-decoded qb2). The mediator permits only one websocket per DID, so the
/// registry must never open a second TSP socket — TSP frames arrive multiplexed
/// on the DIDComm pickup stream.
#[allow(clippy::too_many_arguments)]
pub async fn process_tsp_frame(
    atm: &Arc<ATM>,
    profile: &Arc<ATMProfile>,
    dispatcher: &RegistryDispatcher,
    dedup: &dyn MessageIdStore,
    admin_dids: &[String],
    verifier: &std::sync::Arc<dyn trust_tasks_rs::DynProofVerifier>,
    packed: &str,
) {
    let alias = &profile.inner.alias;
    let my_vid = &profile.inner.did;

    // R1.6 — deliberate ack-first, with the loss window narrowed rather than
    // closed. `process_next_message` pulls frames with `auto_delete = true`, so
    // the mediator has already deleted this frame before we see it: there is no
    // ack left to withhold. Acking first is retained as poison defence — a frame
    // that cannot be unpacked would otherwise be redelivered forever.
    //
    // What we can do is stop *transient* failures from consuming the one chance
    // we get. The packed bytes are still in memory, so a resolver hiccup is
    // retried in-process instead of discarding a valid signed registry write.
    //
    // Write-path dedup now exists ([`crate::dedup`]), so a redelivery would
    // replay rather than duplicate — but only the in-memory store is wired up,
    // and it forgets across a restart. Deferring the delete until after durable
    // handoff therefore waits on a durable dedup store; tracked separately.
    let unpacked = retry_transient(
        UNPACK_MAX_ATTEMPTS,
        UNPACK_INITIAL_BACKOFF,
        UNPACK_MAX_BACKOFF,
        // `atm.tsp()` returns a temporary, so build the future inside the async
        // block where that temporary outlives the borrow.
        || async { atm.tsp().unpack(profile, packed).await },
    )
    .await;

    let (payload, sender_did) = match unpacked {
        Ok(v) => v,
        Err(e) if is_transient_unpack_error(&e) => {
            // Retries exhausted on a recoverable fault: this is a lost write,
            // not a rejected one. Logged at error level because it is a
            // durability event an operator needs to see, not routine noise.
            error!(
                "[profile = {alias}] TSP unpack still failing after {UNPACK_MAX_ATTEMPTS} \
                 attempts; the frame is already deleted from the mediator, so a signed \
                 registry write may have been lost: {e}"
            );
            return;
        }
        Err(e) => {
            // Poison: retrying identical bytes cannot succeed.
            warn!("[profile = {alias}] Dropping unusable TSP frame: {e}");
            return;
        }
    };
    let doc = match parse_envelope(&payload) {
        Ok(doc) => doc,
        Err(e) => {
            // Also poison — it decrypted cleanly and the contents are wrong.
            warn!("[profile = {alias}] Dropping TSP message from {sender_did}: {e}");
            return;
        }
    };
    info!(
        "[profile = {alias}, type = {}, from = {sender_did}] Trust Task (TSP)",
        doc.type_uri.slug()
    );
    let reply = handle_inbound(
        dispatcher,
        dedup,
        admin_dids,
        verifier,
        my_vid,
        &sender_did,
        doc,
    )
    .await;
    if let Err(e) = atm.tsp().send(profile, &sender_did, &reply).await {
        error!("[profile = {alias}] Failed to send TSP response to {sender_did}: {e}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn doc_with(type_uri: &str, proof: bool) -> TrustTask<Value> {
        let mut doc = TrustTask::new(
            new_id(),
            type_uri.parse().expect("valid type uri"),
            serde_json::json!({}),
        );
        if proof {
            doc.proof = Some(
                serde_json::from_value(serde_json::json!({
                    "type": "DataIntegrityProof",
                    "cryptosuite": "eddsa-jcs-2022",
                    "created": "2026-07-07T00:00:00Z",
                    "proofPurpose": "assertionMethod",
                    "verificationMethod": "did:example:admin#key-1",
                    "proofValue": "z0000"
                }))
                .expect("valid proof fixture"),
            );
        }
        doc
    }

    const ADMIN: &str = "did:example:admin";
    const CREATE: &str = "https://trusttasks.org/spec/registry/record/create/0.1";
    const RECOGNITION: &str = "https://trusttasks.org/spec/registry/recognition/0.1";

    #[test]
    fn reads_bypass_write_authorization() {
        let doc = doc_with(RECOGNITION, false);
        assert!(authorize_write(&doc, "did:example:anyone", &[]).is_ok());
    }

    #[test]
    fn write_without_proof_is_rejected() {
        let doc = doc_with(CREATE, false);
        assert!(matches!(
            authorize_write(&doc, ADMIN, &[ADMIN.to_string()]),
            Err(RejectReason::ProofRequired)
        ));
    }

    #[test]
    fn write_from_non_admin_is_denied() {
        let doc = doc_with(CREATE, true);
        assert!(matches!(
            authorize_write(&doc, "did:example:intruder", &[ADMIN.to_string()]),
            Err(RejectReason::PermissionDenied { .. })
        ));
    }

    #[test]
    fn write_from_admin_with_proof_is_allowed() {
        let doc = doc_with(CREATE, true);
        assert!(authorize_write(&doc, ADMIN, &[ADMIN.to_string()]).is_ok());
    }

    #[test]
    fn envelope_round_trips() {
        let doc = doc_with(RECOGNITION, false);
        let bytes = build_envelope(&doc);
        let parsed = parse_envelope(&bytes).expect("round-trips");
        assert_eq!(parsed.type_uri.slug(), "registry/recognition");
    }

    // --- R1.6 transient/poison classification --------------------------

    use std::sync::atomic::{AtomicU32, Ordering};

    /// Fast backoffs so the retry tests do not sleep for real.
    const TEST_BACKOFF: Duration = Duration::from_millis(1);

    #[test]
    fn resolver_failures_are_transient() {
        // The case R1.6 exists for: a momentary resolver outage must not be
        // mistaken for a bad message.
        assert!(is_transient_unpack_error(&ATMError::DIDError(
            "couldn't resolve TSP VID did:web:peer".into()
        )));
        assert!(is_transient_unpack_error(&ATMError::TransportError(
            "connection reset".into()
        )));
        assert!(is_transient_unpack_error(&ATMError::TDKError(
            "resolver cache miss".into()
        )));
    }

    /// Bytes that cannot decrypt or parse will never succeed, however often we
    /// try — retrying them would just delay the drop.
    #[test]
    fn crypto_and_parse_failures_are_poison() {
        assert!(!is_transient_unpack_error(&ATMError::MsgReceiveError(
            "couldn't unpack TSP message: bad signature".into()
        )));
        assert!(!is_transient_unpack_error(&ATMError::MsgReceiveError(
            "couldn't parse TSP envelope: truncated".into()
        )));
        // Our own key material missing is a local misconfiguration.
        assert!(!is_transient_unpack_error(&ATMError::SecretsError(
            "no Ed25519 authentication key".into()
        )));
    }

    #[tokio::test]
    async fn transient_failure_is_retried_until_it_succeeds() {
        let calls = AtomicU32::new(0);
        let result: Result<&str, ATMError> =
            retry_transient(3, TEST_BACKOFF, TEST_BACKOFF, || async {
                // Fail twice, then succeed — the resolver-recovers case.
                if calls.fetch_add(1, Ordering::SeqCst) < 2 {
                    Err(ATMError::DIDError("resolver down".into()))
                } else {
                    Ok("unpacked")
                }
            })
            .await;

        assert_eq!(result.expect("succeeds on third attempt"), "unpacked");
        assert_eq!(calls.load(Ordering::SeqCst), 3);
    }

    #[tokio::test]
    async fn poison_is_not_retried() {
        let calls = AtomicU32::new(0);
        let result: Result<&str, ATMError> =
            retry_transient(3, TEST_BACKOFF, TEST_BACKOFF, || async {
                calls.fetch_add(1, Ordering::SeqCst);
                Err(ATMError::MsgReceiveError("bad signature".into()))
            })
            .await;

        assert!(result.is_err());
        assert_eq!(
            calls.load(Ordering::SeqCst),
            1,
            "poison must fail on the first attempt, not burn the retry budget"
        );
    }

    #[tokio::test]
    async fn transient_failure_gives_up_after_the_attempt_budget() {
        let calls = AtomicU32::new(0);
        let result: Result<&str, ATMError> =
            retry_transient(3, TEST_BACKOFF, TEST_BACKOFF, || async {
                calls.fetch_add(1, Ordering::SeqCst);
                Err(ATMError::DIDError("resolver still down".into()))
            })
            .await;

        // The final error stays transient-classified so the call site can log
        // it as a possible lost write rather than a rejection.
        let err = result.expect_err("gives up");
        assert!(is_transient_unpack_error(&err));
        assert_eq!(calls.load(Ordering::SeqCst), 3);
    }

    #[tokio::test]
    async fn first_attempt_success_does_not_sleep() {
        let calls = AtomicU32::new(0);
        let result: Result<&str, ATMError> = retry_transient(
            3,
            Duration::from_secs(30),
            Duration::from_secs(30),
            || async {
                calls.fetch_add(1, Ordering::SeqCst);
                Ok("unpacked")
            },
        )
        .await;

        // A 30s backoff would hang the test if the happy path slept.
        assert!(result.is_ok());
        assert_eq!(calls.load(Ordering::SeqCst), 1);
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
