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

use affinidi_tdk::messaging::{ATM, profiles::ATMProfile};
use chrono::Utc;
use serde_json::Value;
use tracing::{error, info, warn};
use trust_tasks_rs::{RejectReason, TransportHandler, TrustTask};
use trust_tasks_tsp::{ENVELOPE_TYPE, TspHandler};
use uuid::Uuid;

use crate::trust_tasks::{RegistryDispatcher, handle_document};

fn new_id() -> String {
    Uuid::new_v4().to_string()
}

/// Slugs whose operations mutate the registry (admin ACL + proof required).
fn is_write_slug(slug: &str) -> bool {
    matches!(
        slug,
        "registry/record/create" | "registry/record/update" | "registry/record/delete"
    )
}

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
async fn handle_inbound(
    dispatcher: &RegistryDispatcher,
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
    match handle_document(dispatcher, doc).await {
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
pub async fn process_tsp_frame(
    atm: &Arc<ATM>,
    profile: &Arc<ATMProfile>,
    dispatcher: &RegistryDispatcher,
    admin_dids: &[String],
    verifier: &std::sync::Arc<dyn trust_tasks_rs::DynProofVerifier>,
    packed: &str,
) {
    let alias = &profile.inner.alias;
    let my_vid = &profile.inner.did;

    let (payload, sender_did) = match atm.tsp().unpack(profile, packed).await {
        Ok(v) => v,
        Err(e) => {
            warn!("[profile = {alias}] TSP unpack failed: {e}");
            return;
        }
    };
    let doc = match parse_envelope(&payload) {
        Ok(doc) => doc,
        Err(e) => {
            warn!("[profile = {alias}] Dropping TSP message from {sender_did}: {e}");
            return;
        }
    };
    info!(
        "[profile = {alias}, type = {}, from = {sender_did}] Trust Task (TSP)",
        doc.type_uri.slug()
    );
    let reply = handle_inbound(dispatcher, admin_dids, verifier, my_vid, &sender_did, doc).await;
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
