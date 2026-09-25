//! Data Integrity proof verification for the write-path Trust Tasks.
//!
//! The record-mutation tasks (`registry/record/{put,delete}`) declare
//! `IS_PROOF_REQUIRED`. This module performs the cryptographic step —
//! verifying the Data Integrity proof against the issuer's resolved key — so a
//! forged or tampered write is rejected, not merely a proofless one. A write
//! with no proof, or with no in-band `issuer` for the proof to be bound to, is
//! refused outright rather than left to the verifier.
//!
//! Verification is backed by [`trust_tasks_proof`]'s Affinidi verifier over the
//! shared DID-resolver cache; `did:key` issuers verify offline, `did:web` /
//! `did:webvh` issuers resolve through the cache.

use std::sync::Arc;

use serde_json::Value;
use trust_tasks_proof::affinidi::{CachedDidResolver, Verifier};
use trust_tasks_rs::{DynProofVerifier, RejectReason, TrustTask, erase_verifier};

/// Slugs whose operations mutate the registry and therefore carry a required,
/// verifiable proof plus the admin ACL. The single source of truth — the
/// DIDComm and TSP bindings both gate on this list (they previously carried
/// diverging local copies: `registry/did/rotate` was gated over DIDComm but
/// not over TSP).
pub fn is_write_slug(slug: &str) -> bool {
    matches!(
        slug,
        "registry/record/put"
            | "registry/record/delete"
            | "registry/did/rotate"
            | "governance/capability/enable"
            | "governance/capability/disable"
            | "git-trust/grant"
            | "git-trust/revoke"
    )
}

/// Build a Data Integrity proof verifier backed by the Affinidi DID-resolver
/// cache. Falls back to a `did:key`-only verifier (no network) if the resolver
/// cache cannot be constructed, so proof verification degrades gracefully rather
/// than failing startup.
pub async fn build_verifier() -> Arc<dyn DynProofVerifier> {
    use affinidi_tdk::did_resolver::{DIDCacheClient, config::DIDCacheConfigBuilder};

    match DIDCacheClient::new(DIDCacheConfigBuilder::default().build()).await {
        Ok(client) => {
            let resolver = Arc::new(CachedDidResolver::new(Arc::new(client)));
            erase_verifier(Verifier::with_resolver(resolver))
        }
        Err(e) => {
            tracing::warn!(
                "DID resolver cache unavailable ({e}); Trust Task proof verification limited to did:key issuers"
            );
            erase_verifier(Verifier::for_did_key())
        }
    }
}

/// Cryptographically verify the Data Integrity proof on a **write** document.
///
/// Reads pass through unchanged. A write must carry a proof
/// ([`RejectReason::ProofRequired`]) and an in-band `issuer` the proof is bound
/// to ([`RejectReason::MalformedRequest`]); both are refused here as well as by
/// [`TaskHandler::authorize_write`](crate::trust_tasks::TaskHandler::authorize_write),
/// so this check is safe to call on its own. A present proof that fails
/// verification is [`RejectReason::ProofInvalid`].
pub async fn verify_write_proof(
    verifier: &Arc<dyn DynProofVerifier>,
    doc: &TrustTask<Value>,
) -> Result<(), RejectReason> {
    if !is_write_slug(doc.type_uri.slug()) {
        return Ok(());
    }
    if doc.proof.is_none() {
        return Err(RejectReason::ProofRequired);
    }
    if doc.issuer.is_none() {
        return Err(RejectReason::MalformedRequest {
            reason: "a write must name its issuer".to_string(),
        });
    }
    verifier
        .verify_json(doc)
        .await
        .map_err(|e| RejectReason::ProofInvalid {
            reason: e.to_string(),
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn doc_with_dummy_proof(type_uri: &str) -> TrustTask<Value> {
        let mut doc = TrustTask::new(
            "id-1",
            type_uri.parse().expect("valid type uri"),
            serde_json::json!({}),
        );
        doc.issuer = Some("did:example:admin".to_string());
        doc.proof = Some(
            serde_json::from_value(serde_json::json!({
                "type": "DataIntegrityProof",
                "cryptosuite": "eddsa-jcs-2022",
                "created": "2026-07-09T00:00:00Z",
                "proofPurpose": "assertionMethod",
                "verificationMethod": "did:example:admin#key-1",
                "proofValue": "z0000"
            }))
            .expect("valid proof fixture"),
        );
        doc
    }

    #[tokio::test]
    async fn read_document_skips_verification() {
        let verifier = erase_verifier(Verifier::for_did_key());
        let doc = doc_with_dummy_proof("https://trusttasks.org/spec/registry/recognition/0.1");
        assert!(verify_write_proof(&verifier, &doc).await.is_ok());
    }

    #[tokio::test]
    async fn write_with_bogus_proof_is_rejected() {
        // A did:key verifier rejects a proof whose verificationMethod is not a
        // resolvable did:key with a valid signature.
        let verifier = erase_verifier(Verifier::for_did_key());
        let doc = doc_with_dummy_proof("https://trusttasks.org/spec/registry/record/put/0.1");
        assert!(matches!(
            verify_write_proof(&verifier, &doc).await,
            Err(RejectReason::ProofInvalid { .. })
        ));
    }

    const RECORD_PUT: &str = "https://trusttasks.org/spec/registry/record/put/0.1";

    #[tokio::test]
    async fn write_without_proof_is_refused() {
        let verifier = erase_verifier(Verifier::for_did_key());
        let mut doc = doc_with_dummy_proof(RECORD_PUT);
        doc.proof = None;
        assert!(matches!(
            verify_write_proof(&verifier, &doc).await,
            Err(RejectReason::ProofRequired)
        ));
    }

    #[tokio::test]
    async fn write_without_issuer_is_refused() {
        let verifier = erase_verifier(Verifier::for_did_key());
        let mut doc = doc_with_dummy_proof(RECORD_PUT);
        doc.issuer = None;
        assert!(matches!(
            verify_write_proof(&verifier, &doc).await,
            Err(RejectReason::MalformedRequest { .. })
        ));
    }
}
