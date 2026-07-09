//! Data Integrity proof verification for the write-path Trust Tasks.
//!
//! The record-mutation tasks (`registry/record/{create,update,delete}`) declare
//! `IS_PROOF_REQUIRED`. The DIDComm and TSP bindings already reject a write with
//! no in-band `proof` (presence); this module adds the cryptographic step —
//! verifying the Data Integrity proof against the issuer's resolved key — so a
//! forged or tampered write is rejected, not merely a proofless one.
//!
//! Verification is backed by [`trust_tasks_proof`]'s Affinidi verifier over the
//! shared DID-resolver cache; `did:key` issuers verify offline, `did:web` /
//! `did:webvh` issuers resolve through the cache.

use std::sync::Arc;

use serde_json::Value;
use trust_tasks_proof::affinidi::{CachedDidResolver, Verifier};
use trust_tasks_rs::{DynProofVerifier, RejectReason, TrustTask, erase_verifier};

/// Slugs whose operations mutate the registry and therefore carry a required,
/// verifiable proof.
pub fn is_write_slug(slug: &str) -> bool {
    matches!(
        slug,
        "registry/record/create" | "registry/record/update" | "registry/record/delete"
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
/// Reads pass through unchanged. A proofless write also passes here — presence
/// is enforced separately by the binding's `authorize_write` before this call —
/// so this step only rejects a write whose *present* proof fails verification
/// ([`RejectReason::ProofInvalid`]).
pub async fn verify_write_proof(
    verifier: &Arc<dyn DynProofVerifier>,
    doc: &TrustTask<Value>,
) -> Result<(), RejectReason> {
    if !is_write_slug(doc.type_uri.slug()) || doc.proof.is_none() {
        return Ok(());
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
        let doc = doc_with_dummy_proof("https://trusttasks.org/spec/registry/record/create/0.1");
        assert!(matches!(
            verify_write_proof(&verifier, &doc).await,
            Err(RejectReason::ProofInvalid { .. })
        ));
    }
}
