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
//!
//! A registry write is an operational message (VTI-KEY-084, VTI-KEY-106): it
//! is signed with the writer's `operational` key, carries the proof purpose
//! `authentication`, and the key must be listed under `authentication` in the
//! writer's DID document. [`AuthenticationKeyResolver`] enforces the last part,
//! so a key the writer lists only under `assertionMethod` cannot sign a write.

use std::sync::Arc;

use affinidi_tdk::data_integrity::{DataIntegrityError, ResolvedKey};
use affinidi_tdk::did_common::Document;
use affinidi_tdk::did_common::verification_method::VerificationRelationship;
use affinidi_tdk::did_resolver::DIDCacheClient;
use async_trait::async_trait;
use serde_json::Value;
use trust_tasks_proof::affinidi::{
    CachedDidResolver, ProofPurpose, ProofPurposeResolver, Verifier,
};
use trust_tasks_rs::{DynProofVerifier, RejectReason, TrustTask, erase_verifier};

/// The only `proofPurpose` a registry write may carry (VTI-KEY-106).
pub const WRITE_PROOF_PURPOSE: &str = "authentication";

/// Is `vm` one of the methods `doc` lists under `authentication`, by absolute
/// DID URL or relative fragment, referenced or embedded?
pub fn is_authentication_method(doc: &Document, vm: &str) -> bool {
    let fragment = vm.find('#').map(|i| &vm[i..]);
    let refers = |id: &str| id == vm || fragment.is_some_and(|f| id == f);
    doc.authentication
        .iter()
        .any(|relationship| match relationship {
            VerificationRelationship::Reference(id) => refers(id),
            VerificationRelationship::VerificationMethod(method) => refers(method.id.as_str()),
            _ => false,
        })
}

/// Resolves a proof's verification method only when the controlling DID
/// document lists it under `authentication`, whatever `proofPurpose` the proof
/// declares, through [`CachedDidResolver`] (which also requires the method's
/// controller to be the DID that names it).
pub struct AuthenticationKeyResolver {
    keys: CachedDidResolver,
}

impl AuthenticationKeyResolver {
    pub fn new(client: Arc<DIDCacheClient>) -> Self {
        Self {
            keys: CachedDidResolver::new(client),
        }
    }
}

#[async_trait]
impl ProofPurposeResolver for AuthenticationKeyResolver {
    async fn resolve_vm_for_purpose(
        &self,
        vm: &str,
        _purpose: ProofPurpose,
    ) -> Result<ResolvedKey, DataIntegrityError> {
        self.keys
            .resolve_vm_for_purpose(vm, ProofPurpose::Authentication)
            .await
    }
}

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

/// Slugs a caller may only use with a proof bound to its sender, under the
/// same rules as a write: the writes, plus `registry/record/query`, whose
/// answers carry whole records (context included) rather than the yes/no of
/// the public TRQP queries.
pub fn requires_proof(slug: &str) -> bool {
    is_write_slug(slug) || slug == "registry/record/query"
}

/// Build a Data Integrity proof verifier backed by the Affinidi DID-resolver
/// cache, accepting only keys the signer lists under `authentication`. Falls
/// back to a `did:key`-only verifier (no network) if the resolver cache cannot
/// be constructed, so proof verification degrades gracefully rather than
/// failing startup; a `did:key`'s only key is by construction its
/// authentication key.
pub async fn build_verifier() -> Arc<dyn DynProofVerifier> {
    use affinidi_tdk::did_resolver::{DIDCacheClient, config::DIDCacheConfigBuilder};

    match DIDCacheClient::new(DIDCacheConfigBuilder::default().build()).await {
        Ok(client) => {
            let resolver = Arc::new(AuthenticationKeyResolver::new(Arc::new(client)));
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
    if !requires_proof(doc.type_uri.slug()) {
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

    fn document(authentication: Value) -> Document {
        serde_json::from_value(serde_json::json!({
            "id": "did:example:writer",
            "verificationMethod": [{
                "id": "did:example:writer#key-1",
                "type": "Multikey",
                "controller": "did:example:writer",
                "publicKeyMultibase": "z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"
            }],
            "authentication": authentication,
            "assertionMethod": ["did:example:writer#key-1"]
        }))
        .expect("valid DID document")
    }

    #[test]
    fn a_key_listed_under_authentication_is_accepted() {
        let doc = document(serde_json::json!(["#key-1"]));
        assert!(is_authentication_method(&doc, "did:example:writer#key-1"));
    }

    #[test]
    fn a_key_listed_only_under_assertion_method_is_refused() {
        let doc = document(serde_json::json!([]));
        assert!(!is_authentication_method(&doc, "did:example:writer#key-1"));
    }
}
