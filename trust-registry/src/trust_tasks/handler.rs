//! Transport-agnostic Trust Task handler.
//!
//! Every transport binding — DIDComm, TSP, HTTP, or a host application driving
//! an embedded registry — decodes its own wire format into a
//! `TrustTask<Value>`, learns who sent it, and then applies the *same* sequence
//! of checks before routing:
//!
//! 1. party resolution (SPEC §4.8.1): an in-band `issuer` must equal the
//!    sender the transport authenticated ([`TaskHandler::resolve_issuer`]);
//! 2. framework freshness + recipient checks ([`TrustTask::validate_basic`]);
//! 3. the write-only preconditions the dispatcher does not enforce — proof
//!    presence, an in-band `issuer` that is the authenticated sender and the
//!    controller of the proof's verification method, and the admin-DID ACL
//!    ([`TaskHandler::authorize_write`]);
//! 4. cryptographic Data-Integrity verification of a write's proof
//!    ([`crate::trust_tasks::verify_write_proof`]);
//! 5. the authority binding for record mutations: a record may only be
//!    written or deleted under an authority the issuer may act for
//!    ([`TaskHandler::authorize_authority`]);
//! 6. `registry/did/rotate`, which acts on *our own* DID via the VTA rather
//!    than on the record repository, so it never reaches the dispatcher;
//! 7. dispatch, deduplicated by message id when a store is configured.
//!
//! That sequence used to be written out once per binding, with `authorize_write`
//! copy-pasted between the DIDComm and TSP handlers. Keeping one copy is what
//! makes it safe to add a transport — including a host that owns its own
//! socket and calls [`TaskHandler::handle`] directly.
//!
//! What stays in the bindings is only what is genuinely transport-specific:
//! establishing which sender the transport authenticated, and packing the
//! returned document back onto the wire. Party resolution happens here, so a
//! host calling [`TaskHandler::handle`] directly gets it too.
//!
//! The transport-authenticated sender alone never authorises a write. A write
//! is accepted only when its Data Integrity proof verifies against a key the
//! in-band `issuer` controls, that issuer is the authenticated sender, and the
//! issuer is on the admin list.

use std::collections::HashMap;
use std::sync::Arc;

use chrono::Utc;
use serde_json::Value;
use trust_tasks_rs::{ConsistencyError, DynProofVerifier, ErrorResponse, RejectReason, TrustTask};
use uuid::Uuid;

use crate::capabilities::DispatcherHandle;
use crate::dedup::{MessageIdStore, dispatch_idempotent};
use crate::trust_tasks::handle_document;
use crate::trust_tasks::proof::{is_write_slug, verify_write_proof};

/// The only `proofPurpose` a registry write may carry.
const WRITE_PROOF_PURPOSE: &str = "assertionMethod";

fn new_id() -> String {
    Uuid::new_v4().to_string()
}

/// The authority a record mutation targets, read from the raw payload.
///
/// `None` for task types that do not write records under a caller-named
/// authority. `Some(Err(_))` when a record mutation's payload names no
/// authority, which is refused rather than left for the dispatcher to reject,
/// so the authority check cannot be skipped by a malformed payload.
fn target_authority(doc: &TrustTask<Value>) -> Option<Result<&str, RejectReason>> {
    let authority = match doc.type_uri.slug() {
        "registry/record/put" => doc.payload.pointer("/record/authority_id"),
        "registry/record/delete" => doc.payload.get("authority_id"),
        _ => return None,
    };
    Some(
        authority
            .and_then(Value::as_str)
            .ok_or_else(|| RejectReason::MalformedRequest {
                reason: "a record mutation must name its authority_id".to_string(),
            }),
    )
}

/// The registry's Trust Task application logic, independent of transport.
///
/// Cheap to clone: every field is shared. Notably `dispatcher` is the live
/// handle owned by the [`CapabilitySet`](crate::capabilities::CapabilitySet), so
/// enabling or disabling a capability takes effect through an existing handler
/// without a rebuild.
#[derive(Clone)]
pub struct TaskHandler {
    dispatcher: DispatcherHandle,
    /// Our own DID — the `recipient` every inbound document must address.
    my_did: String,
    /// DIDs permitted to perform record mutations.
    admin_dids: Vec<String>,
    /// Authorities, beyond its own DID, each admin may write records under.
    admin_authorities: Arc<HashMap<String, Vec<String>>>,
    verifier: Arc<dyn DynProofVerifier>,
    /// Write-path message-id dedup (R1.4). `None` on read-only surfaces, where
    /// there is no mutation to replay and caching read answers by message id
    /// would change their semantics.
    dedup: Option<Arc<dyn MessageIdStore>>,
}

impl TaskHandler {
    /// Build a handler over a dispatcher.
    ///
    /// Starts with no dedup store — see [`TaskHandler::with_dedup`], which any
    /// binding carrying writes must add.
    pub fn new(
        dispatcher: DispatcherHandle,
        my_did: impl Into<String>,
        admin_dids: Vec<String>,
        verifier: Arc<dyn DynProofVerifier>,
    ) -> Self {
        Self {
            dispatcher,
            my_did: my_did.into(),
            admin_dids,
            admin_authorities: Arc::new(HashMap::new()),
            verifier,
            dedup: None,
        }
    }

    /// Let admins write records under authorities other than their own DID.
    ///
    /// By default an admin may only put or delete records whose `authority_id`
    /// is its own DID. An operator hosting several authorities under one admin
    /// DID lists them here, keyed by that admin DID.
    pub fn with_admin_authorities(
        mut self,
        admin_authorities: HashMap<String, Vec<String>>,
    ) -> Self {
        self.admin_authorities = Arc::new(admin_authorities);
        self
    }

    /// Attach the message-id dedup store.
    ///
    /// Required on any at-least-once transport (DIDComm and TSP both are):
    /// without it a redelivered mutation is applied a second time instead of
    /// replaying the original response.
    pub fn with_dedup(mut self, dedup: Arc<dyn MessageIdStore>) -> Self {
        self.dedup = Some(dedup);
        self
    }

    /// Our own DID, as bindings need it to resolve parties.
    pub fn my_did(&self) -> &str {
        &self.my_did
    }

    /// SPEC §4.8.1 party resolution against the transport-authenticated
    /// sender: an in-band `issuer` that names anyone else is refused.
    ///
    /// Only the issuer needs resolving here; the recipient is checked against
    /// our own DID by [`TrustTask::validate_basic`].
    pub fn resolve_issuer(
        doc: &TrustTask<Value>,
        sender_did: Option<&str>,
    ) -> Result<(), ConsistencyError> {
        match (doc.issuer.as_deref(), sender_did) {
            (Some(in_band), Some(transport)) if in_band != transport => {
                Err(ConsistencyError::IssuerMismatch {
                    in_band: in_band.to_string(),
                    transport: transport.to_string(),
                })
            }
            _ => Ok(()),
        }
    }

    /// Apply the write-only preconditions the dispatcher does not enforce.
    /// Reads pass straight through.
    ///
    /// A write must carry a proof, name its `issuer` in-band, and come from a
    /// sender the transport authenticated as that same issuer. The proof's
    /// verification method must belong to the issuer (exact DID match) and
    /// carry the `assertionMethod` purpose, and the issuer must be on the admin
    /// list. The signature itself is checked afterwards by
    /// [`verify_write_proof`].
    ///
    /// `sender_did` is `None` for an unauthenticated caller. Such a caller can
    /// never satisfy these checks, so every write is denied — which is why a
    /// read-only surface stays read-only even if it is later pointed at a
    /// dispatcher that does register writes.
    pub fn authorize_write(
        &self,
        doc: &TrustTask<Value>,
        sender_did: Option<&str>,
    ) -> Result<(), RejectReason> {
        if !is_write_slug(doc.type_uri.slug()) {
            return Ok(());
        }
        let Some(proof) = doc.proof.as_ref() else {
            return Err(RejectReason::ProofRequired);
        };
        let Some(sender_did) = sender_did else {
            return Err(RejectReason::PermissionDenied {
                reason: "an unauthenticated caller cannot modify the registry".to_string(),
            });
        };
        let Some(issuer) = doc.issuer.as_deref() else {
            return Err(RejectReason::MalformedRequest {
                reason: "a write must name its issuer".to_string(),
            });
        };
        if issuer != sender_did {
            return Err(RejectReason::IdentityMismatch(
                ConsistencyError::IssuerMismatch {
                    in_band: issuer.to_string(),
                    transport: sender_did.to_string(),
                },
            ));
        }
        let vm = proof.verification_method.as_str();
        let vm_did = vm.split_once('#').map_or(vm, |(did, _)| did);
        if vm_did != issuer {
            return Err(RejectReason::ProofInvalid {
                reason: format!(
                    "the proof's verification method belongs to {vm_did}, not the issuer {issuer}"
                ),
            });
        }
        if proof.proof_purpose != WRITE_PROOF_PURPOSE {
            return Err(RejectReason::ProofInvalid {
                reason: format!(
                    "a write's proof must have proofPurpose {WRITE_PROOF_PURPOSE}, not {}",
                    proof.proof_purpose
                ),
            });
        }
        if !self.admin_dids.iter().any(|d| d == issuer) {
            return Err(RejectReason::PermissionDenied {
                reason: format!("DID {issuer} is not authorised to modify the registry"),
            });
        }
        Ok(())
    }

    /// Refuse a record mutation under an authority the issuer may not act for.
    ///
    /// An issuer may always write under its own DID, and additionally under
    /// any authority [`with_admin_authorities`](Self::with_admin_authorities)
    /// lists for it. Task types that do not name an authority pass through.
    ///
    /// Call only after [`authorize_write`](Self::authorize_write) and
    /// [`verify_write_proof`] have established who the issuer is.
    pub fn authorize_authority(&self, doc: &TrustTask<Value>) -> Result<(), RejectReason> {
        let Some(authority) = target_authority(doc) else {
            return Ok(());
        };
        let authority = authority?;
        let Some(issuer) = doc.issuer.as_deref() else {
            return Err(RejectReason::MalformedRequest {
                reason: "a write must name its issuer".to_string(),
            });
        };
        let delegated = self
            .admin_authorities
            .get(issuer)
            .is_some_and(|authorities| authorities.iter().any(|a| a == authority));
        if authority == issuer || delegated {
            Ok(())
        } else {
            Err(RejectReason::PermissionDenied {
                reason: format!("DID {issuer} may not write records under authority {authority}"),
            })
        }
    }

    /// Run one already-decoded, already-authenticated document through the
    /// registry.
    ///
    /// `sender_did` is the identity the transport authenticated — the DIDComm
    /// authcrypt sender, the TSP peer VID — or `None` where the transport has no
    /// caller identity. Party resolution against it (§4.8.1) happens here, so
    /// every caller gets the same check.
    ///
    /// Returns the response document to send back, or the error document to
    /// send back. Both are conformant Trust Task documents; neither is a
    /// transport-level failure.
    pub async fn handle(
        &self,
        doc: TrustTask<Value>,
        sender_did: Option<&str>,
    ) -> Result<TrustTask<Value>, ErrorResponse> {
        // §4.8.1: the in-band issuer must be the authenticated sender. The
        // error addresses the authenticated sender, never the contested issuer.
        if let Err(consistency) = Self::resolve_issuer(&doc, sender_did) {
            return Err(doc.reject_with_recipient(
                new_id(),
                RejectReason::from(consistency),
                sender_did.map(str::to_string),
            ));
        }

        // Framework freshness + recipient checks (§7.2 items 4/5).
        if let Err(reason) = doc.validate_basic(Utc::now(), &self.my_did) {
            return Err(doc.reject_with(new_id(), reason));
        }

        // Write-only ACL, proof presence and issuer binding.
        if let Err(reason) = self.authorize_write(&doc, sender_did) {
            return Err(doc.reject_with(new_id(), reason));
        }

        // Cryptographically verify the write's Data Integrity proof.
        if let Err(reason) = verify_write_proof(&self.verifier, &doc).await {
            return Err(doc.reject_with(new_id(), reason));
        }

        // Record mutations only under an authority the issuer may act for.
        if let Err(reason) = self.authorize_authority(&doc) {
            return Err(doc.reject_with(new_id(), reason));
        }

        // `registry/did/rotate` rotates *our own* DID's keys through the VTA, so
        // it is handled here rather than by the repository dispatcher (which has
        // no registration for it).
        if doc.type_uri.slug() == "registry/did/rotate" {
            return self.handle_did_rotate(&doc).await;
        }

        let dispatcher = self.dispatcher.read().await.clone();
        match &self.dedup {
            Some(dedup) => dispatch_idempotent(&dispatcher, dedup.as_ref(), doc).await,
            None => handle_document(&dispatcher, doc).await,
        }
    }

    /// Rotate the registry's own VTA-managed `did:webvh` keys. Requires the
    /// `vta` feature; otherwise the request is rejected as unavailable.
    async fn handle_did_rotate(
        &self,
        doc: &TrustTask<Value>,
    ) -> Result<TrustTask<Value>, ErrorResponse> {
        #[cfg(feature = "vta")]
        {
            use crate::trust_tasks::payloads::{DidRotateRequest, DidRotateResponse};

            let req: DidRotateRequest =
                serde_json::from_value(doc.payload.clone()).map_err(|e| {
                    doc.reject_with(
                        new_id(),
                        RejectReason::MalformedRequest {
                            reason: e.to_string(),
                        },
                    )
                })?;
            match crate::configs::vta::rotate_did(&self.my_did, req.pre_rotation_count, req.label)
                .await
            {
                Ok((did, new_scid, new_version_id)) => {
                    let response = DidRotateResponse {
                        did,
                        new_scid,
                        new_version_id,
                    };
                    let value = serde_json::to_value(response).unwrap_or(Value::Null);
                    Ok(doc.respond_with(new_id(), value))
                }
                Err(reason) => Err(doc.reject_with(
                    new_id(),
                    RejectReason::TaskFailed {
                        reason,
                        details: None,
                    },
                )),
            }
        }
        #[cfg(not(feature = "vta"))]
        {
            Err(doc.reject_with(
                new_id(),
                RejectReason::TaskFailed {
                    reason: "DID rotation is unavailable: the Trust Registry was built without the `vta` feature".to_string(),
                    details: None,
                },
            ))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::{Action, AuthorityId, EntityId, Resource};
    use crate::storage::adapters::local_storage::LocalStorage;
    use crate::storage::repository::{TrustRecordAdminRepository, TrustRecordQuery};
    use crate::trust_tasks::build_dispatcher;
    use affinidi_tdk::secrets_resolver::secrets::Secret;
    use serde_json::json;
    use tokio::sync::RwLock;
    use trust_tasks_proof::affinidi::{SignOptions, sign_trust_task};

    const ME: &str = "did:example:registry";
    const RECORD_PUT: &str = "https://trusttasks.org/spec/registry/record/put/0.1";
    const RECORD_DELETE: &str = "https://trusttasks.org/spec/registry/record/delete/0.1";
    const OTHER_AUTHORITY: &str = "did:example:another-community";

    /// An Ed25519 `did:key` whose secret id is its own verification method, so
    /// the offline `did:key` verifier can check what it signs.
    fn did_key(seed: u8) -> (Secret, String) {
        let throwaway = Secret::generate_ed25519(None, Some(&[seed; 32]));
        let public = throwaway.get_public_keymultibase().expect("multikey");
        let vm = format!("did:key:{public}#{public}");
        let mut secret = Secret::generate_ed25519(Some(&vm), Some(&[seed; 32]));
        secret.id = vm;
        (secret, format!("did:key:{public}"))
    }

    fn handler(admin_dids: Vec<String>) -> (TaskHandler, Arc<LocalStorage>) {
        let repo = Arc::new(LocalStorage::new());
        let dispatcher: DispatcherHandle =
            Arc::new(RwLock::new(Arc::new(build_dispatcher(repo.clone()))));
        let handler = TaskHandler::new(
            dispatcher,
            ME,
            admin_dids,
            trust_tasks_rs::erase_verifier(trust_tasks_proof::affinidi::Verifier::for_did_key()),
        );
        (handler, repo)
    }

    fn unsigned(type_uri: &str, issuer: Option<&str>, payload: Value) -> Value {
        let mut doc = json!({
            "id": format!("urn:uuid:{}", Uuid::new_v4()),
            "type": type_uri,
            "recipient": ME,
            "issuedAt": Utc::now(),
            "payload": payload,
        });
        if let Some(issuer) = issuer {
            doc["issuer"] = json!(issuer);
        }
        doc
    }

    fn put_payload(authority: &str) -> Value {
        json!({
            "record": {
                "entity_id": "did:example:member",
                "authority_id": authority,
                "action": "git.commit.sign",
                "resource": "repo",
                "recognized": true,
                "authorized": true,
                "record_type": "authorization",
            }
        })
    }

    fn delete_payload(authority: &str) -> Value {
        json!({
            "entity_id": "did:example:member",
            "authority_id": authority,
            "action": "git.commit.sign",
            "resource": "repo",
        })
    }

    async fn signed(doc: Value, secret: &Secret) -> TrustTask<Value> {
        let signed = sign_trust_task(&doc, secret, SignOptions::new())
            .await
            .expect("sign");
        serde_json::from_value(signed).expect("signed document parses")
    }

    fn code(err: &ErrorResponse) -> String {
        serde_json::to_value(err).expect("serialises")["payload"]["code"]
            .as_str()
            .expect("error code")
            .to_string()
    }

    async fn stored(repo: &LocalStorage, authority: &str) -> bool {
        repo.read(TrustRecordQuery::new(
            EntityId::new("did:example:member"),
            AuthorityId::new(authority),
            Action::new("git.commit.sign"),
            Resource::new("repo"),
        ))
        .await
        .is_ok()
    }

    fn read_doc() -> TrustTask<Value> {
        TrustTask::new(
            "req-1",
            crate::trust_tasks::type_uris::RECOGNITION
                .parse()
                .expect("valid type uri"),
            json!({
                "entity_id": "did:example:entity",
                "authority_id": "did:example:authority",
                "action": "issue",
                "resource": "vc",
            }),
        )
    }

    /// A community writing under its own DID, signed by its own key, over a
    /// transport that authenticated it: what a VTC sends.
    #[tokio::test]
    async fn signed_put_under_the_issuers_own_authority_is_stored() {
        let (key, did) = did_key(1);
        let (h, repo) = handler(vec![did.clone()]);
        let doc = signed(unsigned(RECORD_PUT, Some(&did), put_payload(&did)), &key).await;

        let response = h.handle(doc, Some(&did)).await.expect("write accepted");

        assert!(response.type_uri.is_response());
        assert!(stored(&repo, &did).await);
    }

    /// P-256 keys sign with `ecdsa-jcs-2019`; the binding checks are the same.
    #[tokio::test]
    async fn a_p256_signed_put_is_stored() {
        let throwaway = Secret::generate_p256(None, None).expect("p256");
        let public = throwaway.get_public_keymultibase().expect("multikey");
        let did = format!("did:key:{public}");
        let mut key = throwaway;
        key.id = format!("{did}#{public}");
        let (h, repo) = handler(vec![did.clone()]);
        let signed_value = sign_trust_task(
            &unsigned(RECORD_PUT, Some(&did), put_payload(&did)),
            &key,
            SignOptions::new()
                .with_cryptosuite(trust_tasks_proof::affinidi::CryptoSuite::EcdsaJcs2019),
        )
        .await
        .expect("sign");
        let doc: TrustTask<Value> = serde_json::from_value(signed_value).expect("parses");

        h.handle(doc, Some(&did)).await.expect("write accepted");

        assert!(stored(&repo, &did).await);
    }

    #[tokio::test]
    async fn signed_delete_under_the_issuers_own_authority_is_applied() {
        let (key, did) = did_key(2);
        let (h, repo) = handler(vec![did.clone()]);
        let put = signed(unsigned(RECORD_PUT, Some(&did), put_payload(&did)), &key).await;
        h.handle(put, Some(&did)).await.expect("put accepted");

        let delete = signed(
            unsigned(RECORD_DELETE, Some(&did), delete_payload(&did)),
            &key,
        )
        .await;
        h.handle(delete, Some(&did)).await.expect("delete accepted");

        assert!(!stored(&repo, &did).await);
    }

    #[tokio::test]
    async fn put_under_another_authority_is_refused() {
        let (key, did) = did_key(3);
        let (h, repo) = handler(vec![did.clone()]);
        let doc = signed(
            unsigned(RECORD_PUT, Some(&did), put_payload(OTHER_AUTHORITY)),
            &key,
        )
        .await;

        let err = h.handle(doc, Some(&did)).await.expect_err("refused");

        assert_eq!(code(&err), "permissionDenied");
        assert!(!stored(&repo, OTHER_AUTHORITY).await);
    }

    #[tokio::test]
    async fn delete_under_another_authority_is_refused() {
        let (key, did) = did_key(4);
        let (other_key, other_did) = did_key(5);
        let (h, repo) = handler(vec![did.clone(), other_did.clone()]);
        let put = signed(
            unsigned(RECORD_PUT, Some(&other_did), put_payload(&other_did)),
            &other_key,
        )
        .await;
        h.handle(put, Some(&other_did))
            .await
            .expect("owner's put accepted");

        let delete = signed(
            unsigned(RECORD_DELETE, Some(&did), delete_payload(&other_did)),
            &key,
        )
        .await;
        let err = h.handle(delete, Some(&did)).await.expect_err("refused");

        assert_eq!(code(&err), "permissionDenied");
        assert!(stored(&repo, &other_did).await, "the record survives");
    }

    #[tokio::test]
    async fn a_configured_extra_authority_is_accepted() {
        let (key, did) = did_key(6);
        let (h, repo) = handler(vec![did.clone()]);
        let h = h.with_admin_authorities(HashMap::from([(
            did.clone(),
            vec![OTHER_AUTHORITY.to_string()],
        )]));
        let doc = signed(
            unsigned(RECORD_PUT, Some(&did), put_payload(OTHER_AUTHORITY)),
            &key,
        )
        .await;

        h.handle(doc, Some(&did)).await.expect("write accepted");

        assert!(stored(&repo, OTHER_AUTHORITY).await);
    }

    #[tokio::test]
    async fn a_put_naming_no_authority_is_refused() {
        let (key, did) = did_key(7);
        let (h, _repo) = handler(vec![did.clone()]);
        let mut payload = put_payload(&did);
        payload["record"]
            .as_object_mut()
            .expect("record object")
            .remove("authority_id");
        let doc = signed(unsigned(RECORD_PUT, Some(&did), payload), &key).await;

        let err = h.handle(doc, Some(&did)).await.expect_err("refused");

        assert_eq!(code(&err), "malformedRequest");
    }

    #[tokio::test]
    async fn a_write_without_an_issuer_is_refused() {
        let (key, did) = did_key(8);
        let (h, repo) = handler(vec![did.clone()]);
        let mut doc = signed(unsigned(RECORD_PUT, Some(&did), put_payload(&did)), &key).await;
        doc.issuer = None;

        let err = h.handle(doc, Some(&did)).await.expect_err("refused");

        assert_eq!(code(&err), "malformedRequest");
        assert!(!stored(&repo, &did).await);
    }

    /// The authenticated sender and the in-band issuer must be the same DID,
    /// whichever of them is an admin.
    #[tokio::test]
    async fn an_issuer_that_is_not_the_sender_is_refused() {
        let (key, did) = did_key(9);
        let (_, sender) = did_key(10);
        let (h, repo) = handler(vec![did.clone(), sender.clone()]);
        let doc = signed(unsigned(RECORD_PUT, Some(&did), put_payload(&did)), &key).await;

        let err = h.handle(doc, Some(&sender)).await.expect_err("refused");

        assert_eq!(code(&err), "identityMismatch");
        assert_eq!(err.recipient.as_deref(), Some(sender.as_str()));
        assert!(!stored(&repo, &did).await);
    }

    #[tokio::test]
    async fn a_proof_by_another_did_is_refused() {
        let (_, did) = did_key(11);
        let (other_key, other_did) = did_key(12);
        let (h, repo) = handler(vec![did.clone(), other_did.clone()]);
        let mut doc = signed(
            unsigned(RECORD_PUT, Some(&other_did), put_payload(&did)),
            &other_key,
        )
        .await;
        doc.issuer = Some(did.clone());

        assert!(matches!(
            h.authorize_write(&doc, Some(&did)),
            Err(RejectReason::ProofInvalid { .. })
        ));
        let err = h.handle(doc, Some(&did)).await.expect_err("refused");
        assert_eq!(code(&err), "proofInvalid");
        assert!(!stored(&repo, &did).await);
    }

    #[tokio::test]
    async fn a_proof_for_another_purpose_is_refused() {
        let (key, did) = did_key(13);
        let (h, _repo) = handler(vec![did.clone()]);
        let signed_value = sign_trust_task(
            &unsigned(RECORD_PUT, Some(&did), put_payload(&did)),
            &key,
            SignOptions::new().with_proof_purpose("authentication"),
        )
        .await
        .expect("sign");
        let doc: TrustTask<Value> = serde_json::from_value(signed_value).expect("parses");

        assert!(matches!(
            h.authorize_write(&doc, Some(&did)),
            Err(RejectReason::ProofInvalid { .. })
        ));
    }

    #[tokio::test]
    async fn a_tampered_write_is_refused() {
        let (key, did) = did_key(14);
        let (h, repo) = handler(vec![did.clone()]);
        let mut doc = signed(unsigned(RECORD_PUT, Some(&did), put_payload(&did)), &key).await;
        doc.payload["record"]["entity_id"] = json!("did:example:someone-else");

        let err = h.handle(doc, Some(&did)).await.expect_err("refused");

        assert_eq!(code(&err), "proofInvalid");
        assert!(!stored(&repo, &did).await);
    }

    #[tokio::test]
    async fn a_write_from_a_non_admin_is_denied() {
        let (key, did) = did_key(15);
        let (h, _repo) = handler(vec!["did:example:admin".to_string()]);
        let doc = signed(unsigned(RECORD_PUT, Some(&did), put_payload(&did)), &key).await;

        let err = h.handle(doc, Some(&did)).await.expect_err("refused");

        assert_eq!(code(&err), "permissionDenied");
    }

    /// A transport with no caller identity must never satisfy the admin ACL,
    /// whatever dispatcher it happens to be pointed at.
    #[tokio::test]
    async fn an_anonymous_write_is_denied() {
        let (key, did) = did_key(16);
        let (h, _repo) = handler(vec![did.clone()]);
        let doc = signed(unsigned(RECORD_PUT, Some(&did), put_payload(&did)), &key).await;

        assert!(matches!(
            h.authorize_write(&doc, None),
            Err(RejectReason::PermissionDenied { .. })
        ));
    }

    #[tokio::test]
    async fn a_write_without_a_proof_is_rejected() {
        let (_, did) = did_key(17);
        let (h, _repo) = handler(vec![did.clone()]);
        let doc: TrustTask<Value> =
            serde_json::from_value(unsigned(RECORD_PUT, Some(&did), put_payload(&did)))
                .expect("parses");

        assert!(matches!(
            h.authorize_write(&doc, Some(&did)),
            Err(RejectReason::ProofRequired)
        ));
    }

    #[test]
    fn reads_bypass_write_authorization() {
        let (h, _repo) = handler(vec![]);
        assert!(
            h.authorize_write(&read_doc(), Some("did:example:anyone"))
                .is_ok()
        );
        // Including anonymous ones — the HTTP query surface has no caller identity.
        assert!(h.authorize_write(&read_doc(), None).is_ok());
    }

    /// Party resolution runs inside the handler, so a host calling `handle`
    /// directly cannot skip it — reads included.
    #[tokio::test]
    async fn a_read_whose_issuer_is_not_the_sender_is_refused() {
        let (h, _repo) = handler(vec![]);
        let mut doc = read_doc();
        doc.issuer = Some("did:example:claimed".to_string());

        let err = h
            .handle(doc, Some("did:example:actual"))
            .await
            .expect_err("refused");

        assert_eq!(code(&err), "identityMismatch");
    }

    /// Without a dedup store the handler still routes — it just loses replay
    /// protection. Guards the `None` arm of the dispatch branch.
    #[tokio::test]
    async fn handler_without_dedup_still_dispatches_reads() {
        let (h, _repo) = handler(vec![]);
        let mut doc = read_doc();
        doc.recipient = Some(ME.to_string());
        // A recognition query against an empty store is a well-formed "not
        // recognised" answer, not an error — enough to prove the document went
        // all the way through to a handler.
        let response = h
            .handle(doc, None)
            .await
            .expect("recognition query should reach the dispatcher");
        assert!(response.type_uri.is_response());
    }
}
