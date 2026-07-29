//! Transport-agnostic Trust Task handler.
//!
//! Every transport binding — DIDComm, TSP, HTTP, or a host application driving
//! an embedded registry — decodes its own wire format into a
//! `TrustTask<Value>`, learns who sent it, and then applies the *same* sequence
//! of checks before routing:
//!
//! 1. framework freshness + recipient checks ([`TrustTask::validate_basic`]);
//! 2. the write-only preconditions the dispatcher does not enforce — proof
//!    presence and the admin-DID ACL ([`TaskHandler::authorize_write`]);
//! 3. cryptographic Data-Integrity verification of a write's proof
//!    ([`crate::trust_tasks::verify_write_proof`]);
//! 4. `registry/did/rotate`, which acts on *our own* DID via the VTA rather
//!    than on the record repository, so it never reaches the dispatcher;
//! 5. dispatch, deduplicated by message id when a store is configured.
//!
//! That sequence used to be written out once per binding, with `authorize_write`
//! copy-pasted between the DIDComm and TSP handlers. Keeping one copy is what
//! makes it safe to add a transport — including a host that owns its own
//! socket and calls [`TaskHandler::handle`] directly.
//!
//! What stays in the bindings is only what is genuinely transport-specific:
//! resolving the parties (§4.8.1) from transport-level authentication, and
//! packing the returned document back onto the wire.

use std::sync::Arc;

use chrono::Utc;
use serde_json::Value;
use trust_tasks_rs::{DynProofVerifier, ErrorResponse, RejectReason, TrustTask};
use uuid::Uuid;

use crate::capabilities::DispatcherHandle;
use crate::dedup::{MessageIdStore, dispatch_idempotent};
use crate::trust_tasks::handle_document;
use crate::trust_tasks::proof::{is_write_slug, verify_write_proof};

fn new_id() -> String {
    Uuid::new_v4().to_string()
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
            verifier,
            dedup: None,
        }
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

    /// Apply the write-only preconditions the dispatcher does not enforce:
    /// proof presence and the admin-DID ACL. Reads pass straight through.
    ///
    /// `sender_did` is `None` for an unauthenticated caller. Such a caller can
    /// never satisfy the ACL, so every write is denied — which is why a
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
        if doc.proof.is_none() {
            return Err(RejectReason::ProofRequired);
        }
        let Some(sender_did) = sender_did else {
            return Err(RejectReason::PermissionDenied {
                reason: "an unauthenticated caller cannot modify the registry".to_string(),
            });
        };
        if !self.admin_dids.iter().any(|d| d == sender_did) {
            return Err(RejectReason::PermissionDenied {
                reason: format!("DID {sender_did} is not authorised to modify the registry"),
            });
        }
        Ok(())
    }

    /// Run one already-decoded, already-authenticated document through the
    /// registry.
    ///
    /// `sender_did` is the identity the transport authenticated — the DIDComm
    /// authcrypt sender, the TSP peer VID — or `None` where the transport has no
    /// caller identity. The caller is responsible for having resolved the
    /// framework's parties (§4.8.1) first, since only it knows how its transport
    /// establishes them.
    ///
    /// Returns the response document to send back, or the error document to
    /// send back. Both are conformant Trust Task documents; neither is a
    /// transport-level failure.
    pub async fn handle(
        &self,
        doc: TrustTask<Value>,
        sender_did: Option<&str>,
    ) -> Result<TrustTask<Value>, ErrorResponse> {
        // Framework freshness + recipient checks (§7.2 items 4/5).
        if let Err(reason) = doc.validate_basic(Utc::now(), &self.my_did) {
            return Err(doc.reject_with(new_id(), reason));
        }

        // Write-only ACL + proof presence.
        if let Err(reason) = self.authorize_write(&doc, sender_did) {
            return Err(doc.reject_with(new_id(), reason));
        }

        // Cryptographically verify the write's Data Integrity proof.
        if let Err(reason) = verify_write_proof(&self.verifier, &doc).await {
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
    use crate::storage::adapters::local_storage::LocalStorage;
    use crate::trust_tasks::build_dispatcher;
    use tokio::sync::RwLock;

    const ADMIN: &str = "did:example:admin";
    const ME: &str = "did:example:registry";

    fn handler(admin_dids: Vec<String>) -> TaskHandler {
        let repo = Arc::new(LocalStorage::new());
        let dispatcher: DispatcherHandle = Arc::new(RwLock::new(Arc::new(build_dispatcher(repo))));
        TaskHandler::new(
            dispatcher,
            ME,
            admin_dids,
            trust_tasks_rs::erase_verifier(trust_tasks_proof::affinidi::Verifier::for_did_key()),
        )
    }

    fn doc_with(type_uri: &str, proof: bool) -> TrustTask<Value> {
        let mut doc = TrustTask::new(
            "req-1",
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

    fn read_doc() -> TrustTask<Value> {
        doc_with(
            "https://trusttasks.org/spec/registry/recognition/0.1",
            false,
        )
    }

    /// A recognition query with a payload the dispatcher will actually accept.
    fn valid_read_doc() -> TrustTask<Value> {
        let mut doc = TrustTask::new(
            "req-1",
            crate::trust_tasks::type_uris::RECOGNITION
                .parse()
                .expect("valid type uri"),
            serde_json::json!({
                "entity_id": "did:example:entity",
                "authority_id": "did:example:authority",
                "action": "issue",
                "resource": "vc",
            }),
        );
        doc.recipient = Some(ME.to_string());
        doc
    }

    fn write_doc(proof: bool) -> TrustTask<Value> {
        doc_with("https://trusttasks.org/spec/registry/record/put/0.1", proof)
    }

    #[test]
    fn reads_bypass_write_authorization() {
        let h = handler(vec![]);
        assert!(
            h.authorize_write(&read_doc(), Some("did:example:anyone"))
                .is_ok()
        );
        // Including anonymous ones — the HTTP query surface has no caller identity.
        assert!(h.authorize_write(&read_doc(), None).is_ok());
    }

    #[test]
    fn write_without_proof_is_rejected() {
        let h = handler(vec![ADMIN.to_string()]);
        assert!(matches!(
            h.authorize_write(&write_doc(false), Some(ADMIN)),
            Err(RejectReason::ProofRequired)
        ));
    }

    #[test]
    fn write_from_non_admin_is_denied() {
        let h = handler(vec![ADMIN.to_string()]);
        assert!(matches!(
            h.authorize_write(&write_doc(true), Some("did:example:intruder")),
            Err(RejectReason::PermissionDenied { .. })
        ));
    }

    /// A transport with no caller identity must never satisfy the admin ACL,
    /// whatever dispatcher it happens to be pointed at.
    #[test]
    fn anonymous_write_is_denied() {
        let h = handler(vec![ADMIN.to_string()]);
        assert!(matches!(
            h.authorize_write(&write_doc(true), None),
            Err(RejectReason::PermissionDenied { .. })
        ));
    }

    #[test]
    fn write_from_admin_with_proof_is_allowed() {
        let h = handler(vec![ADMIN.to_string()]);
        assert!(h.authorize_write(&write_doc(true), Some(ADMIN)).is_ok());
    }

    /// Without a dedup store the handler still routes — it just loses replay
    /// protection. Guards the `None` arm of the dispatch branch.
    #[tokio::test]
    async fn handler_without_dedup_still_dispatches_reads() {
        let h = handler(vec![]);
        // A recognition query against an empty store is a well-formed "not
        // recognised" answer, not an error — enough to prove the document went
        // all the way through to a handler.
        let outcome = h.handle(valid_read_doc(), None).await;
        let response = outcome.expect("recognition query should reach the dispatcher");
        assert!(response.type_uri.is_response());
    }
}
