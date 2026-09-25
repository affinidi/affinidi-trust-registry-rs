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
//!
//! and, for writes only:
//!
//! 3. the operation-document checks (VTI-KEY-107): the document names this
//!    registry as its recipient and carries a time of issue inside the
//!    acceptance window ([`TaskHandler::check_write_document`]);
//! 4. proof presence, an in-band `issuer` that is the authenticated sender and
//!    the controller of the proof's verification method, the `authentication`
//!    proof purpose, and the admin-DID ACL ([`TaskHandler::authorize_write`]);
//! 5. cryptographic Data-Integrity verification of the proof against a key the
//!    issuer lists under `authentication` ([`verify_write_proof`]);
//! 6. the authority binding: a write acts only under an authority the issuer
//!    may act for ([`TaskHandler::authorize_authority`]);
//! 7. the replay record, shared by every binding: a document identifier is
//!    executed at most once ([`execute_once`]);
//! 8. dispatch — or, for `registry/did/rotate`, which acts on *our own* DID
//!    via the VTA, the rotation itself;
//! 9. an audit entry for the outcome, refusals included.
//!
//! What stays in the bindings is only what is genuinely transport-specific:
//! establishing which sender the transport authenticated, and packing the
//! returned document back onto the wire. Party resolution happens here, so a
//! host calling [`TaskHandler::handle`] directly gets it too.
//!
//! The transport-authenticated sender alone never authorises a write.

use std::collections::HashMap;
use std::sync::Arc;

use chrono::Utc;
use serde_json::Value;
use trust_tasks_rs::{
    ConsistencyError, DynProofVerifier, ErrorResponse, FreshnessPolicy, RejectReason, TrustTask,
};
use uuid::Uuid;

use crate::audit::model::{AuditLogBuilder, AuditLogger, AuditOperation, AuditResource};
use crate::capabilities::{CapabilitySet, DispatcherHandle};
use crate::dedup::{MessageIdStore, execute_once};
use crate::domain::{Action, AuthorityId, EntityId, Resource};
use crate::trust_tasks::handle_document;
use crate::trust_tasks::proof::{WRITE_PROOF_PURPOSE, is_write_slug, verify_write_proof};

/// How old a write's time of issue may be (VTI-OPS-024). The replay record's
/// retention ([`crate::dedup::DEFAULT_TTL`]) is longer, so every document
/// inside the window is remembered for as long as it could be accepted.
pub const WRITE_ACCEPTANCE_WINDOW: chrono::TimeDelta = trust_tasks_rs::DEFAULT_MAX_AGE;

/// The capability the `git-trust/*` tasks belong to.
const GIT_TRUST: &str = "git-trust";

fn new_id() -> String {
    Uuid::new_v4().to_string()
}

fn write_freshness() -> FreshnessPolicy {
    FreshnessPolicy::consequential().with_max_age(WRITE_ACCEPTANCE_WINDOW)
}

fn required_authority(value: Option<&Value>, what: &str) -> Result<Option<String>, RejectReason> {
    value
        .and_then(Value::as_str)
        .map(|authority| Some(authority.to_string()))
        .ok_or_else(|| RejectReason::MalformedRequest {
            reason: format!("{what} must name its authority_id"),
        })
}

fn audit_operation(slug: &str) -> AuditOperation {
    match slug {
        "registry/record/put" => AuditOperation::Put,
        "registry/record/delete" => AuditOperation::Delete,
        "git-trust/grant" => AuditOperation::Grant,
        "git-trust/revoke" => AuditOperation::Revoke,
        "governance/capability/enable" => AuditOperation::Enable,
        "governance/capability/disable" => AuditOperation::Disable,
        "registry/did/rotate" => AuditOperation::Rotate,
        _ => AuditOperation::Update,
    }
}

fn text(payload: &Value, pointer: &str) -> Option<String> {
    payload
        .pointer(pointer)
        .and_then(Value::as_str)
        .map(str::to_string)
}

/// The record key (or capability) a write acts on, for its audit entry.
/// Identifiers only: never record contents, context or proofs.
fn audit_resource(doc: &TrustTask<Value>, authority: Option<&str>) -> AuditResource {
    let payload = &doc.payload;
    let (entity, action, resource) = match doc.type_uri.slug() {
        "registry/record/put" => (
            text(payload, "/record/entity_id"),
            text(payload, "/record/action"),
            text(payload, "/record/resource"),
        ),
        "registry/record/delete" => (
            text(payload, "/entity_id"),
            text(payload, "/action"),
            text(payload, "/resource"),
        ),
        "git-trust/grant" | "git-trust/revoke" => (
            text(payload, "/subject"),
            Some(crate::capabilities::git_trust::ACTION.to_string()),
            text(payload, "/resource"),
        ),
        "governance/capability/enable" | "governance/capability/disable" => {
            (None, None, text(payload, "/capability"))
        }
        _ => (None, None, None),
    };
    AuditResource::new(
        entity.map(|e| EntityId::new(&e)),
        authority.map(AuthorityId::new),
        action.map(|a| Action::new(&a)),
        resource.map(|r| Resource::new(&r)),
    )
}

/// What a write established before it finished, for its audit entry.
#[derive(Default)]
struct WriteProgress {
    /// The issuer, once its proof has verified.
    proven_issuer: Option<String>,
    /// The authority the write acts under, once established.
    authority: Option<String>,
}

/// The registry's Trust Task application logic, independent of transport.
///
/// Cheap to clone: every field is shared. Notably `dispatcher` is the live
/// handle owned by the [`CapabilitySet`], so enabling or disabling a capability
/// takes effect through an existing handler without a rebuild.
#[derive(Clone)]
pub struct TaskHandler {
    dispatcher: DispatcherHandle,
    /// Our own DID — the `recipient` every inbound document must address.
    my_did: String,
    /// DIDs permitted to perform writes.
    admin_dids: Vec<String>,
    /// Authorities, beyond its own DID, each admin may act under.
    admin_authorities: Arc<HashMap<String, Vec<String>>>,
    verifier: Arc<dyn DynProofVerifier>,
    /// The record of accepted document identifiers (VTI-OPS-025..027), shared
    /// by every binding carrying writes. A handler without one refuses writes.
    dedup: Option<Arc<dyn MessageIdStore>>,
    /// Where capability tasks learn the authority they act under.
    capabilities: Option<Arc<CapabilitySet>>,
    /// Receives an entry for every write, refusals included.
    audit: Option<Arc<dyn AuditLogger>>,
}

impl TaskHandler {
    /// Build a handler over a dispatcher.
    ///
    /// Starts with no replay record, capability set or audit logger. A handler
    /// that carries writes needs [`with_dedup`](Self::with_dedup) (writes are
    /// refused without it), [`with_capabilities`](Self::with_capabilities)
    /// (capability writes are refused without it) and
    /// [`with_audit`](Self::with_audit).
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
            capabilities: None,
            audit: None,
        }
    }

    /// Let admins act under authorities other than their own DID.
    ///
    /// By default an admin may only write under its own DID. An operator
    /// hosting several authorities under one admin DID lists them here, keyed
    /// by that admin DID.
    pub fn with_admin_authorities(
        mut self,
        admin_authorities: HashMap<String, Vec<String>>,
    ) -> Self {
        self.admin_authorities = Arc::new(admin_authorities);
        self
    }

    /// Attach the record of accepted document identifiers.
    ///
    /// Every binding carrying writes must share one store, so a document
    /// accepted on one binding is not executed again on another.
    pub fn with_dedup(mut self, dedup: Arc<dyn MessageIdStore>) -> Self {
        self.dedup = Some(dedup);
        self
    }

    /// Attach the capability set, which says what authority a capability task
    /// acts under.
    pub fn with_capabilities(mut self, capabilities: Arc<CapabilitySet>) -> Self {
        self.capabilities = Some(capabilities);
        self
    }

    /// Attach the audit logger that records every write.
    pub fn with_audit(mut self, audit: Arc<dyn AuditLogger>) -> Self {
        self.audit = Some(audit);
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

    /// The operation-document checks a write's `authentication` proof relies
    /// on, since it carries no challenge or domain (VTI-KEY-107): the document
    /// names this registry as its recipient (VTI-OPS-023) and carries a time of
    /// issue inside the acceptance window (VTI-OPS-024). Its identifier is
    /// checked against the replay record at execution.
    pub fn check_write_document(&self, doc: &TrustTask<Value>) -> Result<(), RejectReason> {
        match doc.recipient.as_deref() {
            None => {
                return Err(RejectReason::MalformedRequest {
                    reason: "a write must name its recipient".to_string(),
                });
            }
            Some(recipient) if recipient != self.my_did => {
                return Err(RejectReason::WrongRecipient {
                    in_band: recipient.to_string(),
                    expected: self.my_did.clone(),
                });
            }
            Some(_) => {}
        }
        if doc.id.is_empty() {
            return Err(RejectReason::MalformedRequest {
                reason: "a write must carry a document identifier".to_string(),
            });
        }
        doc.validate_freshness(Utc::now(), &write_freshness())
    }

    /// Apply the write-only preconditions the dispatcher does not enforce.
    /// Reads pass straight through.
    ///
    /// A write must carry a proof, name its `issuer` in-band, and come from a
    /// sender the transport authenticated as that same issuer. The proof's
    /// verification method must belong to the issuer (exact DID match) and
    /// carry the `authentication` purpose (VTI-KEY-106), and the issuer must be
    /// on the admin list. The signature, and that the key is listed under
    /// `authentication`, are checked afterwards by [`verify_write_proof`].
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

    /// The authority a write acts under, or `None` for one that acts under no
    /// authority (`registry/did/rotate`, or enabling a capability whose config
    /// names none).
    ///
    /// Record mutations name it in the payload. A capability task acts under
    /// the authority its capability was enabled with, and enabling or
    /// disabling a capability acts under the authority its config names.
    pub async fn target_authority(
        &self,
        doc: &TrustTask<Value>,
    ) -> Result<Option<String>, RejectReason> {
        let payload = &doc.payload;
        match doc.type_uri.slug() {
            "registry/record/put" => {
                required_authority(payload.pointer("/record/authority_id"), "a record mutation")
            }
            "registry/record/delete" => {
                required_authority(payload.get("authority_id"), "a record mutation")
            }
            "governance/capability/enable" => {
                match payload.pointer(&format!(
                    "/config/{}",
                    crate::capabilities::CONFIG_AUTHORITY
                )) {
                    None => Ok(None),
                    Some(Value::String(authority)) => Ok(Some(authority.clone())),
                    Some(_) => Err(RejectReason::MalformedRequest {
                        reason: "a capability's authority must be a DID string".to_string(),
                    }),
                }
            }
            "governance/capability/disable" => {
                let capability = payload
                    .get("capability")
                    .and_then(Value::as_str)
                    .ok_or_else(|| RejectReason::MalformedRequest {
                        reason: "a capability change must name its capability".to_string(),
                    })?;
                Ok(self.capabilities()?.configured_authority(capability).await)
            }
            "git-trust/grant" | "git-trust/revoke" => {
                Ok(self.capabilities()?.configured_authority(GIT_TRUST).await)
            }
            _ => Ok(None),
        }
    }

    fn capabilities(&self) -> Result<&CapabilitySet, RejectReason> {
        self.capabilities
            .as_deref()
            .ok_or_else(|| RejectReason::PermissionDenied {
                reason: "this handler cannot establish the authority a capability task acts under"
                    .to_string(),
            })
    }

    /// Refuse a write under an authority the issuer may not act for.
    ///
    /// An issuer may always act under its own DID, and additionally under any
    /// authority [`with_admin_authorities`](Self::with_admin_authorities) lists
    /// for it. A capability's config cannot widen this: enabling a capability
    /// under an authority is itself a write under that authority.
    ///
    /// Call only after [`authorize_write`](Self::authorize_write) and
    /// [`verify_write_proof`] have established who the issuer is.
    pub fn authorize_authority(
        &self,
        doc: &TrustTask<Value>,
        authority: Option<&str>,
    ) -> Result<(), RejectReason> {
        let Some(authority) = authority else {
            return Ok(());
        };
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
                reason: format!("DID {issuer} may not act under authority {authority}"),
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
        if !is_write_slug(doc.type_uri.slug()) {
            return self.handle_read(doc, sender_did).await;
        }

        let audit_template = self.audit.as_ref().map(|_| {
            (
                doc.type_uri.slug().to_string(),
                doc.id.clone(),
                doc.thread_id.clone(),
                doc.issuer
                    .clone()
                    .or_else(|| sender_did.map(str::to_string)),
                doc.clone(),
            )
        });
        let mut progress = WriteProgress::default();
        let outcome = self.handle_write(doc, sender_did, &mut progress).await;

        if let (Some(audit), Some((slug, id, thread_id, claimed, original))) =
            (&self.audit, audit_template)
        {
            let builder = AuditLogBuilder::new()
                .operation(audit_operation(&slug))
                .actor(progress.proven_issuer.clone().unwrap_or_default())
                .claimed_actor(
                    progress
                        .proven_issuer
                        .is_none()
                        .then_some(claimed)
                        .flatten(),
                )
                .resource(audit_resource(&original, progress.authority.as_deref()))
                .task(slug)
                .document_id(id)
                .thread_id(thread_id);
            let entry = match &outcome {
                Ok(_) => builder.build_success(),
                Err(error) => {
                    let code = serde_json::to_value(&error.payload.code)
                        .ok()
                        .and_then(|code| code.as_str().map(str::to_string))
                        .unwrap_or_default();
                    let reason = match error.payload.message.as_deref() {
                        Some(message) => format!("{code}: {message}"),
                        None => code.clone(),
                    };
                    if progress.proven_issuer.is_none()
                        || matches!(code.as_str(), "permissionDenied" | "identityMismatch")
                    {
                        builder.build_unauthorized(reason)
                    } else {
                        builder.build_failure(reason)
                    }
                }
            };
            audit.log(entry).await;
        }
        outcome
    }

    async fn handle_read(
        &self,
        doc: TrustTask<Value>,
        sender_did: Option<&str>,
    ) -> Result<TrustTask<Value>, ErrorResponse> {
        if let Err(consistency) = Self::resolve_issuer(&doc, sender_did) {
            return Err(doc.reject_with_recipient(
                new_id(),
                RejectReason::from(consistency),
                sender_did.map(str::to_string),
            ));
        }
        if let Err(reason) = doc.validate_basic(Utc::now(), &self.my_did) {
            return Err(doc.reject_with(new_id(), reason));
        }
        let dispatcher = self.dispatcher.read().await.clone();
        handle_document(&dispatcher, doc).await
    }

    async fn handle_write(
        &self,
        doc: TrustTask<Value>,
        sender_did: Option<&str>,
        progress: &mut WriteProgress,
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
        if let Err(reason) = doc.validate_basic(Utc::now(), &self.my_did) {
            return Err(doc.reject_with(new_id(), reason));
        }
        if let Err(reason) = self.check_write_document(&doc) {
            return Err(doc.reject_with(new_id(), reason));
        }
        if let Err(reason) = self.authorize_write(&doc, sender_did) {
            return Err(doc.reject_with(new_id(), reason));
        }
        if let Err(reason) = verify_write_proof(&self.verifier, &doc).await {
            return Err(doc.reject_with(new_id(), reason));
        }
        progress.proven_issuer = doc.issuer.clone();

        let authority = match self.target_authority(&doc).await {
            Ok(authority) => authority,
            Err(reason) => return Err(doc.reject_with(new_id(), reason)),
        };
        progress.authority = authority.clone();
        if let Err(reason) = self.authorize_authority(&doc, authority.as_deref()) {
            return Err(doc.reject_with(new_id(), reason));
        }

        let Some(dedup) = &self.dedup else {
            return Err(doc.reject_with(new_id(), RejectReason::Unavailable { retry_after: None }));
        };

        // `registry/did/rotate` rotates *our own* DID's keys through the VTA, so
        // it is handled here rather than by the repository dispatcher (which has
        // no registration for it).
        if doc.type_uri.slug() == "registry/did/rotate" {
            return execute_once(dedup.as_ref(), doc, |doc| async move {
                self.handle_did_rotate(&doc).await
            })
            .await;
        }

        let dispatcher = self.dispatcher.read().await.clone();
        execute_once(dedup.as_ref(), doc, |doc| handle_document(&dispatcher, doc)).await
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
    use crate::audit::model::{AuditLog, AuditStatus};
    use crate::capabilities::{MemoryCapabilityStore, git_trust};
    use crate::dedup::MemoryMessageIdStore;
    use crate::domain::{Action, AuthorityId, EntityId, Resource};
    use crate::storage::adapters::local_storage::LocalStorage;
    use crate::storage::repository::{TrustRecordAdminRepository, TrustRecordQuery};
    use crate::trust_tasks::{build_dispatcher, build_query_dispatcher};
    use affinidi_tdk::secrets_resolver::secrets::Secret;
    use serde_json::json;
    use std::sync::Mutex;
    use trust_tasks_proof::affinidi::{SignOptions, sign_trust_task};

    const ME: &str = "did:example:registry";
    const RECORD_PUT: &str = "https://trusttasks.org/spec/registry/record/put/0.1";
    const RECORD_DELETE: &str = "https://trusttasks.org/spec/registry/record/delete/0.1";
    const GRANT: &str = "https://trusttasks.org/spec/git-trust/grant/0.1";
    const ENABLE: &str = "https://trusttasks.org/spec/governance/capability/enable/0.1";
    const DISABLE: &str = "https://trusttasks.org/spec/governance/capability/disable/0.1";
    const OTHER_AUTHORITY: &str = "did:example:another-community";

    #[derive(Default)]
    struct RecordingAudit {
        entries: Mutex<Vec<AuditLog>>,
    }

    #[async_trait::async_trait]
    impl AuditLogger for RecordingAudit {
        async fn log(&self, audit_log: AuditLog) {
            self.entries.lock().unwrap().push(audit_log);
        }
    }

    struct Fixture {
        handler: TaskHandler,
        repo: Arc<LocalStorage>,
        capabilities: Arc<CapabilitySet>,
        audit: Arc<RecordingAudit>,
    }

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

    fn fixture(admin_dids: Vec<String>) -> Fixture {
        let repo = Arc::new(LocalStorage::new());
        let base_repo = repo.clone();
        let query_repo = repo.clone();
        let capabilities = CapabilitySet::new(
            vec![git_trust::definition(repo.clone()).expect("git-trust definition")],
            Box::new(MemoryCapabilityStore::default()),
            Box::new(move || build_dispatcher(base_repo.clone())),
            Box::new(move || build_query_dispatcher(query_repo.clone())),
        )
        .expect("capability set");
        let audit = Arc::new(RecordingAudit::default());
        let handler = TaskHandler::new(
            capabilities.dispatcher(),
            ME,
            admin_dids,
            trust_tasks_rs::erase_verifier(trust_tasks_proof::affinidi::Verifier::for_did_key()),
        )
        .with_dedup(Arc::new(MemoryMessageIdStore::default()))
        .with_capabilities(capabilities.clone())
        .with_audit(audit.clone());
        Fixture {
            handler,
            repo,
            capabilities,
            audit,
        }
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

    async fn sign_with(doc: Value, secret: &Secret, options: SignOptions) -> TrustTask<Value> {
        let signed = sign_trust_task(&doc, secret, options).await.expect("sign");
        serde_json::from_value(signed).expect("signed document parses")
    }

    /// Signed as an operational message: `authentication` purpose.
    async fn signed(doc: Value, secret: &Secret) -> TrustTask<Value> {
        sign_with(
            doc,
            secret,
            SignOptions::new().with_proof_purpose(WRITE_PROOF_PURPOSE),
        )
        .await
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

    fn last_audit(f: &Fixture) -> AuditLog {
        f.audit
            .entries
            .lock()
            .unwrap()
            .last()
            .cloned()
            .expect("an audit entry")
    }

    // --- The normal write path -------------------------------------------

    /// A community writing under its own DID, signed by its own operational
    /// key, over a transport that authenticated it: what a VTC sends.
    #[tokio::test]
    async fn signed_put_under_the_issuers_own_authority_is_stored() {
        let (key, did) = did_key(1);
        let f = fixture(vec![did.clone()]);
        let doc = signed(unsigned(RECORD_PUT, Some(&did), put_payload(&did)), &key).await;
        let id = doc.id.clone();

        let response = f
            .handler
            .handle(doc, Some(&did))
            .await
            .expect("write accepted");

        assert!(response.type_uri.is_response());
        assert!(stored(&f.repo, &did).await);
        let entry = last_audit(&f);
        assert!(matches!(entry.status, AuditStatus::Success));
        assert_eq!(entry.actor, did);
        assert_eq!(entry.task.as_deref(), Some("registry/record/put"));
        assert_eq!(entry.document_id.as_deref(), Some(id.as_str()));
        assert_eq!(
            entry.resource.authority_id.as_ref().map(|a| a.as_str()),
            Some(did.as_str())
        );
        assert_eq!(
            entry.resource.entity_id.as_ref().map(|e| e.as_str()),
            Some("did:example:member")
        );
    }

    /// P-256 keys sign with `ecdsa-jcs-2019`; the binding checks are the same.
    #[tokio::test]
    async fn a_p256_signed_put_is_stored() {
        let throwaway = Secret::generate_p256(None, None).expect("p256");
        let public = throwaway.get_public_keymultibase().expect("multikey");
        let did = format!("did:key:{public}");
        let mut key = throwaway;
        key.id = format!("{did}#{public}");
        let f = fixture(vec![did.clone()]);
        let doc = sign_with(
            unsigned(RECORD_PUT, Some(&did), put_payload(&did)),
            &key,
            SignOptions::new()
                .with_proof_purpose(WRITE_PROOF_PURPOSE)
                .with_cryptosuite(trust_tasks_proof::affinidi::CryptoSuite::EcdsaJcs2019),
        )
        .await;

        f.handler
            .handle(doc, Some(&did))
            .await
            .expect("write accepted");

        assert!(stored(&f.repo, &did).await);
    }

    #[tokio::test]
    async fn signed_delete_under_the_issuers_own_authority_is_applied() {
        let (key, did) = did_key(2);
        let f = fixture(vec![did.clone()]);
        let put = signed(unsigned(RECORD_PUT, Some(&did), put_payload(&did)), &key).await;
        f.handler
            .handle(put, Some(&did))
            .await
            .expect("put accepted");

        let delete = signed(
            unsigned(RECORD_DELETE, Some(&did), delete_payload(&did)),
            &key,
        )
        .await;
        f.handler
            .handle(delete, Some(&did))
            .await
            .expect("delete accepted");

        assert!(!stored(&f.repo, &did).await);
        assert!(matches!(last_audit(&f).operation, AuditOperation::Delete));
    }

    // --- Authority binding -------------------------------------------------

    #[tokio::test]
    async fn put_under_another_authority_is_refused() {
        let (key, did) = did_key(3);
        let f = fixture(vec![did.clone()]);
        let doc = signed(
            unsigned(RECORD_PUT, Some(&did), put_payload(OTHER_AUTHORITY)),
            &key,
        )
        .await;

        let err = f
            .handler
            .handle(doc, Some(&did))
            .await
            .expect_err("refused");

        assert_eq!(code(&err), "permissionDenied");
        assert!(!stored(&f.repo, OTHER_AUTHORITY).await);
        let entry = last_audit(&f);
        assert!(matches!(entry.status, AuditStatus::Unauthorized));
        assert_eq!(entry.actor, did, "the proven issuer is the actor");
        assert_eq!(
            entry.resource.authority_id.as_ref().map(|a| a.as_str()),
            Some(OTHER_AUTHORITY)
        );
    }

    #[tokio::test]
    async fn delete_under_another_authority_is_refused() {
        let (key, did) = did_key(4);
        let (other_key, other_did) = did_key(5);
        let f = fixture(vec![did.clone(), other_did.clone()]);
        let put = signed(
            unsigned(RECORD_PUT, Some(&other_did), put_payload(&other_did)),
            &other_key,
        )
        .await;
        f.handler
            .handle(put, Some(&other_did))
            .await
            .expect("owner's put accepted");

        let delete = signed(
            unsigned(RECORD_DELETE, Some(&did), delete_payload(&other_did)),
            &key,
        )
        .await;
        let err = f
            .handler
            .handle(delete, Some(&did))
            .await
            .expect_err("refused");

        assert_eq!(code(&err), "permissionDenied");
        assert!(stored(&f.repo, &other_did).await, "the record survives");
    }

    #[tokio::test]
    async fn a_configured_extra_authority_is_accepted() {
        let (key, did) = did_key(6);
        let f = fixture(vec![did.clone()]);
        let handler = f.handler.clone().with_admin_authorities(HashMap::from([(
            did.clone(),
            vec![OTHER_AUTHORITY.to_string()],
        )]));
        let doc = signed(
            unsigned(RECORD_PUT, Some(&did), put_payload(OTHER_AUTHORITY)),
            &key,
        )
        .await;

        handler
            .handle(doc, Some(&did))
            .await
            .expect("write accepted");

        assert!(stored(&f.repo, OTHER_AUTHORITY).await);
    }

    #[tokio::test]
    async fn a_put_naming_no_authority_is_refused() {
        let (key, did) = did_key(7);
        let f = fixture(vec![did.clone()]);
        let mut payload = put_payload(&did);
        payload["record"]
            .as_object_mut()
            .expect("record object")
            .remove("authority_id");
        let doc = signed(unsigned(RECORD_PUT, Some(&did), payload), &key).await;

        let err = f
            .handler
            .handle(doc, Some(&did))
            .await
            .expect_err("refused");

        assert_eq!(code(&err), "malformedRequest");
    }

    async fn enable_git_trust(f: &Fixture, authority: &str) {
        f.capabilities
            .enable(
                "git-trust",
                "0.1",
                Some(json!({ "authority": authority })),
                None,
            )
            .await
            .expect("git-trust enabled");
    }

    fn grant_payload() -> Value {
        json!({ "subject": "did:example:member", "resource": "org/repo" })
    }

    #[tokio::test]
    async fn a_grant_under_the_issuers_own_authority_is_applied() {
        let (key, did) = did_key(20);
        let f = fixture(vec![did.clone()]);
        enable_git_trust(&f, &did).await;
        let doc = signed(unsigned(GRANT, Some(&did), grant_payload()), &key).await;

        f.handler
            .handle(doc, Some(&did))
            .await
            .expect("grant accepted");

        let entry = last_audit(&f);
        assert!(matches!(entry.operation, AuditOperation::Grant));
        assert_eq!(
            entry.resource.authority_id.as_ref().map(|a| a.as_str()),
            Some(did.as_str())
        );
        assert_eq!(
            entry.resource.resource.as_ref().map(|r| r.as_str()),
            Some("org/repo")
        );
    }

    /// git-trust acts under the authority it was enabled with, and an admin
    /// may not grant under an authority it cannot act for.
    #[tokio::test]
    async fn a_grant_under_another_authority_is_refused() {
        let (key, did) = did_key(21);
        let f = fixture(vec![did.clone()]);
        enable_git_trust(&f, OTHER_AUTHORITY).await;
        let doc = signed(unsigned(GRANT, Some(&did), grant_payload()), &key).await;

        let err = f
            .handler
            .handle(doc, Some(&did))
            .await
            .expect_err("refused");

        assert_eq!(code(&err), "permissionDenied");
    }

    /// The capability config cannot be used to widen what an admin may act
    /// under: enabling git-trust for another authority is itself refused.
    #[tokio::test]
    async fn enabling_a_capability_under_another_authority_is_refused() {
        let (key, did) = did_key(22);
        let f = fixture(vec![did.clone()]);
        let doc = signed(
            unsigned(
                ENABLE,
                Some(&did),
                json!({
                    "capability": "git-trust",
                    "version": "0.1",
                    "config": { "authority": OTHER_AUTHORITY },
                }),
            ),
            &key,
        )
        .await;

        let err = f
            .handler
            .handle(doc, Some(&did))
            .await
            .expect_err("refused");

        assert_eq!(code(&err), "permissionDenied");
        assert!(
            f.capabilities
                .configured_authority("git-trust")
                .await
                .is_none()
        );
    }

    #[tokio::test]
    async fn enabling_a_capability_under_the_issuers_own_authority_is_accepted() {
        let (key, did) = did_key(23);
        let f = fixture(vec![did.clone()]);
        let doc = signed(
            unsigned(
                ENABLE,
                Some(&did),
                json!({
                    "capability": "git-trust",
                    "version": "0.1",
                    "config": { "authority": did },
                }),
            ),
            &key,
        )
        .await;

        f.handler
            .handle(doc, Some(&did))
            .await
            .expect("enable accepted");

        assert_eq!(
            f.capabilities.configured_authority("git-trust").await,
            Some(did)
        );
        assert!(matches!(last_audit(&f).operation, AuditOperation::Enable));
    }

    #[tokio::test]
    async fn disabling_a_capability_of_another_authority_is_refused() {
        let (key, did) = did_key(24);
        let f = fixture(vec![did.clone()]);
        enable_git_trust(&f, OTHER_AUTHORITY).await;
        let doc = signed(
            unsigned(DISABLE, Some(&did), json!({ "capability": "git-trust" })),
            &key,
        )
        .await;

        let err = f
            .handler
            .handle(doc, Some(&did))
            .await
            .expect_err("refused");

        assert_eq!(code(&err), "permissionDenied");
        assert!(
            f.capabilities
                .configured_authority("git-trust")
                .await
                .is_some()
        );
    }

    /// Without the capability set the authority of a capability task cannot
    /// be established, so the task is refused rather than run unbound.
    #[tokio::test]
    async fn a_capability_task_without_a_capability_set_is_refused() {
        let (key, did) = did_key(25);
        let f = fixture(vec![did.clone()]);
        enable_git_trust(&f, &did).await;
        let unbound = TaskHandler::new(
            f.capabilities.dispatcher(),
            ME,
            vec![did.clone()],
            trust_tasks_rs::erase_verifier(trust_tasks_proof::affinidi::Verifier::for_did_key()),
        )
        .with_dedup(Arc::new(MemoryMessageIdStore::default()));
        let doc = signed(unsigned(GRANT, Some(&did), grant_payload()), &key).await;

        let err = unbound.handle(doc, Some(&did)).await.expect_err("refused");

        assert_eq!(code(&err), "permissionDenied");
    }

    // --- Issuer, signer and proof ------------------------------------------

    #[tokio::test]
    async fn a_write_without_an_issuer_is_refused() {
        let (key, did) = did_key(8);
        let f = fixture(vec![did.clone()]);
        let mut doc = signed(unsigned(RECORD_PUT, Some(&did), put_payload(&did)), &key).await;
        doc.issuer = None;

        let err = f
            .handler
            .handle(doc, Some(&did))
            .await
            .expect_err("refused");

        assert_eq!(code(&err), "malformedRequest");
        assert!(!stored(&f.repo, &did).await);
        let entry = last_audit(&f);
        assert!(matches!(entry.status, AuditStatus::Unauthorized));
        assert!(entry.actor.is_empty(), "nothing was proven");
        assert_eq!(entry.claimed_actor.as_deref(), Some(did.as_str()));
    }

    /// The authenticated sender and the in-band issuer must be the same DID,
    /// whichever of them is an admin.
    #[tokio::test]
    async fn an_issuer_that_is_not_the_sender_is_refused() {
        let (key, did) = did_key(9);
        let (_, sender) = did_key(10);
        let f = fixture(vec![did.clone(), sender.clone()]);
        let doc = signed(unsigned(RECORD_PUT, Some(&did), put_payload(&did)), &key).await;

        let err = f
            .handler
            .handle(doc, Some(&sender))
            .await
            .expect_err("refused");

        assert_eq!(code(&err), "identityMismatch");
        assert_eq!(err.recipient.as_deref(), Some(sender.as_str()));
        assert!(!stored(&f.repo, &did).await);
        assert!(matches!(last_audit(&f).status, AuditStatus::Unauthorized));
    }

    #[tokio::test]
    async fn a_proof_by_another_did_is_refused() {
        let (_, did) = did_key(11);
        let (other_key, other_did) = did_key(12);
        let f = fixture(vec![did.clone(), other_did.clone()]);
        let mut doc = signed(
            unsigned(RECORD_PUT, Some(&other_did), put_payload(&did)),
            &other_key,
        )
        .await;
        doc.issuer = Some(did.clone());

        assert!(matches!(
            f.handler.authorize_write(&doc, Some(&did)),
            Err(RejectReason::ProofInvalid { .. })
        ));
        let err = f
            .handler
            .handle(doc, Some(&did))
            .await
            .expect_err("refused");
        assert_eq!(code(&err), "proofInvalid");
        assert!(!stored(&f.repo, &did).await);
    }

    /// A write is an operational message: an `assertionMethod` proof — an
    /// attestation key's purpose — does not authorise it (VTI-KEY-106).
    #[tokio::test]
    async fn an_assertion_method_proof_is_refused() {
        let (key, did) = did_key(13);
        let f = fixture(vec![did.clone()]);
        let doc = sign_with(
            unsigned(RECORD_PUT, Some(&did), put_payload(&did)),
            &key,
            SignOptions::new().with_proof_purpose("assertionMethod"),
        )
        .await;

        let err = f
            .handler
            .handle(doc, Some(&did))
            .await
            .expect_err("refused");

        assert_eq!(code(&err), "proofInvalid");
        assert!(!stored(&f.repo, &did).await);
    }

    #[tokio::test]
    async fn a_tampered_write_is_refused() {
        let (key, did) = did_key(14);
        let f = fixture(vec![did.clone()]);
        let mut doc = signed(unsigned(RECORD_PUT, Some(&did), put_payload(&did)), &key).await;
        doc.payload["record"]["entity_id"] = json!("did:example:someone-else");

        let err = f
            .handler
            .handle(doc, Some(&did))
            .await
            .expect_err("refused");

        assert_eq!(code(&err), "proofInvalid");
        assert!(!stored(&f.repo, &did).await);
    }

    #[tokio::test]
    async fn a_write_from_a_non_admin_is_denied() {
        let (key, did) = did_key(15);
        let f = fixture(vec!["did:example:admin".to_string()]);
        let doc = signed(unsigned(RECORD_PUT, Some(&did), put_payload(&did)), &key).await;

        let err = f
            .handler
            .handle(doc, Some(&did))
            .await
            .expect_err("refused");

        assert_eq!(code(&err), "permissionDenied");
    }

    /// A transport with no caller identity must never satisfy the admin ACL,
    /// whatever dispatcher it happens to be pointed at.
    #[tokio::test]
    async fn an_anonymous_write_is_denied() {
        let (key, did) = did_key(16);
        let f = fixture(vec![did.clone()]);
        let doc = signed(unsigned(RECORD_PUT, Some(&did), put_payload(&did)), &key).await;

        assert!(matches!(
            f.handler.authorize_write(&doc, None),
            Err(RejectReason::PermissionDenied { .. })
        ));
    }

    #[tokio::test]
    async fn a_write_without_a_proof_is_rejected() {
        let (_, did) = did_key(17);
        let f = fixture(vec![did.clone()]);
        let doc: TrustTask<Value> =
            serde_json::from_value(unsigned(RECORD_PUT, Some(&did), put_payload(&did)))
                .expect("parses");

        assert!(matches!(
            f.handler.authorize_write(&doc, Some(&did)),
            Err(RejectReason::ProofRequired)
        ));
    }

    // --- Operation-document checks (VTI-KEY-107) ---------------------------

    async fn refused_code(edit: impl FnOnce(&mut Value)) -> String {
        let (key, did) = did_key(30);
        let f = fixture(vec![did.clone()]);
        let mut unsigned_doc = unsigned(RECORD_PUT, Some(&did), put_payload(&did));
        edit(&mut unsigned_doc);
        let doc = signed(unsigned_doc, &key).await;
        let err = f
            .handler
            .handle(doc, Some(&did))
            .await
            .expect_err("refused");
        assert!(!stored(&f.repo, &did).await);
        code(&err)
    }

    #[tokio::test]
    async fn a_write_naming_no_recipient_is_refused() {
        let code = refused_code(|doc| {
            doc.as_object_mut().expect("object").remove("recipient");
        })
        .await;
        assert_eq!(code, "malformedRequest");
    }

    #[tokio::test]
    async fn a_write_addressed_elsewhere_is_refused() {
        let code = refused_code(|doc| doc["recipient"] = json!("did:example:elsewhere")).await;
        assert_eq!(code, "wrongRecipient");
    }

    #[tokio::test]
    async fn a_write_with_no_time_of_issue_is_refused() {
        let code = refused_code(|doc| {
            doc.as_object_mut().expect("object").remove("issuedAt");
        })
        .await;
        assert_eq!(code, "malformedRequest");
    }

    #[tokio::test]
    async fn a_write_older_than_the_acceptance_window_is_refused() {
        let code = refused_code(|doc| {
            doc["issuedAt"] =
                json!(Utc::now() - WRITE_ACCEPTANCE_WINDOW - chrono::TimeDelta::minutes(2));
        })
        .await;
        assert_eq!(code, "expired");
    }

    #[tokio::test]
    async fn a_write_issued_in_the_future_is_refused() {
        let code = refused_code(|doc| {
            doc["issuedAt"] = json!(Utc::now() + chrono::TimeDelta::minutes(10));
        })
        .await;
        assert_eq!(code, "malformedRequest");
    }

    // --- Replay ------------------------------------------------------------

    /// One record of accepted identifiers serves every binding: a document
    /// accepted through one handler is not executed again through another
    /// that shares the store, and its id cannot be reused for another
    /// document.
    #[tokio::test]
    async fn a_document_id_is_accepted_once_across_bindings() {
        let (key, did) = did_key(31);
        let f = fixture(vec![did.clone()]);
        let didcomm = f.handler.clone();
        let tsp = f.handler.clone();
        let first = signed(unsigned(RECORD_PUT, Some(&did), put_payload(&did)), &key).await;

        let original = didcomm
            .handle(first.clone(), Some(&did))
            .await
            .expect("first accepted");
        let replayed = tsp
            .handle(first.clone(), Some(&did))
            .await
            .expect("an identical redelivery is answered");
        assert_eq!(original, replayed, "answered from the record, not re-run");

        let mut reuse = unsigned(RECORD_PUT, Some(&did), put_payload(&did));
        reuse["id"] = json!(first.id);
        reuse["payload"]["record"]["resource"] = json!("another-repo");
        let reuse = signed(reuse, &key).await;
        let err = tsp.handle(reuse, Some(&did)).await.expect_err("refused");
        assert_eq!(code(&err), "idConflict");
    }

    /// Without the record a replay cannot be told from a fresh write.
    #[tokio::test]
    async fn a_write_without_a_replay_record_is_refused() {
        let (key, did) = did_key(32);
        let f = fixture(vec![did.clone()]);
        let unrecorded = TaskHandler::new(
            f.capabilities.dispatcher(),
            ME,
            vec![did.clone()],
            trust_tasks_rs::erase_verifier(trust_tasks_proof::affinidi::Verifier::for_did_key()),
        )
        .with_capabilities(f.capabilities.clone());
        let doc = signed(unsigned(RECORD_PUT, Some(&did), put_payload(&did)), &key).await;

        let err = unrecorded
            .handle(doc, Some(&did))
            .await
            .expect_err("refused");

        assert_eq!(code(&err), "unavailable");
        assert!(!stored(&f.repo, &did).await);
    }

    #[test]
    fn the_replay_record_outlives_the_acceptance_window() {
        let retention = chrono::TimeDelta::from_std(crate::dedup::DEFAULT_TTL).expect("fits");
        assert!(retention >= WRITE_ACCEPTANCE_WINDOW + trust_tasks_rs::DEFAULT_SKEW);
    }

    // --- Reads -------------------------------------------------------------

    #[test]
    fn reads_bypass_write_authorization() {
        let f = fixture(vec![]);
        assert!(
            f.handler
                .authorize_write(&read_doc(), Some("did:example:anyone"))
                .is_ok()
        );
        // Including anonymous ones — the HTTP query surface has no caller identity.
        assert!(f.handler.authorize_write(&read_doc(), None).is_ok());
    }

    /// Party resolution runs inside the handler, so a host calling `handle`
    /// directly cannot skip it — reads included.
    #[tokio::test]
    async fn a_read_whose_issuer_is_not_the_sender_is_refused() {
        let f = fixture(vec![]);
        let mut doc = read_doc();
        doc.issuer = Some("did:example:claimed".to_string());

        let err = f
            .handler
            .handle(doc, Some("did:example:actual"))
            .await
            .expect_err("refused");

        assert_eq!(code(&err), "identityMismatch");
    }

    #[tokio::test]
    async fn reads_are_not_audited() {
        let f = fixture(vec![]);
        let mut doc = read_doc();
        doc.recipient = Some(ME.to_string());
        let response = f
            .handler
            .handle(doc, None)
            .await
            .expect("recognition query should reach the dispatcher");
        assert!(response.type_uri.is_response());
        assert!(f.audit.entries.lock().unwrap().is_empty());
    }
}
