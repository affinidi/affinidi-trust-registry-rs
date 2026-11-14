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
//!    issuer lists under `authentication`
//!    ([`verify_write_proof`](crate::trust_tasks::verify_write_proof));
//! 6. the authority binding: a write acts only under an authority the issuer
//!    may act for ([`TaskHandler::authorize_authority`]). A write that acts on
//!    the registry itself (`registry/did/rotate`, or a capability change with
//!    no authority of its own) acts under the registry's own DID, so only an
//!    admin `ADMIN_AUTHORITIES` lists for that DID may make it;
//! 7. the replay record, shared by every binding: a document identifier is
//!    executed at most once ([`execute_once`]);
//! 8. dispatch — or, for `registry/did/rotate`, which acts on *our own* DID
//!    via the VTA, the rotation itself;
//! 9. an audit entry for the outcome, refusals included. A duplicate answered
//!    from the replay record is recorded as `REPLAYED`, and one that arrived
//!    while the original was running as `DUPLICATE_IN_FLIGHT`: neither was
//!    executed.
//!
//! Which of these steps a task goes through, and where in its payload its
//! authority and record key are, comes from its [`TaskDescriptor`] (or, for a
//! capability's write, from the [`CapabilitySet`]). A slug in one of the
//! registry's own families with no descriptor is not dispatched at all: it is
//! answered as an unsupported type, never served as a read by default.
//! `registry/record/query` goes through steps 3–9 like a write, with a replay
//! record of its own.
//!
//! What stays in the bindings is only what is genuinely transport-specific:
//! establishing which sender the transport authenticated, and packing the
//! returned document back onto the wire. Party resolution happens here, so a
//! host calling [`TaskHandler::handle`] directly gets it too.
//!
//! The transport-authenticated sender alone never authorises a write.

// `TaskOutcome`'s error is a whole `trust-task-error` document, which is large
// by design; boxing it would only move the allocation onto every caller. The
// router allows this lint for the same reason.
#![allow(clippy::result_large_err)]

use affinidi_did_common::scid::{same_reference, strip_scid_src};
use std::collections::HashMap;
use std::sync::Arc;

use chrono::Utc;
use serde_json::Value;
use trust_tasks_rs::{
    ConsistencyError, DynProofVerifier, ErrorResponse, FreshnessPolicy, RejectReason, TrustTask,
};

use crate::audit::model::{AuditLogBuilder, AuditLogger, AuditReason, AuditResource, AuditRole};
use crate::capabilities::{CONFIG_AUTHORITY, CapabilitySet, DispatcherHandle};
use crate::dedup::{
    DEFAULT_QUERY_MAX_ENTRIES, DEFAULT_QUERY_MAX_ENTRIES_PER_ISSUER, Disposition,
    MemoryMessageIdStore, MessageIdStore, execute_once,
};
use crate::domain::{Action, AuthorityId, EntityId, Resource};
use crate::trust_tasks::descriptor::{
    AuthorityRule, CAPABILITY_WRITE, Execution, Field, Replay, TaskDescriptor, descriptor,
    is_reserved,
};
use crate::trust_tasks::proof::{WRITE_PROOF_PURPOSE, verify_proof};
use crate::trust_tasks::reply::ReplySigner;
use crate::trust_tasks::router::new_id;
use crate::trust_tasks::{RegistryDispatcher, handle_document};

/// How old a write's time of issue may be (VTI-OPS-024). The replay record's
/// retention ([`crate::dedup::DEFAULT_TTL`]) is this plus the skew and a
/// minute of margin, so every document
/// inside the window is remembered for as long as it could be accepted.
pub const WRITE_ACCEPTANCE_WINDOW: chrono::TimeDelta = trust_tasks_rs::DEFAULT_MAX_AGE;

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

/// A capability that writes records found enabled with no authority, which
/// enabling now refuses: it must not be usable by every admin.
fn unbound_capability(capability: &str) -> RejectReason {
    RejectReason::PermissionDenied {
        reason: format!("{capability} is enabled without an authority, so no write can be bound"),
    }
}

/// The refusal of a write slug with no authority rule: it is never run under
/// no authority.
fn no_authority(slug: &str) -> RejectReason {
    RejectReason::PermissionDenied {
        reason: format!("no authority is defined for {slug}, so it cannot be bound"),
    }
}

/// How the handler treats a slug.
#[derive(Clone, Copy)]
enum Route {
    /// A public read: dispatched with the framework checks only.
    Read,
    /// Needs a proof, an admin and an authority, is executed at most once and
    /// is audited, by this rule.
    Proven(&'static TaskDescriptor),
    /// In one of the registry's own families, with no descriptor: not served.
    Unserved,
}

/// Where in `doc` one part of the record key is, read as a string.
fn field(rule: &TaskDescriptor, doc: &TrustTask<Value>, field: Field) -> Option<String> {
    match field {
        Field::Absent => None,
        Field::Fixed(value) => Some(value.to_string()),
        Field::At(member) => doc
            .payload
            .pointer(member.pointer(rule.camel_case(&doc.type_uri)))
            .and_then(Value::as_str)
            .map(str::to_string),
    }
}

/// What a write's audit entry needs from the document, taken before the
/// document is handed on.
struct AuditContext {
    rule: &'static TaskDescriptor,
    slug: String,
    id: String,
    thread_id: Option<String>,
    claimed: Option<String>,
    authenticated: Option<String>,
    digest: Option<String>,
    /// The record key (or capability): entity, action, resource. Identifiers
    /// only: never record contents, context or proofs.
    key: (Option<String>, Option<String>, Option<String>),
}

impl AuditContext {
    fn of(rule: &'static TaskDescriptor, doc: &TrustTask<Value>, sender_did: Option<&str>) -> Self {
        Self {
            rule,
            slug: doc.type_uri.slug().to_string(),
            id: doc.id.clone(),
            thread_id: doc.thread_id.clone(),
            claimed: doc
                .issuer
                .clone()
                .or_else(|| sender_did.map(str::to_string)),
            authenticated: sender_did.map(str::to_string),
            digest: trust_tasks_rs::document_digest(doc)
                .ok()
                .map(|digest| digest.to_string()),
            key: (
                field(rule, doc, rule.resource.entity),
                field(rule, doc, rule.resource.action),
                field(rule, doc, rule.resource.resource),
            ),
        }
    }

    /// The entry for `outcome`, given what the write established.
    fn entry(
        self,
        outcome: &Result<TrustTask<Value>, ErrorResponse>,
        progress: WriteProgress,
    ) -> crate::audit::model::AuditLog {
        let (entity, action, resource) = self.key;
        let proven = progress.proven_issuer.is_some();
        let (verification_method, proof_created) = progress.proof.unzip();
        let builder = AuditLogBuilder::new(self.rule.audit)
            // Only a proven issuer is named as the actor, and it is proven
            // only after the admin check (`authorize_write`) has passed.
            .role(if proven {
                AuditRole::Admin
            } else {
                AuditRole::Unproven
            })
            .actor(progress.proven_issuer.unwrap_or_default())
            .claimed_actor((!proven).then_some(self.claimed).flatten())
            .resource(AuditResource::new(
                entity.map(|e| EntityId::new(&e)),
                progress.authority.as_deref().map(AuthorityId::new),
                action.map(|a| Action::new(&a)),
                resource.map(|r| Resource::new(&r)),
            ))
            .authenticated_sender(self.authenticated)
            .task(self.slug)
            .document_id(self.id)
            .document_digest(self.digest)
            .proof(verification_method, proof_created)
            .thread_id(self.thread_id);
        match (progress.disposition, outcome) {
            // Nothing was executed for either: the entry of the execution
            // records what happened.
            (Some(Disposition::Replayed), _) => builder.build_replayed(),
            (Some(Disposition::InFlight), _) => builder.build_duplicate_in_flight(),
            (_, Ok(_)) => builder.build_success(),
            (_, Err(error)) => {
                let code = serde_json::to_value(&error.payload.code)
                    .ok()
                    .and_then(|code| code.as_str().map(str::to_string))
                    .filter(|code| !code.is_empty());
                let unauthorized = !proven
                    || matches!(
                        code.as_deref(),
                        Some("permissionDenied" | "identityMismatch")
                    );
                let message = error.payload.message.clone();
                let reason = match code {
                    Some(code) => AuditReason::coded(code, message),
                    None => AuditReason {
                        code: None,
                        message,
                    },
                };
                if unauthorized {
                    builder.build_unauthorized(reason)
                } else {
                    builder.build_failure(reason)
                }
            }
        }
    }
}

/// What a write established before it finished, for its audit entry.
#[derive(Default)]
struct WriteProgress {
    /// The issuer, once its proof has verified.
    proven_issuer: Option<String>,
    /// The authority the write acts under, once established.
    authority: Option<String>,
    /// The verified proof's verification method and `created` time.
    proof: Option<(String, chrono::DateTime<Utc>)>,
    /// What the replay record did with the document, once consulted.
    disposition: Option<Disposition>,
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
    /// The record of accepted `registry/record/query` documents, kept apart
    /// from `dedup` so that queries cannot use up the capacity writes need.
    /// Shared by the clones of this handler; a handler built separately (by
    /// [`new`](Self::new)) has its own.
    query_replay: Arc<dyn MessageIdStore>,
    /// Where capability tasks learn the authority they act under.
    capabilities: Option<Arc<CapabilitySet>>,
    /// Receives an entry for every write, refusals included.
    audit: Option<Arc<dyn AuditLogger>>,
    /// Signs every reply, errors included. A handler without one sends its
    /// replies unsigned, which a requester that checks will not accept.
    reply_signer: Option<ReplySigner>,
    /// The VTA `did/rotate` rotates through, loaded with the configuration.
    #[cfg(feature = "vta")]
    vta: Option<Arc<crate::configs::vta::VtaConfig>>,
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
            query_replay: Arc::new(MemoryMessageIdStore::default().with_limits(
                DEFAULT_QUERY_MAX_ENTRIES,
                DEFAULT_QUERY_MAX_ENTRIES_PER_ISSUER,
            )),
            capabilities: None,
            audit: None,
            reply_signer: None,
            #[cfg(feature = "vta")]
            vta: None,
        }
    }

    /// Attach the VTA `did/rotate` rotates the registry's keys through.
    /// Without one, rotation is refused as not configured.
    #[cfg(feature = "vta")]
    pub fn with_vta(mut self, vta: Option<Arc<crate::configs::vta::VtaConfig>>) -> Self {
        self.vta = vta;
        self
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

    /// Attach the operational key every reply is signed with. It must be a
    /// key of this handler's own DID.
    pub fn with_reply_signer(mut self, signer: ReplySigner) -> Self {
        self.reply_signer = Some(signer);
        self
    }

    /// Whether `slug` is handled as a write: one of the registry's own writes
    /// or `registry/record/query` (its descriptor
    /// [requires a proof](TaskDescriptor::requires_proof)), or a task a
    /// capability does not declare as a read.
    pub fn is_write(&self, slug: &str) -> bool {
        matches!(self.route(slug), Route::Proven(_))
    }

    /// How `slug` is handled. A capability's write is a write even where the
    /// registry describes the slug as a read; a slug the registry describes
    /// as needing a proof keeps its own rule whatever a capability registers.
    fn route(&self, slug: &str) -> Route {
        let described = descriptor(slug);
        match described {
            Some(rule) if rule.requires_proof() => Route::Proven(rule),
            _ if self
                .capabilities
                .as_ref()
                .is_some_and(|capabilities| capabilities.is_write(slug)) =>
            {
                Route::Proven(&CAPABILITY_WRITE)
            }
            Some(_) => Route::Read,
            None if is_reserved(slug) => Route::Unserved,
            None => Route::Read,
        }
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
            (Some(in_band), Some(transport)) if !same_reference(in_band, transport) => {
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
            Some(recipient) if !same_reference(recipient, &self.my_did) => {
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
    /// `authentication`, are checked afterwards by
    /// [`verify_write_proof`](crate::trust_tasks::verify_write_proof).
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
        if !self.is_write(doc.type_uri.slug()) {
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
        // Compared by DID: a did:scid party may present its DID with the
        // `?src=` locator it is resolved through (VTI-KEY-160, VTI-KEY-163).
        if !same_reference(issuer, sender_did) {
            return Err(RejectReason::IdentityMismatch(
                ConsistencyError::IssuerMismatch {
                    in_band: issuer.to_string(),
                    transport: sender_did.to_string(),
                },
            ));
        }
        let vm = proof.verification_method.as_str();
        let vm_did = vm.split_once('#').map_or(vm, |(did, _)| did);
        // Exact (Trust Tasks SPEC §4.8): a did:scid producer writes its issuer
        // and its method in the same form (VTI-KEY-163).
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
        if !self.admin_dids.iter().any(|d| same_reference(d, issuer)) {
            return Err(RejectReason::PermissionDenied {
                reason: format!("DID {issuer} is not authorised to modify the registry"),
            });
        }
        Ok(())
    }

    /// The authority a write acts under.
    ///
    /// Record tasks name it in the payload. A capability task acts under the
    /// authority its capability was enabled with, and enabling or disabling a
    /// capability acts under the authority its config names. A write that acts
    /// on the registry itself — `registry/did/rotate`, or enabling or
    /// disabling a capability whose config names no authority, or a task of a
    /// capability that writes no records — acts under the registry's own DID.
    ///
    /// `None` only for a capability task or disable whose capability is not
    /// enabled, which changes nothing: the task is answered as unsupported
    /// and the disable as `not_enabled`. A write slug with no rule here is
    /// refused rather than run under no authority.
    pub async fn target_authority(
        &self,
        doc: &TrustTask<Value>,
    ) -> Result<Option<String>, RejectReason> {
        self.resolve_authority(doc)
            .await
            .map(|(authority, _)| authority)
    }

    /// [`target_authority`](Self::target_authority), plus — for a task served
    /// by a capability — the dispatcher read in the same snapshot as the
    /// authority, which is the one the task must be dispatched through.
    async fn resolve_authority(
        &self,
        doc: &TrustTask<Value>,
    ) -> Result<(Option<String>, Option<Arc<RegistryDispatcher>>), RejectReason> {
        let slug = doc.type_uri.slug();
        let Route::Proven(rule) = self.route(slug) else {
            return Err(no_authority(slug));
        };
        let payload = &doc.payload;
        let named_capability = || {
            payload
                .get("capability")
                .and_then(Value::as_str)
                .ok_or_else(|| RejectReason::MalformedRequest {
                    reason: "a capability change must name its capability".to_string(),
                })
        };
        match rule.authority {
            AuthorityRule::NotApplicable => Err(no_authority(slug)),
            // The member is read in the spelling the document's version
            // uses. A document carrying the other spelling has no authority
            // here and is refused, before its payload is ever parsed.
            AuthorityRule::Member { at, what } => Ok((
                required_authority(
                    payload.pointer(at.pointer(rule.camel_case(&doc.type_uri))),
                    what,
                )?,
                None,
            )),
            AuthorityRule::EnableConfig => {
                let capability = named_capability()?;
                let authority = match payload.pointer(&format!("/config/{CONFIG_AUTHORITY}")) {
                    None => None,
                    Some(Value::String(authority)) => Some(authority.clone()),
                    Some(_) => {
                        return Err(RejectReason::MalformedRequest {
                            reason: "a capability's authority must be a DID string".to_string(),
                        });
                    }
                };
                if authority.is_none() && self.capabilities()?.requires_authority(capability) {
                    return Err(RejectReason::MalformedRequest {
                        reason: format!(
                            "{capability} writes records and must be enabled with an `{CONFIG_AUTHORITY}`"
                        ),
                    });
                }
                Ok((Some(authority.unwrap_or_else(|| self.my_did.clone())), None))
            }
            AuthorityRule::NamedCapability => {
                let capability = named_capability()?;
                self.capability_authority(self.capabilities()?, capability)
                    .await
            }
            AuthorityRule::Capability(capability) => {
                self.capability_authority(self.capabilities()?, capability)
                    .await
            }
            AuthorityRule::Registry => Ok((Some(self.my_did.clone()), None)),
            AuthorityRule::OwningCapability => match self
                .capabilities
                .as_deref()
                .and_then(|capabilities| Some((capabilities, capabilities.write_owner(slug)?)))
            {
                Some((capabilities, capability)) => {
                    self.capability_authority(capabilities, capability).await
                }
                None => Err(no_authority(slug)),
            },
        }
    }

    /// The authority a task of `capability` acts under, and the dispatcher
    /// read with it: the capability's configured authority, or the registry's
    /// own DID for a capability that writes no records. `None` when the
    /// capability is not enabled.
    async fn capability_authority(
        &self,
        capabilities: &CapabilitySet,
        capability: &str,
    ) -> Result<(Option<String>, Option<Arc<RegistryDispatcher>>), RejectReason> {
        let snapshot = capabilities.snapshot(capability).await;
        if !snapshot.enabled {
            return Ok((None, Some(snapshot.dispatcher)));
        }
        let authority = match snapshot.authority {
            Some(authority) => authority,
            None if capabilities.requires_authority(capability) => {
                return Err(unbound_capability(capability));
            }
            None => self.my_did.clone(),
        };
        Ok((Some(authority), Some(snapshot.dispatcher)))
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
    /// under an authority is itself a write under that authority. A write on
    /// the registry itself acts under the registry's DID, so it needs that DID
    /// listed for the issuer.
    ///
    /// Call only after [`authorize_write`](Self::authorize_write) and
    /// [`verify_write_proof`](crate::trust_tasks::verify_write_proof) have
    /// established who the issuer is.
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
            .get(&*strip_scid_src(issuer))
            .is_some_and(|authorities| authorities.iter().any(|a| same_reference(a, authority)));
        if same_reference(authority, issuer) || delegated {
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
    /// transport-level failure. Both are issued by this registry and, with a
    /// [`ReplySigner`], signed by it.
    pub async fn handle(
        &self,
        doc: TrustTask<Value>,
        sender_did: Option<&str>,
    ) -> Result<TrustTask<Value>, ErrorResponse> {
        match self.handle_unsealed(doc, sender_did).await {
            Ok(response) => Ok(self.seal_reply(response).await),
            Err(error) => Err(self.seal_reply(error).await),
        }
    }

    /// Make `reply` this registry's: issued by our own DID and signed with the
    /// operational key.
    ///
    /// The issuer is set here rather than trusted from the reply builders,
    /// which copy it from the request's `recipient` — a value the requester
    /// chose, and not yet checked when an early refusal is built. A reply that
    /// cannot be signed goes out unsigned and is logged: a requester that
    /// checks proofs will not accept it, which is the safe failure.
    ///
    /// [`handle`](Self::handle) does this to everything it returns; a binding
    /// calls it only for a reply it builds itself.
    pub async fn seal_reply<P>(&self, mut reply: TrustTask<P>) -> TrustTask<P>
    where
        P: serde::Serialize + serde::de::DeserializeOwned,
    {
        reply.issuer = Some(self.my_did.clone());
        reply.proof = None;
        let Some(signer) = &self.reply_signer else {
            return reply;
        };
        match signer.sign(&reply).await {
            Ok(signed) => signed,
            Err(e) => {
                tracing::error!(
                    "could not sign the reply {} with {}: {e}",
                    reply.id,
                    signer.verification_method()
                );
                reply
            }
        }
    }

    async fn handle_unsealed(
        &self,
        doc: TrustTask<Value>,
        sender_did: Option<&str>,
    ) -> Result<TrustTask<Value>, ErrorResponse> {
        let rule = match self.route(doc.type_uri.slug()) {
            Route::Proven(rule) => rule,
            Route::Read => return self.handle_read(doc, sender_did, true).await,
            Route::Unserved => return self.handle_read(doc, sender_did, false).await,
        };

        let audit = self
            .audit
            .as_ref()
            .map(|logger| (logger, AuditContext::of(rule, &doc, sender_did)));
        let mut progress = WriteProgress::default();
        let outcome = self
            .handle_write(rule, doc, sender_did, &mut progress)
            .await;
        if let Some((logger, context)) = audit {
            logger.log(context.entry(&outcome, progress)).await;
        }
        outcome
    }

    /// A public read, after the framework checks: dispatched when `served`,
    /// answered as an unsupported type otherwise.
    async fn handle_read(
        &self,
        doc: TrustTask<Value>,
        sender_did: Option<&str>,
        served: bool,
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
        if !served {
            // The same answer as for any type nothing registers, from a
            // dispatcher that registers nothing.
            return handle_document(&RegistryDispatcher::new(), doc).await;
        }
        let dispatcher = self.dispatcher.read().await.clone();
        handle_document(&dispatcher, doc).await
    }

    async fn handle_write(
        &self,
        rule: &'static TaskDescriptor,
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
        if let Err(reason) = verify_proof(&self.verifier, &doc).await {
            return Err(doc.reject_with(new_id(), reason));
        }
        progress.proven_issuer = doc.issuer.clone();
        progress.proof = doc
            .proof
            .as_ref()
            .map(|proof| (proof.verification_method.clone(), proof.created));

        let (authority, snapshot_dispatcher) = match self.resolve_authority(&doc).await {
            Ok(resolved) => resolved,
            Err(reason) => return Err(doc.reject_with(new_id(), reason)),
        };
        progress.authority = authority.clone();
        if let Err(reason) = self.authorize_authority(&doc, authority.as_deref()) {
            return Err(doc.reject_with(new_id(), reason));
        }

        let dedup = match (rule.replay(), &self.dedup) {
            (Replay::Queries, _) => &self.query_replay,
            (Replay::Writes, Some(dedup)) => dedup,
            // A write without the record of accepted identifiers, or a rule
            // that names none, is refused rather than run unrecorded.
            (Replay::Writes | Replay::None, _) => {
                return Err(
                    doc.reject_with(new_id(), RejectReason::Unavailable { retry_after: None })
                );
            }
        };

        let once = match rule.execution {
            Execution::DidRotate => {
                execute_once(dedup.as_ref(), doc, |doc| async move {
                    self.handle_did_rotate(rule, &doc).await
                })
                .await
            }
            Execution::Dispatcher => {
                let dispatcher = match snapshot_dispatcher {
                    Some(dispatcher) => dispatcher,
                    None => self.dispatcher.read().await.clone(),
                };
                execute_once(dedup.as_ref(), doc, |doc| handle_document(&dispatcher, doc)).await
            }
        };
        progress.disposition = Some(once.disposition);
        once.outcome
    }

    /// Rotate the registry's own VTA-managed `did:webvh` keys. Requires the
    /// `vta` feature; otherwise the request is rejected as unavailable.
    // `deprecated`: 0.1 is superseded by 0.2 and still answered on purpose, for
    // operators whose tooling has not moved.
    #[allow(deprecated)]
    async fn handle_did_rotate(
        &self,
        rule: &TaskDescriptor,
        doc: &TrustTask<Value>,
    ) -> Result<TrustTask<Value>, ErrorResponse> {
        #[cfg(feature = "vta")]
        {
            use crate::trust_tasks::payloads::{DidRotateRequest, DidRotateResponse, camel};
            use crate::trust_tasks::router::reject_build_err;

            let malformed = |reason: String| {
                doc.reject_with(new_id(), RejectReason::MalformedRequest { reason })
            };
            // One version: parse its request, rotate, build its response.
            // 0.1 is snake_case, 0.2 lowerCamelCase; both carry the same two
            // optional members and answer the same three.
            macro_rules! rotate {
                ($req:ty, $resp:ty) => {{
                    let req: $req = serde_json::from_value(doc.payload.clone())
                        .map_err(|e| malformed(e.to_string()))?;
                    let pre_rotation_count = req
                        .pre_rotation_count
                        .map(u32::try_from)
                        .transpose()
                        .map_err(|_| {
                            malformed("the pre-rotation count is out of range".to_string())
                        })?;
                    let label = req.label.map(|l| l.to_string());
                    let (did, new_scid, new_version_id) = crate::configs::vta::rotate_did(
                        self.vta.as_deref(),
                        &self.my_did,
                        pre_rotation_count,
                        label,
                    )
                    .await
                    .map_err(|reason| {
                        doc.reject_with(
                            new_id(),
                            RejectReason::TaskFailed {
                                reason,
                                details: None,
                            },
                        )
                    })?;
                    let response: Result<$resp, _> = <$resp>::builder()
                        .did(did)
                        .new_scid(new_scid)
                        .new_version_id(new_version_id)
                        .try_into();
                    let response = response.map_err(|e| reject_build_err(doc, e))?;
                    serde_json::to_value(response).unwrap_or(Value::Null)
                }};
            }
            let value = if rule.camel_case(&doc.type_uri) {
                rotate!(camel::DidRotateRequest, camel::DidRotateResponse)
            } else {
                rotate!(DidRotateRequest, DidRotateResponse)
            };
            Ok(doc.respond_with(new_id(), value))
        }
        #[cfg(not(feature = "vta"))]
        {
            let _ = rule;
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
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;
    use crate::audit::model::{AuditLog, AuditOperation, AuditRole, AuditStatus};
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
    use uuid::Uuid;

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
        fixture_with(admin_dids, Vec::new())
    }

    /// [`fixture`], with `extra` capabilities available beside git-trust.
    fn fixture_with(
        admin_dids: Vec<String>,
        extra: Vec<crate::capabilities::CapabilityDefinition>,
    ) -> Fixture {
        let repo = Arc::new(LocalStorage::new());
        let base_repo = repo.clone();
        let query_repo = repo.clone();
        let mut available =
            vec![git_trust::definition(repo.clone()).expect("git-trust definition")];
        available.extend(extra);
        let capabilities = CapabilitySet::new(
            available,
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

    /// The entry for an accepted write names the key that approved it and the
    /// digest of the exact document, so an archived copy of the signed
    /// document can be matched to it and checked.
    #[tokio::test]
    async fn an_accepted_write_records_its_digest_and_approving_key() {
        let (key, did) = did_key(1);
        let f = fixture(vec![did.clone()]);
        let doc = signed(unsigned(RECORD_PUT, Some(&did), put_payload(&did)), &key).await;
        let digest = trust_tasks_rs::document_digest(&doc).unwrap().to_string();
        let proof = doc.proof.clone().expect("signed");

        f.handler
            .handle(doc, Some(&did))
            .await
            .expect("write accepted");

        let entry = last_audit(&f);
        assert!(matches!(entry.status, AuditStatus::Success));
        assert_eq!(entry.document_digest.as_deref(), Some(digest.as_str()));
        assert_eq!(
            entry.verification_method.as_deref(),
            Some(proof.verification_method.as_str())
        );
        assert!(entry.verification_method.unwrap().starts_with(&did));
        assert_eq!(entry.proof_created, Some(proof.created));
    }

    /// A refused write still carries the digest, but no key is named for a
    /// proof that was never verified.
    #[tokio::test]
    async fn a_refused_write_names_no_approving_key() {
        let (key, did) = did_key(1);
        let (_, other) = did_key(2);
        let f = fixture(vec![other]);
        let doc = signed(unsigned(RECORD_PUT, Some(&did), put_payload(&did)), &key).await;
        let digest = trust_tasks_rs::document_digest(&doc).unwrap().to_string();

        f.handler
            .handle(doc, Some(&did))
            .await
            .expect_err("not an admin");

        let entry = last_audit(&f);
        assert!(!matches!(entry.status, AuditStatus::Success));
        assert_eq!(entry.document_digest.as_deref(), Some(digest.as_str()));
        assert_eq!(entry.verification_method, None);
        assert_eq!(entry.proof_created, None);
    }

    const RECORD_PUT_0_3: &str = "https://trusttasks.org/spec/registry/record/put/0.3";

    fn put_payload_0_3(authority: &str) -> Value {
        json!({
            "record": {
                "entityId": "did:example:member",
                "authorityId": authority,
                "action": "git.commit.sign",
                "resource": "repo",
                "authorized": true,
                "recordType": "authorization",
                "validUntil": "2099-01-01T00:00:00Z",
            }
        })
    }

    /// 0.3 names the authority `authorityId`; the write is bound to it exactly
    /// as a 0.1 write is bound to `authority_id`.
    #[tokio::test]
    async fn a_0_3_put_is_bound_to_its_camel_case_authority() {
        let (key, did) = did_key(1);
        let f = fixture(vec![did.clone()]);
        let doc = signed(
            unsigned(RECORD_PUT_0_3, Some(&did), put_payload_0_3(&did)),
            &key,
        )
        .await;
        f.handler
            .handle(doc, Some(&did))
            .await
            .expect("write accepted");
        assert!(stored(&f.repo, &did).await);
        let entry = last_audit(&f);
        assert_eq!(
            entry.resource.entity_id.as_ref().map(|e| e.as_str()),
            Some("did:example:member")
        );
    }

    #[tokio::test]
    async fn a_0_3_put_under_another_authority_is_refused() {
        let (key, did) = did_key(1);
        let f = fixture(vec![did.clone()]);
        let doc = signed(
            unsigned(RECORD_PUT_0_3, Some(&did), put_payload_0_3(OTHER_AUTHORITY)),
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
    }

    /// A 0.3 document spelled the 0.1 way has no `authorityId`, so it names no
    /// authority and is refused before anything is parsed or stored.
    #[tokio::test]
    async fn a_0_3_put_in_the_old_spelling_is_refused() {
        let (key, did) = did_key(1);
        let f = fixture(vec![did.clone()]);
        let doc = signed(
            unsigned(RECORD_PUT_0_3, Some(&did), put_payload(&did)),
            &key,
        )
        .await;
        let err = f
            .handler
            .handle(doc, Some(&did))
            .await
            .expect_err("refused");
        assert_eq!(code(&err), "malformedRequest");
        assert!(!stored(&f.repo, &did).await);
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

    /// A git-trust enabled with no authority (state written before enabling
    /// required one) is not usable by any admin.
    #[tokio::test]
    async fn a_capability_enabled_without_an_authority_is_unusable() {
        use crate::capabilities::{CapabilityState, CapabilityStateStore};
        let (key, did) = did_key(26);
        let repo = Arc::new(LocalStorage::new());
        let store = MemoryCapabilityStore::default();
        store
            .save(&std::collections::BTreeMap::from([(
                "git-trust".to_string(),
                CapabilityState {
                    version: "0.1".to_string(),
                    enabled: true,
                    config: None,
                    enabled_at: Utc::now(),
                    delegate: None,
                },
            )]))
            .expect("seed state");
        let base_repo = repo.clone();
        let query_repo = repo.clone();
        let capabilities = CapabilitySet::new(
            vec![git_trust::definition(repo.clone()).expect("git-trust definition")],
            Box::new(store),
            Box::new(move || build_dispatcher(base_repo.clone())),
            Box::new(move || build_query_dispatcher(query_repo.clone())),
        )
        .expect("capability set");
        let handler = TaskHandler::new(
            capabilities.dispatcher(),
            ME,
            vec![did.clone()],
            trust_tasks_rs::erase_verifier(trust_tasks_proof::affinidi::Verifier::for_did_key()),
        )
        .with_dedup(Arc::new(MemoryMessageIdStore::default()))
        .with_capabilities(capabilities);
        let doc = signed(unsigned(GRANT, Some(&did), grant_payload()), &key).await;

        let err = handler.handle(doc, Some(&did)).await.expect_err("refused");

        assert_eq!(code(&err), "permissionDenied");
    }

    #[tokio::test]
    async fn enabling_a_record_writing_capability_without_an_authority_is_refused() {
        let (key, did) = did_key(27);
        let f = fixture(vec![did.clone()]);
        let doc = signed(
            unsigned(
                ENABLE,
                Some(&did),
                json!({ "capability": "git-trust", "version": "0.1" }),
            ),
            &key,
        )
        .await;

        let err = f
            .handler
            .handle(doc, Some(&did))
            .await
            .expect_err("refused");

        assert_eq!(code(&err), "malformedRequest");
        assert!(!f.capabilities.snapshot("git-trust").await.enabled);
    }

    // --- host-defined capability tasks ----------------------------------------

    const BADGE_ISSUE: &str = "https://trusttasks.org/spec/badge/issue/0.1";
    const ROTATE: &str = "https://trusttasks.org/spec/registry/did/rotate/0.2";

    /// A host's own task that changes state, registered by a host capability
    /// that declares no reads.
    #[derive(serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    struct BadgeIssue {
        subject: String,
    }

    impl trust_tasks_rs::Payload for BadgeIssue {
        const TYPE_URI: &'static str = BADGE_ISSUE;
    }

    /// The `badge` capability: one task, `badge/issue`, not declared as a
    /// read. `runs` counts how often its handler executed.
    fn badge_capability(
        runs: Arc<std::sync::atomic::AtomicUsize>,
    ) -> crate::capabilities::CapabilityDefinition {
        crate::capabilities::CapabilityDefinition {
            manifest: serde_json::from_value(json!({
                "capability": "badge",
                "version": "0.1",
                "specs": ["badge/*"]
            }))
            .expect("manifest"),
            register: Arc::new(
                move |dispatcher: RegistryDispatcher, _: &crate::capabilities::CapabilityState| {
                    let runs = runs.clone();
                    dispatcher.on::<BadgeIssue, _>(move |doc| -> crate::trust_tasks::TaskFuture {
                        runs.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                        Box::pin(async move { Ok(doc.respond_with(new_id(), json!({}))) })
                    })
                },
            ),
            register_reads: None,
            validate_config: None,
            requires_authority: false,
        }
    }

    struct BadgeFixture {
        f: Fixture,
        runs: Arc<std::sync::atomic::AtomicUsize>,
    }

    impl BadgeFixture {
        fn runs(&self) -> usize {
            self.runs.load(std::sync::atomic::Ordering::SeqCst)
        }
    }

    async fn badge_fixture(admin_dids: Vec<String>, enabled: bool) -> BadgeFixture {
        let runs = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let f = fixture_with(admin_dids, vec![badge_capability(runs.clone())]);
        if enabled {
            f.capabilities
                .enable("badge", "0.1", None, None)
                .await
                .expect("badge enabled");
        }
        BadgeFixture { f, runs }
    }

    fn badge_payload() -> Value {
        json!({ "subject": "did:example:member" })
    }

    #[tokio::test]
    async fn an_undeclared_capability_task_from_an_anonymous_caller_is_refused() {
        let b = badge_fixture(Vec::new(), true).await;
        let doc: TrustTask<Value> =
            serde_json::from_value(unsigned(BADGE_ISSUE, None, badge_payload())).unwrap();

        let err = b.f.handler.handle(doc, None).await.expect_err("refused");

        assert_eq!(code(&err), "proofRequired");
        assert_eq!(b.runs(), 0);
        assert!(matches!(last_audit(&b.f).status, AuditStatus::Unauthorized));
    }

    #[tokio::test]
    async fn an_undeclared_capability_task_from_a_non_admin_is_refused() {
        let (key, did) = did_key(60);
        let b = badge_fixture(vec!["did:example:admin".to_string()], true).await;
        let doc = signed(unsigned(BADGE_ISSUE, Some(&did), badge_payload()), &key).await;

        let err =
            b.f.handler
                .handle(doc, Some(&did))
                .await
                .expect_err("refused");

        assert_eq!(code(&err), "permissionDenied");
        assert_eq!(b.runs(), 0);
    }

    #[tokio::test]
    async fn an_unsigned_capability_task_from_an_admin_is_refused() {
        let (_, did) = did_key(61);
        let b = badge_fixture(vec![did.clone()], true).await;
        let doc: TrustTask<Value> =
            serde_json::from_value(unsigned(BADGE_ISSUE, Some(&did), badge_payload())).unwrap();

        let err =
            b.f.handler
                .handle(doc, Some(&did))
                .await
                .expect_err("refused");

        assert_eq!(code(&err), "proofRequired");
        assert_eq!(b.runs(), 0);
    }

    /// A capability that writes no records has no authority of its own, so
    /// its tasks act on the registry itself: only an admin listed for the
    /// registry's DID may run them.
    #[tokio::test]
    async fn a_capability_task_without_an_authority_needs_an_admin_of_the_registry_did() {
        let (key, did) = did_key(62);
        let b = badge_fixture(vec![did.clone()], true).await;

        let doc = signed(unsigned(BADGE_ISSUE, Some(&did), badge_payload()), &key).await;
        let err =
            b.f.handler
                .handle(doc, Some(&did))
                .await
                .expect_err("refused");
        assert_eq!(code(&err), "permissionDenied");
        assert_eq!(b.runs(), 0);

        let operator =
            b.f.handler
                .clone()
                .with_admin_authorities(HashMap::from([(did.clone(), vec![ME.to_string()])]));
        let doc = signed(unsigned(BADGE_ISSUE, Some(&did), badge_payload()), &key).await;
        operator
            .handle(doc, Some(&did))
            .await
            .expect("accepted for an admin of the registry DID");
        assert_eq!(b.runs(), 1);
        let entry = last_audit(&b.f);
        assert!(matches!(entry.status, AuditStatus::Success));
        assert_eq!(
            entry.resource.authority_id.as_ref().map(|a| a.as_str()),
            Some(ME)
        );
    }

    /// The read-only surface serves no capability task that is not a
    /// declared read, so an unauthenticated caller cannot reach it there.
    #[tokio::test]
    async fn an_undeclared_capability_task_is_not_served_on_the_read_only_surface() {
        let b = badge_fixture(Vec::new(), true).await;
        let query = TaskHandler::new(
            b.f.capabilities.query_dispatcher(),
            ME,
            Vec::new(),
            trust_tasks_rs::erase_verifier(trust_tasks_proof::affinidi::Verifier::for_did_key()),
        );
        let doc: TrustTask<Value> =
            serde_json::from_value(unsigned(BADGE_ISSUE, None, badge_payload())).unwrap();

        query.handle(doc, None).await.expect_err("refused");

        assert_eq!(b.runs(), 0);
    }

    #[tokio::test]
    async fn enabling_a_capability_without_an_authority_needs_an_admin_of_the_registry_did() {
        let (key, did) = did_key(63);
        let b = badge_fixture(vec![did.clone()], false).await;
        let enable = || {
            unsigned(
                ENABLE,
                Some(&did),
                json!({ "capability": "badge", "version": "0.1" }),
            )
        };

        let err =
            b.f.handler
                .handle(signed(enable(), &key).await, Some(&did))
                .await
                .expect_err("refused");
        assert_eq!(code(&err), "permissionDenied");
        assert!(!b.f.capabilities.snapshot("badge").await.enabled);

        let operator =
            b.f.handler
                .clone()
                .with_admin_authorities(HashMap::from([(did.clone(), vec![ME.to_string()])]));
        operator
            .handle(signed(enable(), &key).await, Some(&did))
            .await
            .expect("accepted for an admin of the registry DID");
        assert!(b.f.capabilities.snapshot("badge").await.enabled);
    }

    /// Disabling a capability that is not enabled changes nothing, and still
    /// answers `not_enabled` (which a VTC projecting its state treats as
    /// converged) rather than a permission error.
    #[tokio::test]
    async fn disabling_a_capability_that_is_not_enabled_answers_not_enabled() {
        let (key, did) = did_key(64);
        let b = badge_fixture(vec![did.clone()], false).await;
        let doc = signed(
            unsigned(DISABLE, Some(&did), json!({ "capability": "badge" })),
            &key,
        )
        .await;

        let err =
            b.f.handler
                .handle(doc, Some(&did))
                .await
                .expect_err("refused");

        assert_eq!(code(&err), "taskFailed");
        assert!(serde_json::to_string(&err).unwrap().contains("not_enabled"));
    }

    // --- registry/did/rotate acts on the registry itself --------------------

    #[tokio::test]
    async fn rotating_the_registry_did_needs_an_admin_of_the_registry_did() {
        let (key, did) = did_key(65);
        let f = fixture(vec![did.clone()]);
        let doc = signed(unsigned(ROTATE, Some(&did), json!({})), &key).await;

        let err = f
            .handler
            .handle(doc, Some(&did))
            .await
            .expect_err("refused");

        assert_eq!(code(&err), "permissionDenied");
        let entry = last_audit(&f);
        assert!(matches!(entry.operation, AuditOperation::Rotate));
        assert!(matches!(entry.status, AuditStatus::Unauthorized));
    }

    #[tokio::test]
    async fn an_admin_of_the_registry_did_may_rotate_it() {
        let (key, did) = did_key(66);
        let f = fixture(vec![did.clone()]);
        let operator = f
            .handler
            .clone()
            .with_admin_authorities(HashMap::from([(did.clone(), vec![ME.to_string()])]));
        let doc = signed(unsigned(ROTATE, Some(&did), json!({})), &key).await;

        // Past the authority binding the rotation itself runs; with no VTA
        // configured (or no `vta` feature) it fails as a task, not as a
        // permission.
        let err = operator.handle(doc, Some(&did)).await.expect_err("no VTA");

        assert_eq!(code(&err), "taskFailed");
        let entry = last_audit(&f);
        assert_eq!(
            entry.resource.authority_id.as_ref().map(|a| a.as_str()),
            Some(ME)
        );
    }

    // --- record/query is not public ------------------------------------------

    const RECORD_QUERY: &str = "https://trusttasks.org/spec/registry/record/query/0.1";

    #[tokio::test]
    async fn an_unsigned_record_query_is_refused() {
        let (_, did) = did_key(40);
        let f = fixture(vec![did.clone()]);
        let doc: TrustTask<Value> = serde_json::from_value(unsigned(
            RECORD_QUERY,
            Some(&did),
            json!({ "authority_id": did }),
        ))
        .expect("parses");

        let err = f
            .handler
            .handle(doc, Some(&did))
            .await
            .expect_err("refused");

        assert_eq!(code(&err), "proofRequired");
    }

    #[tokio::test]
    async fn a_signed_record_query_under_the_issuers_authority_answers() {
        let (key, did) = did_key(41);
        let f = fixture(vec![did.clone()]);
        let put = signed(unsigned(RECORD_PUT, Some(&did), put_payload(&did)), &key).await;
        f.handler
            .handle(put, Some(&did))
            .await
            .expect("put accepted");
        let query = signed(
            unsigned(RECORD_QUERY, Some(&did), json!({ "authority_id": did })),
            &key,
        )
        .await;

        let response = f.handler.handle(query, Some(&did)).await.expect("answered");

        assert_eq!(
            response.payload["records"].as_array().map(Vec::len),
            Some(1)
        );
        assert!(matches!(last_audit(&f).operation, AuditOperation::Read));
    }

    #[tokio::test]
    async fn a_record_query_under_another_authority_is_refused() {
        let (key, did) = did_key(42);
        let f = fixture(vec![did.clone()]);
        let query = signed(
            unsigned(
                RECORD_QUERY,
                Some(&did),
                json!({ "authority_id": OTHER_AUTHORITY }),
            ),
            &key,
        )
        .await;

        let err = f
            .handler
            .handle(query, Some(&did))
            .await
            .expect_err("refused");

        assert_eq!(code(&err), "permissionDenied");
    }

    #[tokio::test]
    async fn a_record_query_naming_no_authority_is_refused() {
        let (key, did) = did_key(43);
        let f = fixture(vec![did.clone()]);
        let query = signed(unsigned(RECORD_QUERY, Some(&did), json!({})), &key).await;

        let err = f
            .handler
            .handle(query, Some(&did))
            .await
            .expect_err("refused");

        assert_eq!(code(&err), "malformedRequest");
    }

    /// Queries have their own record, so an admin's queries cannot use up the
    /// capacity its writes need.
    #[tokio::test]
    async fn queries_do_not_use_the_write_record() {
        let (key, did) = did_key(45);
        let f = fixture(vec![did.clone()]);
        let handler = f
            .handler
            .clone()
            .with_dedup(Arc::new(MemoryMessageIdStore::default().with_limits(10, 1)));
        for _ in 0..3 {
            let query = signed(
                unsigned(RECORD_QUERY, Some(&did), json!({ "authority_id": did })),
                &key,
            )
            .await;
            handler.handle(query, Some(&did)).await.expect("answered");
        }

        let put = signed(unsigned(RECORD_PUT, Some(&did), put_payload(&did)), &key).await;
        handler
            .handle(put, Some(&did))
            .await
            .expect("write accepted");

        assert!(stored(&f.repo, &did).await);
    }

    #[tokio::test]
    async fn a_record_query_from_a_non_admin_is_refused() {
        let (key, did) = did_key(44);
        let f = fixture(vec!["did:example:admin".to_string()]);
        let query = signed(
            unsigned(RECORD_QUERY, Some(&did), json!({ "authority_id": did })),
            &key,
        )
        .await;

        let err = f
            .handler
            .handle(query, Some(&did))
            .await
            .expect_err("refused");

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

    /// A did:scid admin may present its DID with the `?src=` locator it is
    /// resolved through, while the transport authenticates the bare DID: both
    /// name the same identity (VTI-KEY-160, VTI-KEY-163). The proof's method is
    /// written in the issuer's form, and is bound to it exactly.
    #[tokio::test]
    async fn a_did_scid_admin_is_matched_by_its_did() {
        let (key, did) = did_key(40);
        let bare = "did:scid:vh:1:QmScid";
        let located = "did:scid:vh:1:QmScid?src=registry.example";
        let f = fixture(vec![bare.to_string()]);
        let mut doc = signed(unsigned(RECORD_PUT, Some(&did), put_payload(&did)), &key).await;
        doc.issuer = Some(located.to_string());
        doc.proof.as_mut().expect("signed").verification_method = format!("{located}#key-1");

        assert!(f.handler.authorize_write(&doc, Some(bare)).is_ok());
        assert!(f.handler.authorize_write(&doc, Some(located)).is_ok());
        // A method written in another form than the issuer is not bound to it.
        let mut other_form = doc.clone();
        other_form
            .proof
            .as_mut()
            .expect("signed")
            .verification_method = format!("{bare}#key-1");
        assert!(matches!(
            f.handler.authorize_write(&other_form, Some(bare)),
            Err(RejectReason::ProofInvalid { .. })
        ));
        // Its did:webvh log is a different identity (VTI-KEY-164).
        assert!(matches!(
            f.handler
                .authorize_write(&doc, Some("did:webvh:QmScid:registry.example")),
            Err(RejectReason::IdentityMismatch(_))
        ));

        let handler = f.handler.clone().with_admin_authorities(HashMap::from([(
            bare.to_string(),
            vec![OTHER_AUTHORITY.to_string()],
        )]));
        assert!(handler.authorize_authority(&doc, Some(bare)).is_ok());
        assert!(
            handler
                .authorize_authority(&doc, Some(OTHER_AUTHORITY))
                .is_ok()
        );
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

    /// At-least-once delivery makes duplicates routine: the audit trail
    /// records one write and one replay, not two writes.
    #[tokio::test]
    async fn a_replayed_duplicate_is_audited_as_a_replay() {
        let (key, did) = did_key(33);
        let f = fixture(vec![did.clone()]);
        let doc = signed(unsigned(RECORD_PUT, Some(&did), put_payload(&did)), &key).await;

        f.handler
            .handle(doc.clone(), Some(&did))
            .await
            .expect("first accepted");
        f.handler
            .handle(doc.clone(), Some(&did))
            .await
            .expect("the duplicate is answered");

        let entries = f.audit.entries.lock().unwrap().clone();
        let statuses: Vec<AuditStatus> = entries.iter().map(|e| e.status).collect();
        assert_eq!(statuses, vec![AuditStatus::Success, AuditStatus::Replayed]);
        let (first, replay) = (&entries[0], &entries[1]);
        assert_eq!(replay.document_digest, first.document_digest);
        assert_eq!(replay.document_id, first.document_id);
        assert_eq!(replay.actor, did);
        assert!(replay.reason.is_none());
    }

    /// A store that reports every claim as held by another copy.
    struct AlwaysInFlight;

    #[async_trait::async_trait]
    impl MessageIdStore for AlwaysInFlight {
        async fn claim(
            &self,
            _key: &str,
            _digest: &str,
        ) -> Result<crate::dedup::Claim, crate::dedup::DedupError> {
            Ok(crate::dedup::Claim::InFlight)
        }
        async fn complete(
            &self,
            _key: &str,
            _outcome: &crate::dedup::StoredOutcome,
        ) -> Result<(), crate::dedup::DedupError> {
            Ok(())
        }
        async fn release(&self, _key: &str) -> Result<(), crate::dedup::DedupError> {
            Ok(())
        }
    }

    /// A copy that arrives while the original runs is told to retry; it is
    /// not recorded as a failed write by the issuer.
    #[tokio::test]
    async fn an_in_flight_duplicate_is_not_audited_as_a_failure() {
        let (key, did) = did_key(34);
        let f = fixture(vec![did.clone()]);
        let handler = f.handler.clone().with_dedup(Arc::new(AlwaysInFlight));
        let doc = signed(unsigned(RECORD_PUT, Some(&did), put_payload(&did)), &key).await;

        let err = handler
            .handle(doc, Some(&did))
            .await
            .expect_err("told to retry");
        assert_eq!(code(&err), "taskFailed");
        assert!(err.payload.retryable);
        assert!(!stored(&f.repo, &did).await);

        let entry = last_audit(&f);
        assert_eq!(entry.status, AuditStatus::DuplicateInFlight);
        assert_eq!(entry.actor, did);
        assert!(entry.reason.is_none());
    }

    /// `role` says what the actor was proven to be: an admin only once its
    /// proof verified.
    #[tokio::test]
    async fn only_a_proven_admin_is_audited_as_one() {
        let (key, did) = did_key(35);
        let f = fixture(vec![did.clone()]);
        let doc = signed(unsigned(RECORD_PUT, Some(&did), put_payload(&did)), &key).await;
        f.handler.handle(doc, Some(&did)).await.expect("accepted");
        let entry = last_audit(&f);
        assert_eq!(entry.role, AuditRole::Admin);

        let (outsider_key, outsider) = did_key(36);
        let doc = signed(
            unsigned(RECORD_PUT, Some(&outsider), put_payload(&outsider)),
            &outsider_key,
        )
        .await;
        f.handler
            .handle(doc, Some(&outsider))
            .await
            .expect_err("not an admin");
        let entry = last_audit(&f);
        assert_eq!(entry.status, AuditStatus::Unauthorized);
        assert_eq!(entry.role, AuditRole::Unproven);
        assert_eq!(entry.actor, "");
        let reason = entry.reason.expect("a reason");
        assert_eq!(reason.code.as_deref(), Some("permissionDenied"));
        assert!(
            reason
                .message
                .is_some_and(|message| message.contains("not authorised"))
        );
    }

    /// A task in one of the registry's own families that the descriptor
    /// table does not describe is never served, even if a dispatcher
    /// registers it: nothing says whether it needs a proof.
    #[tokio::test]
    async fn an_undescribed_registry_task_is_not_served() {
        const SHADOW: &str = "https://trusttasks.org/spec/registry/shadow/0.1";
        #[derive(serde::Serialize, serde::Deserialize)]
        struct Shadow {}
        impl trust_tasks_rs::Payload for Shadow {
            const TYPE_URI: &'static str = SHADOW;
        }

        let runs = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let counter = runs.clone();
        let dispatcher = build_dispatcher(Arc::new(LocalStorage::new())).on::<Shadow, _>(
            move |doc| -> crate::trust_tasks::TaskFuture {
                counter.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                Box::pin(async move { Ok(doc.respond_with(new_id(), json!({}))) })
            },
        );
        let handler = TaskHandler::new(
            Arc::new(tokio::sync::RwLock::new(Arc::new(dispatcher))),
            ME,
            Vec::new(),
            trust_tasks_rs::erase_verifier(trust_tasks_proof::affinidi::Verifier::for_did_key()),
        );
        assert!(!handler.is_write("registry/shadow"));

        let doc: TrustTask<Value> =
            serde_json::from_value(unsigned(SHADOW, None, json!({}))).expect("document");
        let err = handler.handle(doc, None).await.expect_err("not served");
        assert_eq!(code(&err), "unsupportedType");
        assert_eq!(runs.load(std::sync::atomic::Ordering::SeqCst), 0);
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

    /// A registry keyed by its own `did:key`, signing its replies with it.
    fn signing_registry(admin_dids: Vec<String>) -> (TaskHandler, String) {
        let (key, registry) = did_key(9);
        let f = fixture(admin_dids);
        let handler = TaskHandler::new(
            f.capabilities.dispatcher(),
            registry.clone(),
            f.handler.admin_dids.clone(),
            trust_tasks_rs::erase_verifier(trust_tasks_proof::affinidi::Verifier::for_did_key()),
        )
        .with_dedup(Arc::new(MemoryMessageIdStore::default()))
        .with_capabilities(f.capabilities.clone())
        .with_reply_signer(ReplySigner::new(key).expect("an Ed25519 key signs"));
        (handler, registry)
    }

    /// `reply` verifies as `registry`'s own operational message.
    async fn assert_signed_by<P: serde::Serialize>(reply: &TrustTask<P>, registry: &str) {
        let reply: TrustTask<Value> =
            serde_json::from_value(serde_json::to_value(reply).expect("serialise"))
                .expect("reparse");
        assert_eq!(reply.issuer.as_deref(), Some(registry));
        let proof = reply.proof.as_ref().expect("the reply carries a proof");
        assert_eq!(proof.proof_purpose, WRITE_PROOF_PURPOSE);
        assert_eq!(
            proof.verification_method.split('#').next(),
            Some(registry),
            "signed with the registry's key"
        );
        trust_tasks_rs::erase_verifier(trust_tasks_proof::affinidi::Verifier::for_did_key())
            .verify_json(&reply)
            .await
            .expect("the reply's proof verifies");
    }

    #[tokio::test]
    async fn a_success_reply_is_signed_by_the_registry() {
        let (key, did) = did_key(1);
        let (handler, registry) = signing_registry(vec![did.clone()]);
        let mut doc = unsigned(RECORD_PUT, Some(&did), put_payload(&did));
        doc["recipient"] = json!(registry);
        let doc = signed(doc, &key).await;

        let response = handler
            .handle(doc, Some(&did))
            .await
            .expect("write accepted");

        assert_eq!(response.recipient.as_deref(), Some(did.as_str()));
        assert_signed_by(&response, &registry).await;
    }

    /// A rejection is signed as a success is: an unsigned one could be forged
    /// by anyone who saw the request, and a requester could not tell it from
    /// the registry's.
    #[tokio::test]
    async fn a_rejection_is_signed_by_the_registry() {
        let (key, did) = did_key(1);
        let (handler, registry) = signing_registry(Vec::new());
        let mut doc = unsigned(RECORD_PUT, Some(&did), put_payload(&did));
        doc["recipient"] = json!(registry);
        let doc = signed(doc, &key).await;

        let err = handler
            .handle(doc, Some(&did))
            .await
            .expect_err("not on the admin list");

        assert_eq!(code(&err), "permissionDenied");
        assert_signed_by(&err, &registry).await;
    }

    /// An early refusal is built before the request's `recipient` is checked,
    /// so the reply's issuer must not be copied from it.
    #[tokio::test]
    async fn a_refusal_names_the_registry_whatever_the_request_addressed() {
        let (_, did) = did_key(1);
        let (handler, registry) = signing_registry(Vec::new());
        let mut doc = unsigned(
            RECORD_PUT,
            Some("did:example:someone-else"),
            put_payload(&did),
        );
        doc["recipient"] = json!("did:example:not-the-registry");
        let doc: TrustTask<Value> = serde_json::from_value(doc).expect("document");

        let err = handler
            .handle(doc, Some(&did))
            .await
            .expect_err("the in-band issuer is not the sender");

        assert_signed_by(&err, &registry).await;
    }

    /// One locked request version: its Type URI, the schema its generated
    /// module embeds, and whether a payload deserializes into its type.
    type LockedVersion = (String, Option<&'static str>, fn(Value) -> bool);

    /// Every request version `trust-tasks.lock` pins, from the generated
    /// `crate::specs` modules. The superseded 0.1 versions are deprecated and
    /// still answered on purpose.
    #[allow(deprecated)]
    fn locked_versions() -> Vec<LockedVersion> {
        macro_rules! locked {
            ($($module:path),* $(,)?) => {
                vec![$({
                    use $module as m;
                    (
                        <m::Payload as trust_tasks_rs::Payload>::type_uri().to_string(),
                        <m::Payload as trust_tasks_rs::Payload>::PAYLOAD_SCHEMA,
                        (|v: Value| serde_json::from_value::<m::Payload>(v).is_ok())
                            as fn(Value) -> bool,
                    )
                }),*]
            };
        }
        locked![
            crate::specs::git_trust::grant::v0_1,
            crate::specs::git_trust::revoke::v0_1,
            crate::specs::governance::capability::disable::v0_1,
            crate::specs::governance::capability::enable::v0_1,
            crate::specs::governance::capability::list::v0_1,
            crate::specs::registry::authorization::v0_1,
            crate::specs::registry::authorization::v0_2,
            crate::specs::registry::did::rotate::v0_1,
            crate::specs::registry::did::rotate::v0_2,
            crate::specs::registry::recognition::v0_1,
            crate::specs::registry::recognition::v0_2,
            crate::specs::registry::record::delete::v0_1,
            crate::specs::registry::record::delete::v0_2,
            crate::specs::registry::record::put::v0_1,
            crate::specs::registry::record::put::v0_3,
            crate::specs::registry::record::query::v0_1,
            crate::specs::registry::record::query::v0_3,
        ]
    }

    /// Every Type URI the registry answers resolves to a schema generated
    /// from `trust-tasks.lock`, and a payload that breaks it is refused.
    ///
    /// trust-tasks-rs is built without its prebuilt spec families, so
    /// `trust_tasks_rs::schema_index` does not know these URIs and a lookup
    /// there returns `None`. Nothing in the registry may use it. Payload
    /// schemas come from the generated types, so this fails if a registration
    /// has no locked version behind it, if the lock gains a version the table
    /// below does not name, or if a generated type loses its schema.
    #[tokio::test]
    #[allow(deprecated)]
    async fn every_answered_type_uri_resolves_to_a_generated_schema() {
        let (_, did) = did_key(40);
        let f = fixture(vec![did.clone()]);
        enable_git_trust(&f, &did).await;

        let mut answered: Vec<String> = Vec::new();
        for handle in [
            f.capabilities.dispatcher(),
            f.capabilities.query_dispatcher(),
        ] {
            let dispatcher = handle.read().await.clone();
            answered.extend(
                dispatcher
                    .registered_uris()
                    .into_iter()
                    .map(|u| u.to_string()),
            );
        }
        // `registry/did/rotate` is answered by the handler itself, not the
        // dispatcher.
        answered.push(<crate::specs::registry::did::rotate::v0_1::Payload as trust_tasks_rs::Payload>::type_uri().to_string());
        answered.push(<crate::specs::registry::did::rotate::v0_2::Payload as trust_tasks_rs::Payload>::type_uri().to_string());
        answered.sort();
        answered.dedup();

        let locked = locked_versions();
        let mut pinned: Vec<String> = include_str!("../../trust-tasks.lock")
            .lines()
            .filter_map(|l| l.strip_prefix("type_uri = \""))
            .map(|l| l.trim_end_matches('"').to_string())
            .collect();
        pinned.sort();
        let mut generated: Vec<String> = locked.iter().map(|(uri, _, _)| uri.clone()).collect();
        generated.sort();
        assert_eq!(
            generated, pinned,
            "the table must name every locked version"
        );
        assert_eq!(
            answered, pinned,
            "the registry answers exactly the locked versions"
        );

        for (uri, schema, accepts) in &locked {
            let schema = schema.unwrap_or_else(|| panic!("{uri}: generated type has no schema"));
            let schema: Value = serde_json::from_str(schema).expect("schema is JSON");
            assert!(schema.is_object(), "{uri}: schema is not an object");
            assert!(
                !accepts(json!("not a payload")),
                "{uri}: accepted a non-object"
            );
            if schema.get("additionalProperties") == Some(&Value::Bool(false)) {
                assert!(
                    !accepts(json!({ "notAMember": true })),
                    "{uri}: accepted an unknown member its schema refuses"
                );
            }
        }
    }

    // --- Audit attribution ---------------------------------------------------

    /// What the HTTP surface does with a write: no authenticated sender.
    #[tokio::test]
    async fn a_write_without_an_authenticated_sender_is_audited_as_such() {
        let (key, did) = did_key(40);
        let f = fixture(vec![did.clone()]);
        let doc = signed(unsigned(RECORD_PUT, Some(&did), put_payload(&did)), &key).await;

        f.handler.handle(doc, None).await.expect_err("refused");

        let entry = last_audit(&f);
        assert!(matches!(entry.status, AuditStatus::Unauthorized));
        assert!(entry.actor.is_empty());
        assert_eq!(entry.claimed_actor.as_deref(), Some(did.as_str()));
        assert_eq!(entry.authenticated_sender, None);
    }

    #[tokio::test]
    async fn a_refusal_records_the_transport_authenticated_sender() {
        let (_, did) = did_key(41);
        let f = fixture(vec![did.clone()]);
        let doc: TrustTask<Value> =
            serde_json::from_value(unsigned(RECORD_PUT, Some(&did), put_payload(&did)))
                .expect("document parses");

        f.handler
            .handle(doc, Some(&did))
            .await
            .expect_err("refused");

        let entry = last_audit(&f);
        assert!(entry.actor.is_empty(), "the proof was never checked");
        assert_eq!(entry.authenticated_sender.as_deref(), Some(did.as_str()));
    }
}
