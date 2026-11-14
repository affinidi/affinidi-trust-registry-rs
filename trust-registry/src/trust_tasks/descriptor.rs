//! What the registry knows about each Trust Task it serves, in one table.
//!
//! Every task the registry itself answers — the `registry/*` family, the
//! `governance/capability/*` surface and the built-in `git-trust` capability —
//! has one [`TaskDescriptor`] in [`DESCRIPTORS`]. The
//! [`TaskHandler`](crate::trust_tasks::TaskHandler) reads everything it decides
//! per task from it: whether the task is a write ([`TaskDescriptor::is_write`])
//! or needs a proof ([`TaskDescriptor::requires_proof`]), which replay record
//! it uses ([`TaskDescriptor::replay`]), how it is executed, the operation its
//! audit entry records, which spelling its payload uses at which version, and
//! where in the payload its record key and authority are.
//!
//! A task of a capability that is not built in is described by
//! [`CAPABILITY_WRITE`] when the [`CapabilitySet`](crate::capabilities::CapabilitySet)
//! classifies it as a write. A slug with neither is not a write the registry
//! knows how to bind, and is never treated as one by default: see
//! [`TaskHandler`](crate::trust_tasks::TaskHandler) for how it is refused.
//!
//! The tests below hold this table and the dispatchers to each other: every
//! Type URI the dispatchers answer has a descriptor, and every descriptor's
//! Type URIs are answered. Each descriptor also lists the extension error
//! codes its specification declares ([`TaskDescriptor::errors`]); the task's
//! handler answers with them through [`spec_error`], and a test holds the
//! list to every served version's declaration.

// The 0.1 `registry/*` versions are superseded (the generated types are
// `#[deprecated]`) and still answered on purpose.
#![allow(deprecated)]

use trust_tasks_rs::{DeclaredErrorCode, ErrorPayload, ErrorResponse, Payload, TrustTask, TypeUri};

use crate::audit::model::AuditOperation;
use crate::specs::git_trust::grant::v0_1 as grant_spec;
use crate::specs::git_trust::revoke::v0_1 as revoke_spec;
use crate::specs::governance::capability::disable::v0_1 as disable_spec;
use crate::specs::governance::capability::enable::v0_1 as enable_spec;
use crate::specs::governance::capability::list::v0_1 as list_spec;
use crate::specs::registry::record::delete::v0_2 as delete_spec;
use crate::specs::registry::record::put::v0_3 as put_spec;
use crate::specs::registry::record::query::v0_3 as query_spec;

use super::payloads::{
    AuthorizationRequest, DidRotateRequest, RecognitionRequest, RecordDeleteRequest,
    RecordPutRequest, RecordQueryRequest, camel,
};

/// How the registry treats a task.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TaskKind {
    /// Public: no proof, no admin, no authority, no replay record, no audit.
    Read,
    /// A query answered only under the rules of a write (a proof from an
    /// admin, an authority, its own replay record, an audit entry), because
    /// its answer carries whole records: `registry/record/query`.
    ProvenQuery,
    /// Changes the registry.
    Write,
}

/// Which record of accepted document identifiers a task is executed through.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Replay {
    /// None: a read is not executed at most once.
    None,
    /// The record shared by every binding carrying writes.
    Writes,
    /// The separate record for queries, so queries cannot use up the capacity
    /// writes need.
    Queries,
}

/// How a task is executed once it has been authorised.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Execution {
    /// Through the live dispatcher (or the capability snapshot's).
    Dispatcher,
    /// By the handler itself: `registry/did/rotate` acts on the registry's own
    /// DID through the VTA, and no dispatcher registers it.
    DidRotate,
}

/// Which spelling a task's payload uses at a given version.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Casing {
    /// One spelling at every version served.
    Single,
    /// snake_case before this `(major, minor)`, lowerCamelCase from it.
    CamelFrom(u32, u32),
}

/// A payload member, in the spelling of each casing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Member {
    /// JSON pointer in the snake_case versions.
    pub snake: &'static str,
    /// JSON pointer in the lowerCamelCase versions.
    pub camel: &'static str,
}

impl Member {
    /// A member spelled the same in every version.
    const fn same(pointer: &'static str) -> Self {
        Self {
            snake: pointer,
            camel: pointer,
        }
    }

    const fn spelled(snake: &'static str, camel: &'static str) -> Self {
        Self { snake, camel }
    }

    /// The pointer for a document whose version is lowerCamelCase or not.
    pub fn pointer(&self, camel_case: bool) -> &'static str {
        if camel_case { self.camel } else { self.snake }
    }
}

/// Where one part of the audited record key comes from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Field {
    /// The task has no such part.
    Absent,
    /// The same value for every document of the task.
    Fixed(&'static str),
    /// A string member of the payload.
    At(Member),
}

/// The record key (or capability) a task acts on, for its audit entry.
/// Identifiers only: never record contents, context or proofs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ResourceRule {
    pub entity: Field,
    pub action: Field,
    pub resource: Field,
}

impl ResourceRule {
    const NONE: Self = Self {
        entity: Field::Absent,
        action: Field::Absent,
        resource: Field::Absent,
    };
}

/// Where the authority a write acts under comes from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthorityRule {
    /// A read acts under no authority. On the write path this is refused, so a
    /// write never runs under no authority.
    NotApplicable,
    /// A string member of the payload, required; `what` names the task in the
    /// refusal when it is missing.
    Member { at: Member, what: &'static str },
    /// `governance/capability/enable`: the `authority` of the config being
    /// enabled, or the registry's own DID for a capability that writes no
    /// records.
    EnableConfig,
    /// `governance/capability/disable`: the authority of the enablement of
    /// the capability named in the payload that the issuer may act for.
    NamedCapability,
    /// A task of this built-in capability: the authority of the enablement
    /// the issuer may act for (enablement is per authority).
    Capability(&'static str),
    /// A task of a capability that is not built in: as `Capability`, for the
    /// capability the [`CapabilitySet`](crate::capabilities::CapabilitySet)
    /// says owns it.
    OwningCapability,
    /// The registry's own DID: the task acts on the registry itself.
    Registry,
}

/// Everything the registry decides per task.
#[derive(Debug, Clone, Copy)]
pub struct TaskDescriptor {
    /// The Trust Task slug, e.g. `registry/record/put`. Empty for
    /// [`CAPABILITY_WRITE`], which stands for any capability's write.
    pub slug: &'static str,
    /// Every Type URI of the task the registry answers, one per version.
    pub type_uris: &'static [&'static str],
    pub kind: TaskKind,
    pub execution: Execution,
    /// The operation the task's audit entry records.
    pub audit: AuditOperation,
    pub casing: Casing,
    pub resource: ResourceRule,
    pub authority: AuthorityRule,
    /// The payload member carrying the requester's stated reason (the
    /// `reason` of `governance/capability/disable` and `git-trust/revoke`),
    /// which the audit entry of a success records. [`Field::Absent`] for a
    /// task without one.
    pub audit_reason: Field,
    /// The extension error codes the task's specification declares, by the
    /// condition each one names. The codes are the same at every version the
    /// registry serves.
    pub errors: &'static [(TaskError, DeclaredErrorCode)],
}

/// A condition a task's specification gives an extension error code of its
/// own (SPEC §8.5), rather than the generic `taskFailed`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TaskError {
    /// The record (or key) the task names does not exist.
    NotFound,
    /// A record already exists at the key a strict create names.
    AlreadyExists,
    /// The named capability, at the named version, is not one this host
    /// serves.
    UnknownCapability,
    /// The capability is already enabled for this authority.
    AlreadyEnabled,
    /// The enablement request (its config, manifest or delegate) is not
    /// acceptable.
    ConfigInvalid,
    /// The capability is not enabled for this authority.
    NotEnabled,
    /// An active grant already exists for the subject and resource.
    AlreadyGranted,
    /// No active grant exists for the subject and resource.
    NotGranted,
}

impl TaskDescriptor {
    /// The code the task's specification declares for `error`, if it declares
    /// one.
    pub fn error_code(&self, error: TaskError) -> Option<DeclaredErrorCode> {
        self.errors
            .iter()
            .find(|(condition, _)| *condition == error)
            .map(|(_, code)| *code)
    }

    /// Whether the task changes the registry.
    pub fn is_write(&self) -> bool {
        self.kind == TaskKind::Write
    }

    /// Whether a caller may only use the task with a proof bound to its
    /// sender, under the rules of a write.
    pub fn requires_proof(&self) -> bool {
        self.kind != TaskKind::Read
    }

    /// The replay record the task is executed through.
    pub fn replay(&self) -> Replay {
        match self.kind {
            TaskKind::Read => Replay::None,
            TaskKind::ProvenQuery => Replay::Queries,
            TaskKind::Write => Replay::Writes,
        }
    }

    /// Whether a document of `type_uri` spells its members in lowerCamelCase.
    pub fn camel_case(&self, type_uri: &TypeUri) -> bool {
        match self.casing {
            Casing::Single => false,
            Casing::CamelFrom(major, minor) => {
                (type_uri.major(), type_uri.minor()) >= (major, minor)
            }
        }
    }
}

const RECORD_KEY_FLAT: ResourceRule = ResourceRule {
    entity: Field::At(Member::spelled("/entity_id", "/entityId")),
    action: Field::At(Member::same("/action")),
    resource: Field::At(Member::same("/resource")),
};

const AUTHORITY_FLAT_MUTATION: AuthorityRule = AuthorityRule::Member {
    at: Member::spelled("/authority_id", "/authorityId"),
    what: "a record mutation",
};

const GIT_TRUST_KEY: ResourceRule = ResourceRule {
    entity: Field::At(Member::same("/subject")),
    action: Field::Fixed(crate::capabilities::git_trust::ACTION),
    resource: Field::At(Member::same("/resource")),
};

const CAPABILITY_NAMED: ResourceRule = ResourceRule {
    entity: Field::Absent,
    action: Field::Absent,
    resource: Field::At(Member::same("/capability")),
};

const fn read(slug: &'static str, type_uris: &'static [&'static str]) -> TaskDescriptor {
    TaskDescriptor {
        slug,
        type_uris,
        kind: TaskKind::Read,
        execution: Execution::Dispatcher,
        audit: AuditOperation::Read,
        casing: Casing::Single,
        resource: ResourceRule::NONE,
        authority: AuthorityRule::NotApplicable,
        audit_reason: Field::Absent,
        errors: &[],
    }
}

/// Every task the registry itself serves.
pub static DESCRIPTORS: &[TaskDescriptor] = &[
    // --- the public TRQP queries ---------------------------------------------
    read(
        "registry/recognition",
        &[
            RecognitionRequest::TYPE_URI,
            camel::RecognitionRequest::TYPE_URI,
        ],
    ),
    read(
        "registry/authorization",
        &[
            AuthorizationRequest::TYPE_URI,
            camel::AuthorizationRequest::TYPE_URI,
        ],
    ),
    read(
        "governance/capability/list",
        &[list_spec::Payload::TYPE_URI],
    ),
    // --- records -------------------------------------------------------------
    TaskDescriptor {
        slug: "registry/record/put",
        type_uris: &[
            RecordPutRequest::TYPE_URI,
            camel::RecordPutRequest::TYPE_URI,
        ],
        kind: TaskKind::Write,
        execution: Execution::Dispatcher,
        audit: AuditOperation::Put,
        casing: Casing::CamelFrom(0, 3),
        resource: ResourceRule {
            entity: Field::At(Member::spelled("/record/entity_id", "/record/entityId")),
            action: Field::At(Member::same("/record/action")),
            resource: Field::At(Member::same("/record/resource")),
        },
        // Read in the spelling the document's version uses. A document
        // carrying the other spelling has no authority here and is refused,
        // before its payload is ever parsed.
        authority: AuthorityRule::Member {
            at: Member::spelled("/record/authority_id", "/record/authorityId"),
            what: "a record mutation",
        },
        audit_reason: Field::Absent,
        errors: &[
            (
                TaskError::AlreadyExists,
                put_spec::error_codes::ALREADY_EXISTS,
            ),
            (TaskError::NotFound, put_spec::error_codes::NOT_FOUND),
        ],
    },
    TaskDescriptor {
        slug: "registry/record/delete",
        type_uris: &[
            RecordDeleteRequest::TYPE_URI,
            camel::RecordDeleteRequest::TYPE_URI,
        ],
        kind: TaskKind::Write,
        execution: Execution::Dispatcher,
        audit: AuditOperation::Delete,
        casing: Casing::CamelFrom(0, 2),
        resource: RECORD_KEY_FLAT,
        authority: AUTHORITY_FLAT_MUTATION,
        audit_reason: Field::Absent,
        errors: &[(TaskError::NotFound, delete_spec::error_codes::NOT_FOUND)],
    },
    TaskDescriptor {
        slug: "registry/record/query",
        type_uris: &[
            RecordQueryRequest::TYPE_URI,
            camel::RecordQueryRequest::TYPE_URI,
        ],
        kind: TaskKind::ProvenQuery,
        execution: Execution::Dispatcher,
        audit: AuditOperation::Read,
        casing: Casing::CamelFrom(0, 3),
        resource: RECORD_KEY_FLAT,
        authority: AuthorityRule::Member {
            at: Member::spelled("/authority_id", "/authorityId"),
            what: "a record query",
        },
        audit_reason: Field::Absent,
        errors: &[(TaskError::NotFound, query_spec::error_codes::NOT_FOUND)],
    },
    // --- the registry itself -------------------------------------------------
    TaskDescriptor {
        slug: "registry/did/rotate",
        type_uris: &[
            DidRotateRequest::TYPE_URI,
            camel::DidRotateRequest::TYPE_URI,
        ],
        kind: TaskKind::Write,
        execution: Execution::DidRotate,
        audit: AuditOperation::Rotate,
        casing: Casing::CamelFrom(0, 2),
        resource: ResourceRule::NONE,
        authority: AuthorityRule::Registry,
        audit_reason: Field::Absent,
        errors: &[],
    },
    // --- capabilities ----------------------------------------------------------
    TaskDescriptor {
        slug: "governance/capability/enable",
        type_uris: &[enable_spec::Payload::TYPE_URI],
        kind: TaskKind::Write,
        execution: Execution::Dispatcher,
        audit: AuditOperation::Enable,
        casing: Casing::Single,
        resource: CAPABILITY_NAMED,
        authority: AuthorityRule::EnableConfig,
        audit_reason: Field::Absent,
        errors: &[
            (
                TaskError::UnknownCapability,
                enable_spec::error_codes::UNKNOWN_CAPABILITY,
            ),
            (
                TaskError::AlreadyEnabled,
                enable_spec::error_codes::ALREADY_ENABLED,
            ),
            (
                TaskError::ConfigInvalid,
                enable_spec::error_codes::CONFIG_INVALID,
            ),
        ],
    },
    TaskDescriptor {
        slug: "governance/capability/disable",
        type_uris: &[disable_spec::Payload::TYPE_URI],
        kind: TaskKind::Write,
        execution: Execution::Dispatcher,
        audit: AuditOperation::Disable,
        casing: Casing::Single,
        resource: CAPABILITY_NAMED,
        authority: AuthorityRule::NamedCapability,
        audit_reason: Field::At(Member::same("/reason")),
        errors: &[(
            TaskError::NotEnabled,
            disable_spec::error_codes::NOT_ENABLED,
        )],
    },
    TaskDescriptor {
        slug: "git-trust/grant",
        type_uris: &[grant_spec::Payload::TYPE_URI],
        kind: TaskKind::Write,
        execution: Execution::Dispatcher,
        audit: AuditOperation::Grant,
        casing: Casing::Single,
        resource: GIT_TRUST_KEY,
        authority: AuthorityRule::Capability(GIT_TRUST),
        audit_reason: Field::Absent,
        errors: &[(
            TaskError::AlreadyGranted,
            grant_spec::error_codes::ALREADY_GRANTED,
        )],
    },
    TaskDescriptor {
        slug: "git-trust/revoke",
        type_uris: &[revoke_spec::Payload::TYPE_URI],
        kind: TaskKind::Write,
        execution: Execution::Dispatcher,
        audit: AuditOperation::Revoke,
        casing: Casing::Single,
        resource: GIT_TRUST_KEY,
        authority: AuthorityRule::Capability(GIT_TRUST),
        audit_reason: Field::At(Member::same("/reason")),
        errors: &[(TaskError::NotGranted, revoke_spec::error_codes::NOT_GRANTED)],
    },
];

/// The capability the `git-trust/*` tasks belong to.
pub const GIT_TRUST: &str = "git-trust";

/// A write task of a capability that is not built in. Its audit entry records
/// an `UPDATE` with no record key, since the registry does not know the
/// payload's shape, and it acts under the authority of the capability that
/// owns it.
pub static CAPABILITY_WRITE: TaskDescriptor = TaskDescriptor {
    slug: "",
    type_uris: &[],
    kind: TaskKind::Write,
    execution: Execution::Dispatcher,
    audit: AuditOperation::Update,
    casing: Casing::Single,
    resource: ResourceRule::NONE,
    authority: AuthorityRule::OwningCapability,
    audit_reason: Field::Absent,
    errors: &[],
};

/// The descriptor of one of the registry's own tasks.
pub fn descriptor(slug: &str) -> Option<&'static TaskDescriptor> {
    DESCRIPTORS.iter().find(|d| d.slug == slug)
}

/// The error response for `error` on `doc`: the extension code the task's
/// specification declares for it, with the `retryable` value the
/// specification gives it, and `message`.
///
/// A task whose specification declares no code for `error` answers with
/// `taskFailed` (non-retryable) and the same message, which is what a
/// consumer that does not know an extension code reads it as (SPEC §8.5).
pub fn spec_error<P>(
    doc: &TrustTask<P>,
    error: TaskError,
    message: impl Into<String>,
) -> ErrorResponse {
    let payload = match descriptor(doc.type_uri.slug()).and_then(|d| d.error_code(error)) {
        Some(code) => ErrorPayload::from(code),
        None => ErrorPayload::new(trust_tasks_rs::StandardCode::TaskFailed),
    };
    doc.reject_with(super::router::new_id(), payload.with_message(message))
}

/// The slug families the registry itself defines. A slug in one of them with
/// no descriptor is not served: it cannot be a capability's task, and nothing
/// says how to authorise it.
pub const RESERVED_FAMILIES: &[&str] = &["registry/", "governance/"];

/// Whether `slug` is in one of the [`RESERVED_FAMILIES`].
pub fn is_reserved(slug: &str) -> bool {
    RESERVED_FAMILIES
        .iter()
        .any(|family| slug.starts_with(family))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;
    use std::collections::BTreeSet;
    use std::sync::Arc;

    use crate::capabilities::{CapabilitySet, MemoryCapabilityStore, git_trust};
    use crate::storage::adapters::local_storage::LocalStorage;
    use crate::trust_tasks::{build_dispatcher, build_query_dispatcher};

    /// Every Type URI any surface answers, with git-trust enabled, plus the
    /// ones the handler executes itself.
    async fn answered() -> BTreeSet<String> {
        let repo = Arc::new(LocalStorage::new());
        let base_repo = repo.clone();
        let query_repo = repo.clone();
        let set = CapabilitySet::new(
            vec![git_trust::definition(repo).unwrap()],
            Box::new(MemoryCapabilityStore::default()),
            Box::new(move || build_dispatcher(base_repo.clone())),
            Box::new(move || build_query_dispatcher(query_repo.clone())),
        )
        .unwrap();
        set.enable(
            GIT_TRUST,
            "0.1",
            Some(serde_json::json!({ "authority": "did:example:authority" })),
            None,
        )
        .await
        .unwrap();
        let mut uris = BTreeSet::new();
        for handle in [set.dispatcher(), set.query_dispatcher()] {
            let dispatcher = handle.read().await.clone();
            uris.extend(dispatcher.registered_uris().into_iter().map(str::to_string));
        }
        for d in DESCRIPTORS
            .iter()
            .filter(|d| d.execution == Execution::DidRotate)
        {
            uris.extend(d.type_uris.iter().map(|uri| uri.to_string()));
        }
        uris
    }

    #[tokio::test]
    async fn every_answered_task_has_a_descriptor_and_every_descriptor_is_answered() {
        let described: BTreeSet<String> = DESCRIPTORS
            .iter()
            .flat_map(|d| d.type_uris.iter().map(|uri| uri.to_string()))
            .collect();
        assert_eq!(answered().await, described);
    }

    #[test]
    fn each_descriptor_names_its_own_slug_once() {
        let mut slugs = BTreeSet::new();
        for d in DESCRIPTORS {
            assert!(slugs.insert(d.slug), "{} is described twice", d.slug);
            assert!(!d.type_uris.is_empty(), "{} answers no version", d.slug);
            for uri in d.type_uris {
                let parsed: TypeUri = uri.parse().unwrap();
                assert_eq!(parsed.slug(), d.slug, "{uri}");
            }
        }
    }

    #[test]
    fn every_task_that_needs_a_proof_has_an_authority_rule() {
        for d in DESCRIPTORS.iter().chain([&CAPABILITY_WRITE]) {
            assert_eq!(
                d.requires_proof(),
                d.authority != AuthorityRule::NotApplicable,
                "{}",
                d.slug
            );
            assert_eq!(d.requires_proof(), d.replay() != Replay::None, "{}", d.slug);
        }
    }

    #[test]
    fn the_registry_requires_a_proof_for_record_queries() {
        // The spec does not (`IS_PROOF_REQUIRED` is false for
        // `registry/record/query`): this registry does, on purpose.
        let query = descriptor("registry/record/query").unwrap();
        assert!(query.requires_proof() && !query.is_write());
        assert_eq!(query.replay(), Replay::Queries);
    }

    #[test]
    fn spellings_change_at_the_lower_camel_case_versions() {
        let put = descriptor("registry/record/put").unwrap();
        let at = |uri: &str| put.camel_case(&uri.parse().unwrap());
        assert!(!at(RecordPutRequest::TYPE_URI));
        assert!(at(camel::RecordPutRequest::TYPE_URI));
        let delete = descriptor("registry/record/delete").unwrap();
        assert!(!delete.camel_case(&RecordDeleteRequest::type_uri()));
        assert!(delete.camel_case(&camel::RecordDeleteRequest::type_uri()));
    }

    /// Every version's declared extension codes, by Type URI.
    fn declared() -> Vec<(&'static str, &'static [DeclaredErrorCode])> {
        use crate::specs::git_trust as g;
        use crate::specs::governance::capability as c;
        use crate::specs::registry as r;
        vec![
            (
                g::grant::v0_1::Payload::TYPE_URI,
                g::grant::v0_1::ERROR_CODES,
            ),
            (
                g::revoke::v0_1::Payload::TYPE_URI,
                g::revoke::v0_1::ERROR_CODES,
            ),
            (
                c::enable::v0_1::Payload::TYPE_URI,
                c::enable::v0_1::ERROR_CODES,
            ),
            (
                c::disable::v0_1::Payload::TYPE_URI,
                c::disable::v0_1::ERROR_CODES,
            ),
            (c::list::v0_1::Payload::TYPE_URI, c::list::v0_1::ERROR_CODES),
            (
                r::record::put::v0_1::Payload::TYPE_URI,
                r::record::put::v0_1::ERROR_CODES,
            ),
            (
                r::record::put::v0_3::Payload::TYPE_URI,
                r::record::put::v0_3::ERROR_CODES,
            ),
            (
                r::record::delete::v0_1::Payload::TYPE_URI,
                r::record::delete::v0_1::ERROR_CODES,
            ),
            (
                r::record::delete::v0_2::Payload::TYPE_URI,
                r::record::delete::v0_2::ERROR_CODES,
            ),
            (
                r::record::query::v0_1::Payload::TYPE_URI,
                r::record::query::v0_1::ERROR_CODES,
            ),
            (
                r::record::query::v0_3::Payload::TYPE_URI,
                r::record::query::v0_3::ERROR_CODES,
            ),
            (
                r::did::rotate::v0_1::Payload::TYPE_URI,
                r::did::rotate::v0_1::ERROR_CODES,
            ),
            (
                r::did::rotate::v0_2::Payload::TYPE_URI,
                r::did::rotate::v0_2::ERROR_CODES,
            ),
            (
                r::recognition::v0_1::Payload::TYPE_URI,
                r::recognition::v0_1::ERROR_CODES,
            ),
            (
                r::recognition::v0_2::Payload::TYPE_URI,
                r::recognition::v0_2::ERROR_CODES,
            ),
            (
                r::authorization::v0_1::Payload::TYPE_URI,
                r::authorization::v0_1::ERROR_CODES,
            ),
            (
                r::authorization::v0_2::Payload::TYPE_URI,
                r::authorization::v0_2::ERROR_CODES,
            ),
        ]
    }

    /// Each descriptor names exactly the extension codes every version it
    /// serves declares: none is missing, none is invented.
    #[test]
    fn each_descriptor_carries_the_codes_its_specification_declares() {
        let declared = declared();
        let mut seen = BTreeSet::new();
        for d in DESCRIPTORS {
            let ours: BTreeSet<&str> = d.errors.iter().map(|(_, code)| code.code).collect();
            for uri in d.type_uris {
                let (_, codes) = declared
                    .iter()
                    .find(|(declared_uri, _)| declared_uri == uri)
                    .unwrap_or_else(|| panic!("{uri} is not in the declared list"));
                let theirs: BTreeSet<&str> = codes.iter().map(|code| code.code).collect();
                assert_eq!(ours, theirs, "{uri}");
                seen.insert(*uri);
            }
            for (condition, code) in d.errors {
                assert_eq!(d.error_code(*condition), Some(*code), "{}", d.slug);
            }
        }
        assert_eq!(
            seen.len(),
            declared.len(),
            "every declared version is served"
        );
    }

    #[test]
    fn a_spec_error_carries_the_declared_code_and_retry_flag() {
        let doc = TrustTask::new(
            "urn:uuid:put".to_string(),
            RecordPutRequest::type_uri(),
            serde_json::json!({}),
        );
        let error = spec_error(&doc, TaskError::AlreadyExists, "taken");
        assert_eq!(
            serde_json::to_value(&error.payload.code).unwrap(),
            "registry/record/put:alreadyExists"
        );
        assert!(!error.payload.retryable);
        assert_eq!(error.payload.message.as_deref(), Some("taken"));

        // A condition the task's specification has no code for.
        let error = spec_error(&doc, TaskError::NotGranted, "no");
        assert_eq!(
            serde_json::to_value(&error.payload.code).unwrap(),
            "taskFailed"
        );
    }

    #[test]
    fn unknown_slugs_have_no_descriptor() {
        assert!(descriptor("registry/record/bulk").is_none());
        assert!(is_reserved("registry/record/bulk"));
        assert!(!is_reserved("badge/issue"));
    }
}
