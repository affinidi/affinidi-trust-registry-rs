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
//! Type URIs are answered. Further per-task policy (for example the spec's
//! extension error codes a task may answer with) belongs here too.

// The 0.1 `registry/*` versions are superseded (the generated types are
// `#[deprecated]`) and still answered on purpose.
#![allow(deprecated)]

use trust_tasks_rs::{Payload, TypeUri};

use crate::audit::model::AuditOperation;
use crate::specs::git_trust::grant::v0_1 as grant_spec;
use crate::specs::git_trust::revoke::v0_1 as revoke_spec;
use crate::specs::governance::capability::disable::v0_1 as disable_spec;
use crate::specs::governance::capability::enable::v0_1 as enable_spec;
use crate::specs::governance::capability::list::v0_1 as list_spec;

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
    /// `governance/capability/disable`: the authority the capability named in
    /// the payload was enabled with.
    NamedCapability,
    /// A task of this built-in capability: the authority it was enabled with.
    Capability(&'static str),
    /// A task of a capability that is not built in: the authority of the
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
}

impl TaskDescriptor {
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
};

/// The descriptor of one of the registry's own tasks.
pub fn descriptor(slug: &str) -> Option<&'static TaskDescriptor> {
    DESCRIPTORS.iter().find(|d| d.slug == slug)
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

    #[test]
    fn unknown_slugs_have_no_descriptor() {
        assert!(descriptor("registry/record/bulk").is_none());
        assert!(is_reserved("registry/record/bulk"));
        assert!(!is_reserved("badge/issue"));
    }
}
