//! `git-trust` — the first capability module.
//!
//! Grants and revokes a member DID's commit-signing authority as TRQP
//! authorization tuples `{entity: subject, authority: the community's
//! authority DID, action: "git.commit.sign", resource}` in this registry,
//! where CI verifiers (`did-git-sign verify-trust`) query them anonymously.
//!
//! Per-community configuration (validated at
//! `governance/capability/enable`): `{"authority": "did:..."}` — the
//! authority DID every tuple is recorded under. There is no default
//! authority: absent or malformed config rejects, it never guesses.

// `TaskOutcome`'s error is a whole `trust-task-error` document, which is large
// by design; boxing it would only move the allocation onto every caller. The
// router allows this lint for the same reason.
#![allow(clippy::result_large_err)]

use std::sync::Arc;

use crate::specs::git_trust::grant::v0_1 as grant_spec;
use crate::specs::git_trust::revoke::v0_1 as revoke_spec;
use serde_json::Value;
use trust_tasks_rs::{RejectReason, TrustTask};

use crate::domain::{Action, AuthorityId, Context, EntityId, RecordType, Resource, TrustRecord};
use crate::storage::repository::{RepositoryError, TrustRecordAdminRepository, TrustRecordQuery};
use crate::trust_tasks::descriptor::{TaskError, spec_error};
use crate::trust_tasks::payloads::query_as_written;
use crate::trust_tasks::router::{map_repo_err, new_id, reject_build_err, respond};
use crate::trust_tasks::{RegistryDispatcher, TaskFuture, TaskOutcome};

use super::{CapabilityDefinition, CapabilityState};

/// The TRQP action every git-trust tuple is recorded under.
pub const ACTION: &str = "git.commit.sign";

/// Build the git-trust [`CapabilityDefinition`] over `repository`.
///
/// Errs only if the static manifest literal stops matching the generated
/// `CapabilityManifest` shape (i.e. a spec upgrade) — surfaced at startup,
/// never panicking.
pub fn definition(
    repository: Arc<dyn TrustRecordAdminRepository>,
) -> Result<CapabilityDefinition, String> {
    let manifest = serde_json::from_value(serde_json::json!({
        "capability": "git-trust",
        "version": "0.1",
        "title": "Git Commit Trust",
        "description": "Grant and revoke members' commit-signing authority; CI verifies each PR commit's signer DID against this community's registry.",
        "specs": ["git-trust/*"],
        "vocabulary": {
            "actions": [ACTION],
            "resourcePattern": "<org>[/<repo>]"
        },
        "roles": { "grant": ["operator"], "view": ["member"] },
        "externalAdapters": [
            { "kind": "github-action", "ref": "OpenVTC/openvtc/.github/actions/verify-trust" }
        ]
    }))
    .map_err(|e| format!("git-trust manifest does not match the spec shape: {e}"))?;

    Ok(CapabilityDefinition {
        manifest,
        register: Arc::new(
            move |dispatcher: RegistryDispatcher, state: &CapabilityState| {
                let authority = authority_of(state);
                let grant_repo = repository.clone();
                let grant_authority = authority.clone();
                let revoke_repo = repository.clone();
                dispatcher
                    .on::<grant_spec::Payload, _>(move |doc| -> TaskFuture {
                        let repo = grant_repo.clone();
                        let authority = grant_authority.clone();
                        Box::pin(handle_grant(repo, authority, doc))
                    })
                    .on::<revoke_spec::Payload, _>(move |doc| -> TaskFuture {
                        let repo = revoke_repo.clone();
                        let authority = authority.clone();
                        Box::pin(handle_revoke(repo, authority, doc))
                    })
            },
        ),
        register_reads: None,
        validate_config: Some(Arc::new(|config: &Value| match config.get("authority") {
            Some(Value::String(did)) if did.starts_with("did:") => Ok(()),
            Some(_) => Err("`authority` must be a DID string".to_string()),
            None => Err(
                "git-trust config requires `authority` (the community's authority DID)".to_string(),
            ),
        })),
        requires_authority: true,
    })
}

/// The community authority DID from the enablement config. Enable-time
/// validation guarantees presence; an inconsistent state yields `None` and
/// the handlers reject rather than guess.
/// Kept as written: a state file of an earlier release may name a did:scid
/// with its `?src=` locator, and the tuples it wrote are stored under that
/// spelling ([`read_tuple`] falls back to it).
fn authority_of(state: &CapabilityState) -> Option<String> {
    state
        .config
        .as_ref()
        .and_then(|c| c.get("authority"))
        .and_then(Value::as_str)
        .filter(|did| did.starts_with("did:"))
        .map(str::to_string)
}

#[allow(clippy::result_large_err)]
fn require_authority<P>(
    authority: &Option<String>,
    doc: &TrustTask<P>,
) -> Result<String, trust_tasks_rs::ErrorResponse> {
    authority.clone().ok_or_else(|| {
        doc.reject_with(
            new_id(),
            RejectReason::InternalError {
                reason: "git-trust is enabled without an authority DID in its config".to_string(),
            },
        )
    })
}

/// The git-trust tuple for `subject` and `resource`, if there is one: read by
/// its normalised key, and — when that misses and the authority or subject is
/// a did:scid written with its `?src=` locator (as in a state file of an
/// earlier release) — by the key as written, where that release stored it.
async fn read_tuple(
    repository: &dyn TrustRecordAdminRepository,
    subject: &str,
    authority: &str,
    resource: &str,
) -> Result<Option<TrustRecord>, RepositoryError> {
    match repository.read(key_of(subject, authority, resource)).await {
        Ok(record) => return Ok(Some(record)),
        Err(RepositoryError::RecordNotFound(_)) => {}
        Err(e) => return Err(e),
    }
    let Some(as_written) = query_as_written(subject, authority, ACTION, resource) else {
        return Ok(None);
    };
    match repository.read(as_written).await {
        Ok(record) => Ok(Some(record)),
        Err(RepositoryError::RecordNotFound(_)) => Ok(None),
        Err(e) => Err(e),
    }
}

/// `existing` with `authorized` set, under its own key (which, for a tuple
/// an earlier release stored with a did:scid locator, is the located one).
fn with_authorized(existing: &TrustRecord, authorized: bool) -> TrustRecord {
    TrustRecord::new(
        existing.entity_id().clone(),
        existing.authority_id().clone(),
        Action::new(ACTION),
        existing.resource().clone(),
        existing.is_recognized(),
        authorized,
        existing.context().clone(),
        RecordType::Authorization,
    )
}

/// `git-trust/grant`: record the tuple as authorized.
///
/// A revoked grant is kept (revoke marks it unauthorized), so granting again
/// over it updates it back to authorized. Only an active grant answers
/// `git-trust/grant:alreadyGranted`.
async fn handle_grant(
    repository: Arc<dyn TrustRecordAdminRepository>,
    authority: Option<String>,
    doc: TrustTask<grant_spec::Payload>,
) -> TaskOutcome {
    let authority = require_authority(&authority, &doc)?;
    let subject = doc.payload.subject.to_string();
    let resource = doc.payload.resource.to_string();
    let already_granted = || {
        spec_error(
            &doc,
            TaskError::AlreadyGranted,
            "an active grant exists for this subject and resource",
        )
    };

    let existing = read_tuple(repository.as_ref(), &subject, &authority, &resource)
        .await
        .map_err(|e| doc.reject_with(new_id(), map_repo_err(e)))?;
    let written = match &existing {
        Some(record) if record.is_authorized() => return Err(already_granted()),
        // A revoked grant: authorize it again, keeping what else it carries.
        Some(record) => repository.update(with_authorized(record, true)).await,
        None => {
            repository
                .create(TrustRecord::new(
                    EntityId::new(&subject),
                    AuthorityId::new(&authority),
                    Action::new(ACTION),
                    Resource::new(&resource),
                    true,
                    true,
                    Context::empty(),
                    RecordType::Authorization,
                ))
                .await
        }
    };
    match written {
        Ok(()) => {
            let response: Result<grant_spec::Response, _> = grant_spec::Response::builder()
                .subject(subject)
                .resource(resource)
                .granted(true)
                .try_into();
            respond(&doc, response.map_err(|e| reject_build_err(&doc, e))?)
        }
        // Created by a concurrent grant since the read: it is active now.
        Err(RepositoryError::RecordAlreadyExists(_)) => Err(already_granted()),
        Err(e) => Err(doc.reject_with(new_id(), map_repo_err(e))),
    }
}

/// `git-trust/revoke`: mark an active grant unauthorized, keeping the record
/// for audit. With no active grant — none at all, or one already revoked —
/// it answers `git-trust/revoke:notGranted`.
async fn handle_revoke(
    repository: Arc<dyn TrustRecordAdminRepository>,
    authority: Option<String>,
    doc: TrustTask<revoke_spec::Payload>,
) -> TaskOutcome {
    let authority = require_authority(&authority, &doc)?;
    let subject = doc.payload.subject.to_string();
    let resource = doc.payload.resource.to_string();

    let not_granted = || {
        spec_error(
            &doc,
            TaskError::NotGranted,
            "no active grant exists for this subject and resource",
        )
    };
    let existing = match read_tuple(repository.as_ref(), &subject, &authority, &resource).await {
        Ok(Some(record)) if record.is_authorized() => record,
        Ok(_) => return Err(not_granted()),
        Err(e) => return Err(doc.reject_with(new_id(), map_repo_err(e))),
    };

    match repository.update(with_authorized(&existing, false)).await {
        Ok(()) => {
            let response: Result<revoke_spec::Response, _> = revoke_spec::Response::builder()
                .subject(subject)
                .resource(resource)
                .revoked(true)
                .try_into();
            respond(&doc, response.map_err(|e| reject_build_err(&doc, e))?)
        }
        // Deleted since the read (by `registry/record/delete`).
        Err(RepositoryError::RecordNotFound(_)) => Err(not_granted()),
        Err(e) => Err(doc.reject_with(new_id(), map_repo_err(e))),
    }
}

/// The key of the git-trust tuple for `subject` and `resource`.
fn key_of(subject: &str, authority: &str, resource: &str) -> TrustRecordQuery {
    TrustRecordQuery::new(
        EntityId::new(subject),
        AuthorityId::new(authority),
        Action::new(ACTION),
        Resource::new(resource),
    )
}

#[cfg(test)]
mod tests {
    // `deprecated`: exercises the superseded 0.1 query types on purpose.
    #![allow(clippy::unwrap_used, clippy::expect_used, deprecated)]

    use super::*;
    use crate::capabilities::{CapabilitySet, MemoryCapabilityStore};
    use crate::specs::registry::authorization::v0_1 as authz;
    use crate::storage::adapters::local_storage::LocalStorage;
    use trust_tasks_rs::{Dispatcher, Payload as _};

    const AUTHORITY: &str = "did:example:community-authority";
    const SIGNER: &str = "did:example:signer";

    fn set_over(repository: Arc<dyn TrustRecordAdminRepository>) -> Arc<CapabilitySet> {
        let query_repo = repository.clone();
        CapabilitySet::new(
            vec![definition(repository).unwrap()],
            Box::new(MemoryCapabilityStore::default()),
            Box::new(Dispatcher::new),
            // Query surface serves real TRQP reads, like the HTTP binding.
            Box::new(move || crate::trust_tasks::build_query_dispatcher(query_repo.clone())),
        )
        .unwrap()
    }

    fn task(uri: trust_tasks_rs::TypeUri, payload: Value) -> TrustTask<Value> {
        TrustTask::new(new_id(), uri, payload)
    }

    async fn dispatch(
        set: &CapabilitySet,
        admin: bool,
        doc: TrustTask<Value>,
    ) -> Result<TrustTask<Value>, trust_tasks_rs::ErrorResponse> {
        let handle = if admin {
            set.dispatcher()
        } else {
            set.query_dispatcher()
        };
        let d = handle.read().await.clone();
        crate::trust_tasks::handle_document(&d, doc).await
    }

    async fn authorized(set: &CapabilitySet, resource: &str) -> bool {
        let out = dispatch(
            set,
            false,
            task(
                authz::Payload::type_uri(),
                serde_json::json!({
                    "entity_id": SIGNER, "authority_id": AUTHORITY,
                    "action": ACTION, "resource": resource
                }),
            ),
        )
        .await
        .expect("authorization query answers");
        out.payload["authorized"] == serde_json::json!(true)
    }

    #[tokio::test]
    async fn grant_then_query_then_revoke_full_loop() {
        let repository: Arc<dyn TrustRecordAdminRepository> = Arc::new(LocalStorage::default());
        let set = set_over(repository);

        // Enable with the community authority in config.
        set.enable(
            "git-trust",
            "0.1",
            Some(serde_json::json!({ "authority": AUTHORITY })),
            None,
        )
        .await
        .unwrap();

        // Grant over the wire → TRQP answers true.
        let out = dispatch(
            &set,
            true,
            task(
                grant_spec::Payload::type_uri(),
                serde_json::json!({ "subject": SIGNER, "resource": "openvtc/openvtc" }),
            ),
        )
        .await
        .expect("grant succeeds");
        assert_eq!(out.payload["granted"], serde_json::json!(true));
        assert!(authorized(&set, "openvtc/openvtc").await);

        // Duplicate grant rejects.
        assert_eq!(
            refusal(&set, grant_spec::Payload::type_uri()).await,
            ("git-trust/grant:alreadyGranted".to_string(), false)
        );

        // Revoke → TRQP answers false (record retained, not deleted).
        let out = dispatch(
            &set,
            true,
            task(
                revoke_spec::Payload::type_uri(),
                serde_json::json!({ "subject": SIGNER, "resource": "openvtc/openvtc" }),
            ),
        )
        .await
        .expect("revoke succeeds");
        assert_eq!(out.payload["revoked"], serde_json::json!(true));
        assert!(!authorized(&set, "openvtc/openvtc").await);

        // A second revoke finds no active grant.
        assert_eq!(
            refusal(&set, revoke_spec::Payload::type_uri()).await,
            ("git-trust/revoke:notGranted".to_string(), false)
        );

        // Granting again after a revoke authorizes the retained record.
        let out = dispatch(
            &set,
            true,
            task(
                grant_spec::Payload::type_uri(),
                serde_json::json!({ "subject": SIGNER, "resource": "openvtc/openvtc" }),
            ),
        )
        .await
        .expect("a revoked grant can be granted again");
        assert_eq!(out.payload["granted"], serde_json::json!(true));
        assert!(authorized(&set, "openvtc/openvtc").await);
    }

    /// The code and retry flag a grant or revoke of the test tuple is refused
    /// with.
    async fn refusal(set: &CapabilitySet, uri: trust_tasks_rs::TypeUri) -> (String, bool) {
        let err = dispatch(
            set,
            true,
            task(
                uri,
                serde_json::json!({ "subject": SIGNER, "resource": "openvtc/openvtc" }),
            ),
        )
        .await
        .expect_err("refused");
        (err.payload.code.to_string(), err.payload.retryable)
    }

    #[tokio::test]
    async fn revoke_without_grant_rejects() {
        let repository: Arc<dyn TrustRecordAdminRepository> = Arc::new(LocalStorage::default());
        let set = set_over(repository);
        set.enable(
            "git-trust",
            "0.1",
            Some(serde_json::json!({ "authority": AUTHORITY })),
            None,
        )
        .await
        .unwrap();

        assert_eq!(
            refusal(&set, revoke_spec::Payload::type_uri()).await,
            ("git-trust/revoke:notGranted".to_string(), false)
        );
    }

    #[tokio::test]
    async fn enable_requires_an_authority_did() {
        let repository: Arc<dyn TrustRecordAdminRepository> = Arc::new(LocalStorage::default());
        let set = set_over(repository);

        for bad in [
            serde_json::json!({}),
            serde_json::json!({ "authority": "not-a-did" }),
            serde_json::json!({ "authority": 42 }),
        ] {
            assert!(
                set.enable("git-trust", "0.1", Some(bad.clone()), None)
                    .await
                    .is_err(),
                "config must be rejected: {bad}"
            );
        }
        // R5.1: absent config is the most restrictive interpretation — with a
        // required authority there is no safe default, so it rejects too.
        assert!(
            matches!(
                set.enable("git-trust", "0.1", None, None).await,
                Err(crate::capabilities::CapabilityError::ConfigInvalid(_))
            ),
            "absent config must reject, never guess an authority"
        );
    }

    #[tokio::test]
    async fn tasks_do_not_route_while_disabled() {
        let repository: Arc<dyn TrustRecordAdminRepository> = Arc::new(LocalStorage::default());
        let set = set_over(repository);
        assert!(
            dispatch(
                &set,
                true,
                task(
                    grant_spec::Payload::type_uri(),
                    serde_json::json!({ "subject": SIGNER, "resource": "openvtc/openvtc" }),
                ),
            )
            .await
            .is_err(),
            "off by default"
        );
    }

    /// A grant an earlier release wrote under a did:scid authority with its
    /// `?src=` locator, from a single-slot state file naming it that way, is
    /// revoked (not answered `notGranted`) and can be granted again.
    #[tokio::test]
    async fn a_legacy_located_grant_is_revoked_and_granted_again() {
        const LOCATED: &str = "did:scid:vh:1:community?src=example.com";
        let repository: Arc<dyn TrustRecordAdminRepository> = Arc::new(LocalStorage::default());
        repository
            .create(TrustRecord::new(
                EntityId::new(SIGNER),
                AuthorityId::as_written(LOCATED),
                Action::new(ACTION),
                Resource::new("openvtc/openvtc"),
                true,
                true,
                Context::empty(),
                RecordType::Authorization,
            ))
            .await
            .unwrap();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("capabilities.json");
        std::fs::write(
            &path,
            serde_json::json!({
                "git-trust": {
                    "version": "0.1", "enabled": true,
                    "config": { "authority": LOCATED },
                    "enabledAt": "2026-01-01T00:00:00Z",
                }
            })
            .to_string(),
        )
        .unwrap();
        let query_repo = repository.clone();
        let set = CapabilitySet::new(
            vec![definition(repository.clone()).unwrap()],
            Box::new(crate::capabilities::FileCapabilityStore::new(&path)),
            Box::new(Dispatcher::new),
            Box::new(move || crate::trust_tasks::build_query_dispatcher(query_repo.clone())),
        )
        .unwrap();
        let stored = || async {
            repository
                .read(TrustRecordQuery::new(
                    EntityId::new(SIGNER),
                    AuthorityId::as_written(LOCATED),
                    Action::new(ACTION),
                    Resource::new("openvtc/openvtc"),
                ))
                .await
                .unwrap()
                .is_authorized()
        };

        assert_eq!(
            refusal(&set, grant_spec::Payload::type_uri()).await,
            ("git-trust/grant:alreadyGranted".to_string(), false)
        );
        let out = dispatch(
            &set,
            true,
            task(
                revoke_spec::Payload::type_uri(),
                serde_json::json!({ "subject": SIGNER, "resource": "openvtc/openvtc" }),
            ),
        )
        .await
        .expect("the legacy grant is revoked");
        assert_eq!(out.payload["revoked"], serde_json::json!(true));
        assert!(!stored().await);
        dispatch(
            &set,
            true,
            task(
                grant_spec::Payload::type_uri(),
                serde_json::json!({ "subject": SIGNER, "resource": "openvtc/openvtc" }),
            ),
        )
        .await
        .expect("granted again");
        assert!(stored().await);
    }
}
