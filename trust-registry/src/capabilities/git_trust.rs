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

use std::sync::Arc;

use serde_json::Value;
use trust_tasks_rs::specs::git_trust::grant::v0_1 as grant_spec;
use trust_tasks_rs::specs::git_trust::revoke::v0_1 as revoke_spec;
use trust_tasks_rs::{RejectReason, TrustTask};
use uuid::Uuid;

use crate::domain::{Action, AuthorityId, Context, EntityId, RecordType, Resource, TrustRecord};
use crate::storage::repository::{RepositoryError, TrustRecordAdminRepository, TrustRecordQuery};
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
        validate_config: Some(Arc::new(|config: &Value| match config.get("authority") {
            Some(Value::String(did)) if did.starts_with("did:") => Ok(()),
            Some(_) => Err("`authority` must be a DID string".to_string()),
            None => Err(
                "git-trust config requires `authority` (the community's authority DID)".to_string(),
            ),
        })),
    })
}

/// The community authority DID from the enablement config. Enable-time
/// validation guarantees presence; an inconsistent state yields `None` and
/// the handlers reject rather than guess.
fn authority_of(state: &CapabilityState) -> Option<String> {
    state
        .config
        .as_ref()
        .and_then(|c| c.get("authority"))
        .and_then(Value::as_str)
        .filter(|did| did.starts_with("did:"))
        .map(str::to_string)
}

fn new_id() -> String {
    Uuid::new_v4().to_string()
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

async fn handle_grant(
    repository: Arc<dyn TrustRecordAdminRepository>,
    authority: Option<String>,
    doc: TrustTask<grant_spec::Payload>,
) -> TaskOutcome {
    let authority = require_authority(&authority, &doc)?;
    let subject = doc.payload.subject.to_string();
    let resource = doc.payload.resource.to_string();

    let record = TrustRecord::new(
        EntityId::new(&subject),
        AuthorityId::new(&authority),
        Action::new(ACTION),
        Resource::new(&resource),
        true,
        true,
        Context::empty(),
        RecordType::Authorization,
    );
    match repository.create(record).await {
        Ok(()) => respond(
            &doc,
            serde_json::json!({ "subject": subject, "resource": resource, "granted": true }),
        ),
        Err(RepositoryError::RecordAlreadyExists(_)) => Err(doc.reject_with(
            new_id(),
            RejectReason::TaskFailed {
                reason: "already_granted: an active grant exists for this subject and resource"
                    .to_string(),
                details: None,
            },
        )),
        Err(e) => Err(doc.reject_with(
            new_id(),
            RejectReason::InternalError {
                reason: e.to_string(),
            },
        )),
    }
}

async fn handle_revoke(
    repository: Arc<dyn TrustRecordAdminRepository>,
    authority: Option<String>,
    doc: TrustTask<revoke_spec::Payload>,
) -> TaskOutcome {
    let authority = require_authority(&authority, &doc)?;
    let subject = doc.payload.subject.to_string();
    let resource = doc.payload.resource.to_string();

    let query = TrustRecordQuery::new(
        EntityId::new(&subject),
        AuthorityId::new(&authority),
        Action::new(ACTION),
        Resource::new(&resource),
    );
    let existing = match repository.read(query).await {
        Ok(record) => record,
        Err(RepositoryError::RecordNotFound(_)) => {
            return Err(doc.reject_with(
                new_id(),
                RejectReason::TaskFailed {
                    reason: "not_granted: no active grant exists for this subject and resource"
                        .to_string(),
                    details: None,
                },
            ));
        }
        Err(e) => {
            return Err(doc.reject_with(
                new_id(),
                RejectReason::InternalError {
                    reason: e.to_string(),
                },
            ));
        }
    };

    // Revoke = mark unauthorized, retaining the record for audit.
    let revoked = TrustRecord::new(
        EntityId::new(&subject),
        AuthorityId::new(&authority),
        Action::new(ACTION),
        Resource::new(&resource),
        existing.is_recognized(),
        false,
        existing.context().clone(),
        RecordType::Authorization,
    );
    match repository.update(revoked).await {
        Ok(()) => respond(
            &doc,
            serde_json::json!({ "subject": subject, "resource": resource, "revoked": true }),
        ),
        Err(e) => Err(doc.reject_with(
            new_id(),
            RejectReason::InternalError {
                reason: e.to_string(),
            },
        )),
    }
}

#[allow(clippy::result_large_err)]
fn respond<P>(doc: &TrustTask<P>, payload: Value) -> TaskOutcome {
    Ok(doc.respond_with(new_id(), payload))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;
    use crate::capabilities::{CapabilitySet, MemoryCapabilityStore};
    use crate::storage::adapters::local_storage::LocalStorage;
    use trust_tasks_rs::specs::registry::authorization::v0_1 as authz;
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
            "already_granted"
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

        assert!(
            dispatch(
                &set,
                true,
                task(
                    revoke_spec::Payload::type_uri(),
                    serde_json::json!({ "subject": SIGNER, "resource": "openvtc/openvtc" }),
                ),
            )
            .await
            .is_err(),
            "not_granted"
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
}
