//! Shared fixtures for the per-transport query tests: one seeded registry and
//! one query document, so the DIDComm and TSP bindings are held to the same
//! answer.

use std::sync::Arc;

use serde_json::{Value, json};
use tokio::sync::RwLock;
use trust_tasks_rs::TrustTask;

use crate::capabilities::DispatcherHandle;
use crate::domain::{Action, AuthorityId, EntityId, RecordType, Resource, TrustRecordBuilder};
use crate::storage::adapters::local_storage::LocalStorage;
use crate::trust_tasks::{TaskHandler, build_dispatcher};

pub(crate) const REGISTRY_DID: &str = "did:example:registry";
pub(crate) const CLIENT_DID: &str = "did:example:client";

/// The registry's shared Trust Task handler over a store holding one record
/// that is both recognized and authorized.
pub(crate) fn seeded_handler() -> TaskHandler {
    let record = TrustRecordBuilder::new()
        .entity_id(EntityId::new("did:example:entity"))
        .authority_id(AuthorityId::new("did:example:authority"))
        .action(Action::new("issue"))
        .resource(Resource::new("vc"))
        .recognized(true)
        .authorized(true)
        .record_type(RecordType::Authorization)
        .build()
        .expect("valid record");
    let repo = Arc::new(LocalStorage::with_records(vec![record]).expect("seeded store"));
    let dispatcher: DispatcherHandle = Arc::new(RwLock::new(Arc::new(build_dispatcher(repo))));
    TaskHandler::new(
        dispatcher,
        REGISTRY_DID,
        Vec::new(),
        trust_tasks_rs::erase_verifier(trust_tasks_proof::affinidi::Verifier::for_did_key()),
    )
}

/// An unsigned query of `type_uri` for the seeded record, from the client to
/// the registry.
pub(crate) fn query_doc(type_uri: &str) -> TrustTask<Value> {
    let mut doc = TrustTask::new(
        format!("urn:uuid:{}", uuid::Uuid::new_v4()),
        type_uri.parse().expect("valid type uri"),
        json!({
            "entity_id": "did:example:entity",
            "authority_id": "did:example:authority",
            "action": "issue",
            "resource": "vc"
        }),
    );
    doc.issuer = Some(CLIENT_DID.to_string());
    doc.recipient = Some(REGISTRY_DID.to_string());
    doc.issued_at = Some(chrono::Utc::now());
    doc
}
