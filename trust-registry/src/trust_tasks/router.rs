//! Transport-agnostic Trust Task router for the Trust Registry.
//!
//! [`build_dispatcher`] wires the `registry/*` payloads onto a single
//! [`trust_tasks_rs::Dispatcher`] whose handlers call the existing
//! [`TrustRecordRepository`]/[`TrustRecordAdminRepository`]. It performs **no
//! transport work** — a later change plugs this dispatcher into the DIDComm,
//! HTTP, and TSP bindings. Keeping the routing here means all three transports
//! share one implementation and cannot diverge.
//!
//! Proof enforcement (`IS_PROOF_REQUIRED` on the write payloads) is applied by
//! the transport/consume layer where a `ProofVerifier` exists, not here.
//!
//! `TaskOutcome` carries `trust_tasks_rs::ErrorResponse` in its `Err` variant,
//! which is intentionally large (a full `trust-task-error` document). Boxing it
//! would just push the allocation onto every caller, so — matching the upstream
//! crate's own `dispatch_or_reject` — we allow `result_large_err` module-wide.
#![allow(clippy::result_large_err)]

use std::sync::Arc;

use chrono::Utc;
use futures::future::BoxFuture;
use serde::Serialize;
use serde_json::Value;
use trust_tasks_rs::{Dispatcher, ErrorResponse, RejectReason, TrustTask};
use uuid::Uuid;

use crate::domain::TrustRecord;
use crate::storage::repository::{
    RepositoryError, TrustRecordAdminRepository, TrustRecordRepository,
};

use super::payloads::{
    AuthorizationRequest, AuthorizationResponse, RecognitionRequest, RecognitionResponse,
    RecordCreateRequest, RecordCreateResponse, RecordDeleteRequest, RecordDeleteResponse,
    RecordListRequest, RecordListResponse, RecordReadRequest, RecordReadResponse,
    RecordUpdateRequest, RecordUpdateResponse, query_of, reserialize,
};

/// A handler's result: a success response document or a routed error response.
pub type TaskOutcome = Result<TrustTask<Value>, ErrorResponse>;

/// The boxed future every dispatcher handler returns.
pub type TaskFuture = BoxFuture<'static, TaskOutcome>;

/// A [`Dispatcher`] specialised to the Trust Registry's async handlers.
pub type RegistryDispatcher = Dispatcher<TaskFuture>;

fn new_id() -> String {
    Uuid::new_v4().to_string()
}

/// Map a repository error to the closest framework [`RejectReason`].
fn map_repo_err(err: RepositoryError) -> RejectReason {
    match err {
        RepositoryError::ValidationError(reason) => RejectReason::MalformedRequest { reason },
        RepositoryError::RecordNotFound(reason) | RepositoryError::RecordAlreadyExists(reason) => {
            RejectReason::TaskFailed {
                reason,
                details: None,
            }
        }
        RepositoryError::ConnectionFailed(reason)
        | RepositoryError::QueryFailed(reason)
        | RepositoryError::SerializationFailed(reason) => RejectReason::InternalError { reason },
        RepositoryError::LockPoisoned => RejectReason::InternalError {
            reason: "lock poisoned".to_string(),
        },
    }
}

/// Build a success response document from a serialisable payload, or an
/// internal-error response if serialisation fails.
fn respond<P, T: Serialize>(doc: &TrustTask<P>, payload: T) -> TaskOutcome {
    match serde_json::to_value(payload) {
        Ok(value) => Ok(doc.respond_with(new_id(), value)),
        Err(e) => Err(doc.reject_with(
            new_id(),
            RejectReason::InternalError {
                reason: e.to_string(),
            },
        )),
    }
}

/// Build a [`RegistryDispatcher`] over `repository`.
///
/// Registers every `registry/*` Trust Task type. Reads only need
/// [`TrustRecordRepository`]; the admin bound is taken once so all operations
/// share one repository handle.
pub fn build_dispatcher<R>(repository: Arc<R>) -> RegistryDispatcher
where
    R: TrustRecordAdminRepository + ?Sized + 'static,
{
    Dispatcher::new()
        .on::<RecognitionRequest, _>({
            let repo = repository.clone();
            move |doc| -> TaskFuture { Box::pin(handle_recognition(repo.clone(), doc)) }
        })
        .on::<AuthorizationRequest, _>({
            let repo = repository.clone();
            move |doc| -> TaskFuture { Box::pin(handle_authorization(repo.clone(), doc)) }
        })
        .on::<RecordCreateRequest, _>({
            let repo = repository.clone();
            move |doc| -> TaskFuture { Box::pin(handle_create(repo.clone(), doc)) }
        })
        .on::<RecordUpdateRequest, _>({
            let repo = repository.clone();
            move |doc| -> TaskFuture { Box::pin(handle_update(repo.clone(), doc)) }
        })
        .on::<RecordDeleteRequest, _>({
            let repo = repository.clone();
            move |doc| -> TaskFuture { Box::pin(handle_delete(repo.clone(), doc)) }
        })
        .on::<RecordReadRequest, _>({
            let repo = repository.clone();
            move |doc| -> TaskFuture { Box::pin(handle_read(repo.clone(), doc)) }
        })
        .on::<RecordListRequest, _>({
            let repo = repository.clone();
            move |doc| -> TaskFuture { Box::pin(handle_list(repo.clone(), doc)) }
        })
}

/// Build a read-only [`RegistryDispatcher`] over `repository`.
///
/// Registers only the TRQP query operations (`registry/recognition` and
/// `registry/authorization`), which need just [`TrustRecordRepository`]. Used by
/// the HTTP binding, where — mirroring the existing REST TRQP surface — the
/// registry is read-only and record CRUD stays on the DIDComm transport.
pub fn build_query_dispatcher<R>(repository: Arc<R>) -> RegistryDispatcher
where
    R: TrustRecordRepository + ?Sized + 'static,
{
    Dispatcher::new()
        .on::<RecognitionRequest, _>({
            let repo = repository.clone();
            move |doc| -> TaskFuture { Box::pin(handle_recognition(repo.clone(), doc)) }
        })
        .on::<AuthorizationRequest, _>({
            let repo = repository.clone();
            move |doc| -> TaskFuture { Box::pin(handle_authorization(repo.clone(), doc)) }
        })
}

/// Route a raw inbound document and await its handler.
///
/// Convenience for callers holding a `TrustTask<Value>`: routing/deserialisation
/// failures become an [`ErrorResponse`] via SPEC §8.1, then the matched
/// handler's own outcome is returned.
pub async fn handle_document(
    dispatcher: &RegistryDispatcher,
    doc: TrustTask<Value>,
) -> TaskOutcome {
    match dispatcher.dispatch_or_reject(doc, new_id()) {
        Ok(future) => future.await,
        Err(error_response) => Err(error_response),
    }
}

// --- handlers ---------------------------------------------------------------

async fn handle_recognition<R>(
    repository: Arc<R>,
    doc: TrustTask<RecognitionRequest>,
) -> TaskOutcome
where
    R: TrustRecordRepository + ?Sized + 'static,
{
    let p = &doc.payload;
    let query = query_of(&p.entity_id, &p.authority_id, &p.action, &p.resource);
    let record = match repository.find_by_query(query).await {
        Ok(record) => record,
        Err(e) => return Err(doc.reject_with(new_id(), map_repo_err(e))),
    };
    let evaluated_at = Utc::now();

    let message = record.as_ref().map(|tr| {
        format!(
            "{} recognized by {}",
            tr.entity_id().as_str(),
            tr.authority_id().as_str()
        )
    });
    let response = RecognitionResponse {
        entity_id: p.entity_id.clone(),
        authority_id: p.authority_id.clone(),
        action: p.action.clone(),
        resource: p.resource.clone(),
        recognized: record.map(|tr| tr.is_recognized()).unwrap_or(false),
        time_evaluated: evaluated_at,
        time_requested: p.context.as_ref().and_then(|c| c.time),
        context: None,
        ext: None,
        message,
    };
    respond(&doc, response)
}

async fn handle_authorization<R>(
    repository: Arc<R>,
    doc: TrustTask<AuthorizationRequest>,
) -> TaskOutcome
where
    R: TrustRecordRepository + ?Sized + 'static,
{
    let p = &doc.payload;
    let query = query_of(&p.entity_id, &p.authority_id, &p.action, &p.resource);
    let record = match repository.find_by_query(query).await {
        Ok(record) => record,
        Err(e) => return Err(doc.reject_with(new_id(), map_repo_err(e))),
    };
    let evaluated_at = Utc::now();

    let message = record.as_ref().map(|tr| {
        format!(
            "{} authorized to {}+{} by {}",
            tr.entity_id().as_str(),
            tr.action().as_str(),
            tr.resource().as_str(),
            tr.authority_id().as_str()
        )
    });
    let response = AuthorizationResponse {
        entity_id: p.entity_id.clone(),
        authority_id: p.authority_id.clone(),
        action: p.action.clone(),
        resource: p.resource.clone(),
        authorized: record.map(|tr| tr.is_authorized()).unwrap_or(false),
        time_evaluated: evaluated_at,
        time_requested: p.context.as_ref().and_then(|c| c.time),
        context: None,
        ext: None,
        message,
    };
    respond(&doc, response)
}

/// Convert a spec record (carried by a create/update payload) into the domain
/// record the repository operates on, mapping a malformed record to a
/// `MalformedRequest` rejection.
fn record_from_payload<P>(
    doc: &TrustTask<P>,
    spec: &impl Serialize,
) -> Result<TrustRecord, ErrorResponse> {
    reserialize(spec)
        .map_err(|reason| doc.reject_with(new_id(), RejectReason::MalformedRequest { reason }))
}

async fn handle_create<R>(repository: Arc<R>, doc: TrustTask<RecordCreateRequest>) -> TaskOutcome
where
    R: TrustRecordAdminRepository + ?Sized + 'static,
{
    let record = record_from_payload(&doc, &doc.payload.record)?;
    match repository.create(record).await {
        Ok(()) => respond(
            &doc,
            RecordCreateResponse {
                ok: true,
                message: None,
                ext: None,
            },
        ),
        Err(e) => Err(doc.reject_with(new_id(), map_repo_err(e))),
    }
}

async fn handle_update<R>(repository: Arc<R>, doc: TrustTask<RecordUpdateRequest>) -> TaskOutcome
where
    R: TrustRecordAdminRepository + ?Sized + 'static,
{
    let record = record_from_payload(&doc, &doc.payload.record)?;
    match repository.update(record).await {
        Ok(()) => respond(
            &doc,
            RecordUpdateResponse {
                ok: true,
                message: None,
                ext: None,
            },
        ),
        Err(e) => Err(doc.reject_with(new_id(), map_repo_err(e))),
    }
}

async fn handle_delete<R>(repository: Arc<R>, doc: TrustTask<RecordDeleteRequest>) -> TaskOutcome
where
    R: TrustRecordAdminRepository + ?Sized + 'static,
{
    let p = &doc.payload;
    let query = query_of(&p.entity_id, &p.authority_id, &p.action, &p.resource);
    match repository.delete(query).await {
        Ok(()) => respond(
            &doc,
            RecordDeleteResponse {
                ok: true,
                message: None,
                ext: None,
            },
        ),
        Err(e) => Err(doc.reject_with(new_id(), map_repo_err(e))),
    }
}

async fn handle_read<R>(repository: Arc<R>, doc: TrustTask<RecordReadRequest>) -> TaskOutcome
where
    R: TrustRecordAdminRepository + ?Sized + 'static,
{
    let p = &doc.payload;
    let query = query_of(&p.entity_id, &p.authority_id, &p.action, &p.resource);
    match repository.read(query).await {
        Ok(record) => match reserialize::<_, RecordReadResponse>(&record) {
            Ok(response) => respond(&doc, response),
            Err(reason) => Err(doc.reject_with(new_id(), RejectReason::InternalError { reason })),
        },
        Err(e) => Err(doc.reject_with(new_id(), map_repo_err(e))),
    }
}

async fn handle_list<R>(repository: Arc<R>, doc: TrustTask<RecordListRequest>) -> TaskOutcome
where
    R: TrustRecordAdminRepository + ?Sized + 'static,
{
    match repository.list().await {
        // `TrustRecordList` serialises as `{ "records": [...] }`, matching the
        // spec list response, so the round-trip is a straight re-serialise.
        Ok(list) => match reserialize::<_, RecordListResponse>(&list) {
            Ok(response) => respond(&doc, response),
            Err(reason) => Err(doc.reject_with(new_id(), RejectReason::InternalError { reason })),
        },
        Err(e) => Err(doc.reject_with(new_id(), map_repo_err(e))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::{
        Action, AuthorityId, EntityId, RecordType, Resource, TrustRecord, TrustRecordBuilder,
    };
    use crate::storage::repository::{TrustRecordList, TrustRecordQuery};
    use std::sync::Mutex;
    use trust_tasks_rs::Payload;

    #[derive(Default)]
    struct MockRepo {
        record: Option<TrustRecord>,
        created: Mutex<Vec<TrustRecord>>,
        fail: bool,
    }

    fn sample_record() -> TrustRecord {
        TrustRecordBuilder::new()
            .entity_id(EntityId::new("did:example:entity"))
            .authority_id(AuthorityId::new("did:example:authority"))
            .action(Action::new("issue"))
            .resource(Resource::new("vc"))
            .recognized(true)
            .authorized(true)
            .record_type(RecordType::Authorization)
            .build()
            .expect("valid record")
    }

    #[async_trait::async_trait]
    impl TrustRecordRepository for MockRepo {
        async fn find_by_query(
            &self,
            _query: TrustRecordQuery,
        ) -> Result<Option<TrustRecord>, RepositoryError> {
            if self.fail {
                return Err(RepositoryError::QueryFailed("boom".into()));
            }
            Ok(self.record.clone())
        }
    }

    #[async_trait::async_trait]
    impl TrustRecordAdminRepository for MockRepo {
        async fn create(&self, record: TrustRecord) -> Result<(), RepositoryError> {
            self.created
                .lock()
                .map_err(|_| RepositoryError::LockPoisoned)?
                .push(record);
            Ok(())
        }
        async fn update(&self, _record: TrustRecord) -> Result<(), RepositoryError> {
            Ok(())
        }
        async fn delete(&self, _query: TrustRecordQuery) -> Result<(), RepositoryError> {
            Ok(())
        }
        async fn list(&self) -> Result<TrustRecordList, RepositoryError> {
            Ok(TrustRecordList::new(
                self.record.clone().into_iter().collect(),
            ))
        }
        async fn read(&self, _query: TrustRecordQuery) -> Result<TrustRecord, RepositoryError> {
            self.record
                .clone()
                .ok_or_else(|| RepositoryError::RecordNotFound("none".into()))
        }
    }

    fn value_doc<P: Payload>(payload: P) -> TrustTask<Value> {
        let value = serde_json::to_value(payload).expect("serialises");
        TrustTask::new(new_id(), P::type_uri(), value)
    }

    #[tokio::test]
    async fn recognition_returns_typed_response() {
        let repo = Arc::new(MockRepo {
            record: Some(sample_record()),
            ..Default::default()
        });
        let dispatcher = build_dispatcher(repo);

        let doc = value_doc(RecognitionRequest {
            entity_id: "did:example:entity".into(),
            authority_id: "did:example:authority".into(),
            action: "issue".into(),
            resource: "vc".into(),
            context: None,
            ext: None,
        });

        let out = handle_document(&dispatcher, doc)
            .await
            .expect("ok response");
        assert!(out.type_uri.is_response());
        let resp: RecognitionResponse =
            serde_json::from_value(out.payload).expect("response parses");
        assert!(resp.recognized);
        assert_eq!(resp.entity_id, "did:example:entity");
        assert!(resp.message.is_some());
    }

    #[tokio::test]
    async fn recognition_absent_record_is_not_recognized() {
        let repo = Arc::new(MockRepo::default());
        let dispatcher = build_dispatcher(repo);
        let doc = value_doc(RecognitionRequest {
            entity_id: "x".into(),
            authority_id: "y".into(),
            action: "a".into(),
            resource: "r".into(),
            context: None,
            ext: None,
        });
        let out = handle_document(&dispatcher, doc).await.expect("ok");
        let resp: RecognitionResponse = serde_json::from_value(out.payload).expect("parses");
        assert!(!resp.recognized);
        assert!(resp.message.is_none());
    }

    #[tokio::test]
    async fn create_record_acknowledges_and_persists() {
        let repo = Arc::new(MockRepo::default());
        let dispatcher = build_dispatcher(repo.clone());
        let doc = value_doc(RecordCreateRequest {
            record: reserialize(&sample_record()).expect("domain -> spec record"),
            ext: None,
        });
        let out = handle_document(&dispatcher, doc).await.expect("ok");
        let ack: RecordCreateResponse = serde_json::from_value(out.payload).expect("ack parses");
        assert!(ack.ok);
        assert_eq!(repo.created.lock().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn repository_error_becomes_error_response() {
        let repo = Arc::new(MockRepo {
            fail: true,
            ..Default::default()
        });
        let dispatcher = build_dispatcher(repo);
        let doc = value_doc(RecognitionRequest {
            entity_id: "x".into(),
            authority_id: "y".into(),
            action: "a".into(),
            resource: "r".into(),
            context: None,
            ext: None,
        });
        let out = handle_document(&dispatcher, doc).await;
        assert!(out.is_err(), "repository failure should reject");
    }

    #[tokio::test]
    async fn unknown_type_is_rejected() {
        let repo = Arc::new(MockRepo::default());
        let dispatcher = build_dispatcher(repo);
        let doc = TrustTask::new(
            new_id(),
            "https://trusttasks.org/spec/registry/does-not-exist/0.1"
                .parse()
                .expect("valid type uri"),
            serde_json::json!({}),
        );
        let out = handle_document(&dispatcher, doc).await;
        assert!(
            out.is_err(),
            "unknown type should route to an error response"
        );
    }

    #[test]
    fn dispatcher_registers_all_seven_ops() {
        let repo = Arc::new(MockRepo::default());
        let dispatcher = build_dispatcher(repo);
        assert_eq!(dispatcher.registered_uris().len(), 7);
    }

    #[test]
    fn query_dispatcher_registers_only_the_two_reads() {
        let repo = Arc::new(MockRepo::default());
        let dispatcher = build_query_dispatcher(repo);
        assert_eq!(dispatcher.registered_uris().len(), 2);
    }

    #[tokio::test]
    async fn query_dispatcher_handles_recognition() {
        let repo = Arc::new(MockRepo {
            record: Some(sample_record()),
            ..Default::default()
        });
        let dispatcher = build_query_dispatcher(repo);
        let doc = value_doc(RecognitionRequest {
            entity_id: "did:example:entity".into(),
            authority_id: "did:example:authority".into(),
            action: "issue".into(),
            resource: "vc".into(),
            context: None,
            ext: None,
        });
        let out = handle_document(&dispatcher, doc).await.expect("ok");
        let resp: RecognitionResponse = serde_json::from_value(out.payload).expect("parses");
        assert!(resp.recognized);
    }

    #[tokio::test]
    async fn query_dispatcher_rejects_record_writes() {
        // Record CRUD is DIDComm-only; the HTTP query dispatcher must not route it.
        let repo = Arc::new(MockRepo::default());
        let dispatcher = build_query_dispatcher(repo);
        let doc = value_doc(RecordCreateRequest {
            record: reserialize(&sample_record()).expect("domain -> spec record"),
            ext: None,
        });
        let out = handle_document(&dispatcher, doc).await;
        assert!(
            out.is_err(),
            "write over the query dispatcher must be rejected"
        );
    }
}
