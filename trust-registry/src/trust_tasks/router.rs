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
    RecordDeleteRequest, RecordDeleteResponse, RecordPutRequest, RecordPutResponse,
    RecordQueryRequest, RecordQueryResponse, SpecTrustRecord, query_of, reserialize,
};

/// Default `registry/record/query` page size when the request names none.
const QUERY_DEFAULT_LIMIT: usize = 50;
/// Hard `registry/record/query` page-size ceiling (the spec's 1..=200 clamp).
const QUERY_MAX_LIMIT: usize = 200;

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
        .on::<RecordPutRequest, _>({
            let repo = repository.clone();
            move |doc| -> TaskFuture { Box::pin(handle_put(repo.clone(), doc)) }
        })
        .on::<RecordQueryRequest, _>({
            let repo = repository.clone();
            move |doc| -> TaskFuture { Box::pin(handle_query(repo.clone(), doc)) }
        })
        .on::<RecordDeleteRequest, _>({
            let repo = repository.clone();
            move |doc| -> TaskFuture { Box::pin(handle_delete(repo.clone(), doc)) }
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

/// Convert a spec record (carried by a put payload) into the domain record the
/// repository operates on, mapping a malformed record to a `MalformedRequest`
/// rejection.
fn record_from_payload<P>(
    doc: &TrustTask<P>,
    spec: &impl Serialize,
) -> Result<TrustRecord, ErrorResponse> {
    reserialize(spec)
        .map_err(|reason| doc.reject_with(new_id(), RejectReason::MalformedRequest { reason }))
}

/// `registry/record/put` — create or replace at the record's four-part key.
///
/// `expectedExisting` recovers the strict semantics of the superseded
/// create/update pair: `Some(false)` is create-only, `Some(true)` is
/// update-only, `None` is create-or-replace (create first, fall back to update
/// when the key is already present).
async fn handle_put<R>(repository: Arc<R>, doc: TrustTask<RecordPutRequest>) -> TaskOutcome
where
    R: TrustRecordAdminRepository + ?Sized + 'static,
{
    let record = record_from_payload(&doc, &doc.payload.record)?;
    let outcome = match doc.payload.expected_existing {
        // Strict update: the key must already exist.
        Some(true) => repository.update(record).await.map(|()| false),
        // Strict create: the key must not exist.
        Some(false) => repository.create(record).await.map(|()| true),
        // Pure upsert.
        None => match repository.create(record.clone()).await {
            Ok(()) => Ok(true),
            Err(RepositoryError::RecordAlreadyExists(_)) => {
                repository.update(record).await.map(|()| false)
            }
            Err(e) => Err(e),
        },
    };
    match outcome {
        Ok(created) => respond(
            &doc,
            RecordPutResponse {
                ok: true,
                created,
                message: None,
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

/// `registry/record/query` — exact fetch when all four key parts are present
/// (notFound on a miss, via the repository's `read`), filtered cursor-paginated
/// enumeration otherwise.
///
/// The cursor is an opaque-to-callers offset into the deterministically sorted
/// match set; enumeration order is therefore stable across the pages of one
/// traversal, as the spec requires.
async fn handle_query<R>(repository: Arc<R>, doc: TrustTask<RecordQueryRequest>) -> TaskOutcome
where
    R: TrustRecordAdminRepository + ?Sized + 'static,
{
    let p = &doc.payload;

    // Fully keyed: an exact fetch of the single record, notFound on a miss.
    if let (Some(entity_id), Some(authority_id), Some(action), Some(resource)) =
        (&p.entity_id, &p.authority_id, &p.action, &p.resource)
    {
        let query = query_of(entity_id, authority_id, action, resource);
        return match repository.read(query).await {
            Ok(record) => match reserialize::<_, SpecTrustRecord>(&record) {
                Ok(record) => respond(
                    &doc,
                    RecordQueryResponse {
                        records: vec![record],
                        next_cursor: None,
                    },
                ),
                Err(reason) => {
                    Err(doc.reject_with(new_id(), RejectReason::InternalError { reason }))
                }
            },
            Err(e) => Err(doc.reject_with(new_id(), map_repo_err(e))),
        };
    }

    // Partially keyed (or unkeyed): filtered, paginated enumeration.
    let offset: usize = match p.cursor.as_deref() {
        None => 0,
        Some(cursor) => match cursor.parse() {
            Ok(offset) => offset,
            Err(_) => {
                return Err(doc.reject_with(
                    new_id(),
                    RejectReason::MalformedRequest {
                        reason: "unrecognized cursor".to_string(),
                    },
                ));
            }
        },
    };
    let limit = p
        .limit
        .map_or(QUERY_DEFAULT_LIMIT, |l| l as usize)
        .clamp(1, QUERY_MAX_LIMIT);

    let list = match repository.list().await {
        Ok(list) => list,
        Err(e) => return Err(doc.reject_with(new_id(), map_repo_err(e))),
    };
    let field_matches =
        |filter: Option<&str>, value: &str| filter.is_none_or(|wanted| wanted == value);
    let mut matches: Vec<TrustRecord> = list
        .into_records()
        .into_iter()
        .filter(|r| {
            field_matches(p.entity_id.as_deref(), r.entity_id().as_str())
                && field_matches(p.authority_id.as_deref(), r.authority_id().as_str())
                && field_matches(p.action.as_deref(), r.action().as_str())
                && field_matches(p.resource.as_deref(), r.resource().as_str())
        })
        .collect();
    matches.sort_by(|a, b| {
        (
            a.entity_id().as_str(),
            a.authority_id().as_str(),
            a.action().as_str(),
            a.resource().as_str(),
        )
            .cmp(&(
                b.entity_id().as_str(),
                b.authority_id().as_str(),
                b.action().as_str(),
                b.resource().as_str(),
            ))
    });

    let next_cursor =
        (offset.saturating_add(limit) < matches.len()).then(|| (offset + limit).to_string());
    let page: Result<Vec<SpecTrustRecord>, String> = matches
        .iter()
        .skip(offset)
        .take(limit)
        .map(reserialize)
        .collect();
    match page {
        Ok(records) => respond(
            &doc,
            RecordQueryResponse {
                records,
                next_cursor,
            },
        ),
        Err(reason) => Err(doc.reject_with(new_id(), RejectReason::InternalError { reason })),
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
        /// Extra records returned by `list` (after `record`), for enumeration
        /// and pagination tests.
        listing: Vec<TrustRecord>,
        created: Mutex<Vec<TrustRecord>>,
        updated: Mutex<Vec<TrustRecord>>,
        /// When set, `create` reports the key as already taken.
        create_conflicts: bool,
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
            if self.create_conflicts {
                return Err(RepositoryError::RecordAlreadyExists("taken".into()));
            }
            self.created
                .lock()
                .map_err(|_| RepositoryError::LockPoisoned)?
                .push(record);
            Ok(())
        }
        async fn update(&self, record: TrustRecord) -> Result<(), RepositoryError> {
            self.updated
                .lock()
                .map_err(|_| RepositoryError::LockPoisoned)?
                .push(record);
            Ok(())
        }
        async fn delete(&self, _query: TrustRecordQuery) -> Result<(), RepositoryError> {
            Ok(())
        }
        async fn list(&self) -> Result<TrustRecordList, RepositoryError> {
            Ok(TrustRecordList::new(
                self.record
                    .clone()
                    .into_iter()
                    .chain(self.listing.iter().cloned())
                    .collect(),
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
    async fn put_of_a_new_key_creates_and_reports_created() {
        let repo = Arc::new(MockRepo::default());
        let dispatcher = build_dispatcher(repo.clone());
        let doc = value_doc(RecordPutRequest {
            record: reserialize(&sample_record()).expect("domain -> spec record"),
            expected_existing: None,
        });
        let out = handle_document(&dispatcher, doc).await.expect("ok");
        let ack: RecordPutResponse = serde_json::from_value(out.payload).expect("ack parses");
        assert!(ack.ok);
        assert!(ack.created);
        assert_eq!(repo.created.lock().unwrap().len(), 1);
        assert_eq!(repo.updated.lock().unwrap().len(), 0);
    }

    #[tokio::test]
    async fn put_of_an_existing_key_falls_back_to_update() {
        let repo = Arc::new(MockRepo {
            create_conflicts: true,
            ..Default::default()
        });
        let dispatcher = build_dispatcher(repo.clone());
        let doc = value_doc(RecordPutRequest {
            record: reserialize(&sample_record()).expect("domain -> spec record"),
            expected_existing: None,
        });
        let out = handle_document(&dispatcher, doc).await.expect("ok");
        let ack: RecordPutResponse = serde_json::from_value(out.payload).expect("ack parses");
        assert!(ack.ok);
        assert!(!ack.created, "replacing an existing key is not a create");
        assert_eq!(repo.updated.lock().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn strict_create_put_rejects_an_existing_key() {
        // expectedExisting: false must NOT fall back to update — it surfaces
        // the already-exists conflict instead.
        let repo = Arc::new(MockRepo {
            create_conflicts: true,
            ..Default::default()
        });
        let dispatcher = build_dispatcher(repo.clone());
        let doc = value_doc(RecordPutRequest {
            record: reserialize(&sample_record()).expect("domain -> spec record"),
            expected_existing: Some(false),
        });
        let out = handle_document(&dispatcher, doc).await;
        assert!(out.is_err(), "strict create over an existing key rejects");
        assert_eq!(repo.updated.lock().unwrap().len(), 0);
    }

    #[tokio::test]
    async fn strict_update_put_routes_to_update() {
        let repo = Arc::new(MockRepo::default());
        let dispatcher = build_dispatcher(repo.clone());
        let doc = value_doc(RecordPutRequest {
            record: reserialize(&sample_record()).expect("domain -> spec record"),
            expected_existing: Some(true),
        });
        let out = handle_document(&dispatcher, doc).await.expect("ok");
        let ack: RecordPutResponse = serde_json::from_value(out.payload).expect("ack parses");
        assert!(!ack.created);
        assert_eq!(repo.updated.lock().unwrap().len(), 1);
        assert_eq!(repo.created.lock().unwrap().len(), 0);
    }

    #[tokio::test]
    async fn fully_keyed_query_fetches_exactly_one_record() {
        let repo = Arc::new(MockRepo {
            record: Some(sample_record()),
            ..Default::default()
        });
        let dispatcher = build_dispatcher(repo);
        let doc = value_doc(RecordQueryRequest {
            entity_id: Some("did:example:entity".into()),
            authority_id: Some("did:example:authority".into()),
            action: Some("issue".into()),
            resource: Some("vc".into()),
            ..Default::default()
        });
        let out = handle_document(&dispatcher, doc).await.expect("ok");
        let resp: RecordQueryResponse = serde_json::from_value(out.payload).expect("parses");
        assert_eq!(resp.records.len(), 1);
        assert!(resp.next_cursor.is_none());
    }

    #[tokio::test]
    async fn fully_keyed_query_miss_is_an_error_not_an_empty_page() {
        let repo = Arc::new(MockRepo::default());
        let dispatcher = build_dispatcher(repo);
        let doc = value_doc(RecordQueryRequest {
            entity_id: Some("x".into()),
            authority_id: Some("y".into()),
            action: Some("a".into()),
            resource: Some("r".into()),
            ..Default::default()
        });
        let out = handle_document(&dispatcher, doc).await;
        assert!(out.is_err(), "fully keyed miss must reject with notFound");
    }

    fn listing_record(entity: &str) -> TrustRecord {
        TrustRecordBuilder::new()
            .entity_id(EntityId::new(entity))
            .authority_id(AuthorityId::new("did:example:authority"))
            .action(Action::new("issue"))
            .resource(Resource::new("vc"))
            .recognized(true)
            .authorized(true)
            .record_type(RecordType::Authorization)
            .build()
            .expect("valid record")
    }

    #[tokio::test]
    async fn partial_query_filters_and_paginates_with_a_stable_cursor() {
        let repo = Arc::new(MockRepo {
            listing: vec![
                listing_record("did:example:charlie"),
                listing_record("did:example:alice"),
                listing_record("did:example:bob"),
            ],
            ..Default::default()
        });
        let dispatcher = build_dispatcher(repo);

        // Page 1 of 2.
        let doc = value_doc(RecordQueryRequest {
            authority_id: Some("did:example:authority".into()),
            limit: Some(2),
            ..Default::default()
        });
        let out = handle_document(&dispatcher, doc).await.expect("ok");
        let page1: RecordQueryResponse = serde_json::from_value(out.payload).expect("parses");
        assert_eq!(page1.records.len(), 2);
        assert_eq!(page1.records[0].entity_id, "did:example:alice");
        assert_eq!(page1.records[1].entity_id, "did:example:bob");
        let cursor = page1.next_cursor.expect("a second page remains");

        // Page 2 of 2.
        let doc = value_doc(RecordQueryRequest {
            authority_id: Some("did:example:authority".into()),
            limit: Some(2),
            cursor: Some(cursor),
            ..Default::default()
        });
        let out = handle_document(&dispatcher, doc).await.expect("ok");
        let page2: RecordQueryResponse = serde_json::from_value(out.payload).expect("parses");
        assert_eq!(page2.records.len(), 1);
        assert_eq!(page2.records[0].entity_id, "did:example:charlie");
        assert!(page2.next_cursor.is_none());
    }

    #[tokio::test]
    async fn partial_query_with_no_match_is_an_empty_page_not_an_error() {
        let repo = Arc::new(MockRepo {
            record: Some(sample_record()),
            ..Default::default()
        });
        let dispatcher = build_dispatcher(repo);
        let doc = value_doc(RecordQueryRequest {
            authority_id: Some("did:example:someone-else".into()),
            ..Default::default()
        });
        let out = handle_document(&dispatcher, doc).await.expect("ok");
        let resp: RecordQueryResponse = serde_json::from_value(out.payload).expect("parses");
        assert!(resp.records.is_empty());
        assert!(resp.next_cursor.is_none());
    }

    #[tokio::test]
    async fn malformed_cursor_is_rejected() {
        let repo = Arc::new(MockRepo::default());
        let dispatcher = build_dispatcher(repo);
        let doc = value_doc(RecordQueryRequest {
            cursor: Some("not-a-cursor".into()),
            ..Default::default()
        });
        let out = handle_document(&dispatcher, doc).await;
        assert!(out.is_err(), "a cursor we did not mint must be rejected");
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
    fn dispatcher_registers_all_five_ops() {
        // recognition, authorization, record/put, record/query, record/delete.
        let repo = Arc::new(MockRepo::default());
        let dispatcher = build_dispatcher(repo);
        assert_eq!(dispatcher.registered_uris().len(), 5);
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
        let doc = value_doc(RecordPutRequest {
            record: reserialize(&sample_record()).expect("domain -> spec record"),
            expected_existing: None,
        });
        let out = handle_document(&dispatcher, doc).await;
        assert!(
            out.is_err(),
            "write over the query dispatcher must be rejected"
        );
    }
}
