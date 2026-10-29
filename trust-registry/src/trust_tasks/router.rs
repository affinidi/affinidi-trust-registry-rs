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
// The 0.1 `registry/*` types are deprecated (superseded by the lowerCamelCase
// versions); both are served deliberately, so peers on either keep working.
#![allow(deprecated)]

use std::sync::Arc;

use chrono::{DateTime, Utc};
use futures::future::BoxFuture;
use serde::Serialize;
use serde_json::Value;
use trust_tasks_rs::{Dispatcher, ErrorResponse, RejectReason, TrustTask};
use uuid::Uuid;

use crate::domain::{Evaluation, TrustRecord};
use crate::storage::repository::{
    RepositoryError, TrustRecordAdminRepository, TrustRecordRepository,
};

use super::payloads::{
    AuthorizationRequest, AuthorizationResponse, AuthorizationResponseMessage, RecognitionRequest,
    RecognitionResponse, RecognitionResponseMessage, RecordDeleteRequest, RecordDeleteResponse,
    RecordPutRequest, RecordPutResponse, RecordQueryRequest, RecordQueryResponse, query_of,
    record_from_v1, record_from_v2, record_to_v1, record_to_v2, v2,
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

/// Map a generated-payload builder failure to an internal-error response.
///
/// The generated response types are `#[non_exhaustive]`, so they are assembled
/// through their builders and validated at `try_into()`. Every required field
/// is supplied at each call site, so a failure here means this crate and the
/// spec crate disagree about the response shape — our bug, not the caller's.
fn reject_build_err<P>(doc: &TrustTask<P>, err: impl std::fmt::Display) -> ErrorResponse {
    doc.reject_with(
        new_id(),
        RejectReason::InternalError {
            reason: format!("could not build response payload: {err}"),
        },
    )
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
        .on::<v2::RecognitionRequest, _>({
            let repo = repository.clone();
            move |doc| -> TaskFuture { Box::pin(handle_recognition_v2(repo.clone(), doc)) }
        })
        .on::<v2::AuthorizationRequest, _>({
            let repo = repository.clone();
            move |doc| -> TaskFuture { Box::pin(handle_authorization_v2(repo.clone(), doc)) }
        })
        .on::<v2::RecordPutRequest, _>({
            let repo = repository.clone();
            move |doc| -> TaskFuture { Box::pin(handle_put_v2(repo.clone(), doc)) }
        })
        .on::<v2::RecordQueryRequest, _>({
            let repo = repository.clone();
            move |doc| -> TaskFuture { Box::pin(handle_query_v2(repo.clone(), doc)) }
        })
        .on::<v2::RecordDeleteRequest, _>({
            let repo = repository.clone();
            move |doc| -> TaskFuture { Box::pin(handle_delete_v2(repo.clone(), doc)) }
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
        .on::<v2::RecognitionRequest, _>({
            let repo = repository.clone();
            move |doc| -> TaskFuture { Box::pin(handle_recognition_v2(repo.clone(), doc)) }
        })
        .on::<v2::AuthorizationRequest, _>({
            let repo = repository.clone();
            move |doc| -> TaskFuture { Box::pin(handle_authorization_v2(repo.clone(), doc)) }
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
//
// Each task has one core, shared by its versions, and a thin per-version layer
// that reads that version's payload and builds its response. The versions
// differ only in wire spelling (and, for records, whether the validity window
// can be carried), never in what the registry decides.

/// Look up the record a TRQP query names and evaluate it as of the instant
/// asked (`context.time`), or the registry's clock when none was asked.
async fn evaluate_query<R>(
    repository: &R,
    ids: (&str, &str, &str, &str),
    asked: Option<DateTime<Utc>>,
) -> Result<(Option<TrustRecord>, Evaluation), RepositoryError>
where
    R: TrustRecordRepository + ?Sized,
{
    let record = repository
        .find_by_query(query_of(ids.0, ids.1, ids.2, ids.3))
        .await?;
    let evaluation = Evaluation::of(record.as_ref(), asked, Utc::now());
    Ok((record, evaluation))
}

/// The advisory `message`. The spec caps it at 1024 characters, so an answer
/// whose message would exceed that (pathologically long identifiers) goes
/// without one rather than failing on a field nothing decides on.
fn query_message<M>(record: Option<&TrustRecord>, evaluation: &Evaluation, verb: &str) -> Option<M>
where
    M: TryFrom<String>,
{
    let tr = record?;
    let text = match evaluation.out_of_window_reason(tr) {
        Some(reason) => format!(
            "{} not {verb} by {}: {reason}",
            tr.entity_id().as_str(),
            tr.authority_id().as_str()
        ),
        None if verb == "authorized" => format!(
            "{} authorized to {}+{} by {}",
            tr.entity_id().as_str(),
            tr.action().as_str(),
            tr.resource().as_str(),
            tr.authority_id().as_str()
        ),
        None => format!(
            "{} recognized by {}",
            tr.entity_id().as_str(),
            tr.authority_id().as_str()
        ),
    };
    text.try_into().ok()
}

/// One TRQP query handler per version. `$evaluated`/`$asked` are the builder
/// setters for that version's two time members (`time_evaluated` /
/// `time_requested` in 0.1, `evaluated_at` / `as_of` in 0.2).
macro_rules! trqp_handler {
    ($name:ident, $req:ty, $resp:ty, $msg:ty, $flag:ident, $is:ident, $verb:literal, $evaluated:ident, $asked:ident) => {
        async fn $name<R>(repository: Arc<R>, doc: TrustTask<$req>) -> TaskOutcome
        where
            R: TrustRecordRepository + ?Sized + 'static,
        {
            let p = &doc.payload;
            let asked = p.context.as_ref().and_then(|c| c.time);
            let (record, evaluation) = match evaluate_query(
                repository.as_ref(),
                (&p.entity_id, &p.authority_id, &p.action, &p.resource),
                asked,
            )
            .await
            {
                Ok(found) => found,
                Err(e) => return Err(doc.reject_with(new_id(), map_repo_err(e))),
            };
            // Outside its window, a record answers false whatever it stores.
            let holds = evaluation.in_window() && record.as_ref().is_some_and(|tr| tr.$is());
            let message: Option<$msg> = query_message(record.as_ref(), &evaluation, $verb);
            let response: $resp = <$resp>::builder()
                .entity_id(p.entity_id.clone())
                .authority_id(p.authority_id.clone())
                .action(p.action.clone())
                .resource(p.resource.clone())
                .$flag(holds)
                .$evaluated(Utc::now())
                .$asked(asked)
                .message(message)
                .try_into()
                .map_err(|e| reject_build_err(&doc, e))?;
            respond(&doc, response)
        }
    };
}

trqp_handler!(
    handle_recognition,
    RecognitionRequest,
    RecognitionResponse,
    RecognitionResponseMessage,
    recognized,
    is_recognized,
    "recognized",
    time_evaluated,
    time_requested
);
trqp_handler!(
    handle_authorization,
    AuthorizationRequest,
    AuthorizationResponse,
    AuthorizationResponseMessage,
    authorized,
    is_authorized,
    "authorized",
    time_evaluated,
    time_requested
);
trqp_handler!(
    handle_recognition_v2,
    v2::RecognitionRequest,
    v2::RecognitionResponse,
    v2::RecognitionResponseMessage,
    recognized,
    is_recognized,
    "recognized",
    evaluated_at,
    as_of
);
trqp_handler!(
    handle_authorization_v2,
    v2::AuthorizationRequest,
    v2::AuthorizationResponse,
    v2::AuthorizationResponseMessage,
    authorized,
    is_authorized,
    "authorized",
    evaluated_at,
    as_of
);

/// `registry/record/put` — create or replace at the record's four-part key.
///
/// `expectedExisting` recovers the strict semantics of the superseded
/// create/update pair: `Some(false)` is create-only, `Some(true)` is
/// update-only, `None` is create-or-replace (create first, fall back to update
/// when the key is already present). Returns whether the record was created.
async fn put_record<R>(
    repository: &R,
    record: TrustRecord,
    expected_existing: Option<bool>,
) -> Result<bool, RepositoryError>
where
    R: TrustRecordAdminRepository + ?Sized,
{
    match expected_existing {
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
    }
}

fn malformed<P>(doc: &TrustTask<P>) -> impl FnOnce(String) -> ErrorResponse + '_ {
    move |reason| doc.reject_with(new_id(), RejectReason::MalformedRequest { reason })
}

/// `registry/record/put/0.1`. The record has no validity window, so a put
/// replaces any window the stored record had.
async fn handle_put<R>(repository: Arc<R>, doc: TrustTask<RecordPutRequest>) -> TaskOutcome
where
    R: TrustRecordAdminRepository + ?Sized + 'static,
{
    let record = record_from_v1(&doc.payload.record).map_err(malformed(&doc))?;
    match put_record(repository.as_ref(), record, doc.payload.expected_existing).await {
        Ok(created) => {
            let response: RecordPutResponse = RecordPutResponse::builder()
                .ok(true)
                .created(created)
                .try_into()
                .map_err(|e| reject_build_err(&doc, e))?;
            respond(&doc, response)
        }
        Err(e) => Err(doc.reject_with(new_id(), map_repo_err(e))),
    }
}

/// `registry/record/put/0.3`: lowerCamelCase, with the optional validity
/// window. A window whose `validFrom` is not before its `validUntil` is
/// refused as `malformedRequest`.
async fn handle_put_v2<R>(repository: Arc<R>, doc: TrustTask<v2::RecordPutRequest>) -> TaskOutcome
where
    R: TrustRecordAdminRepository + ?Sized + 'static,
{
    let record = record_from_v2(&doc.payload.record).map_err(malformed(&doc))?;
    match put_record(repository.as_ref(), record, doc.payload.expected_existing).await {
        Ok(was_created) => {
            let response: v2::RecordPutResponse = v2::RecordPutResponse::builder()
                .ok(true)
                .was_created(was_created)
                .try_into()
                .map_err(|e| reject_build_err(&doc, e))?;
            respond(&doc, response)
        }
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
        Ok(()) => {
            let response: RecordDeleteResponse = RecordDeleteResponse::builder()
                .ok(true)
                .try_into()
                .map_err(|e| reject_build_err(&doc, e))?;
            respond(&doc, response)
        }
        Err(e) => Err(doc.reject_with(new_id(), map_repo_err(e))),
    }
}

async fn handle_delete_v2<R>(
    repository: Arc<R>,
    doc: TrustTask<v2::RecordDeleteRequest>,
) -> TaskOutcome
where
    R: TrustRecordAdminRepository + ?Sized + 'static,
{
    let p = &doc.payload;
    let query = query_of(&p.entity_id, &p.authority_id, &p.action, &p.resource);
    match repository.delete(query).await {
        Ok(()) => {
            let response: v2::RecordDeleteResponse = v2::RecordDeleteResponse::builder()
                .ok(true)
                .try_into()
                .map_err(|e| reject_build_err(&doc, e))?;
            respond(&doc, response)
        }
        Err(e) => Err(doc.reject_with(new_id(), map_repo_err(e))),
    }
}

/// The filters and paging of a `registry/record/query`, whatever its version.
struct RecordFilter<'a> {
    entity_id: Option<&'a str>,
    authority_id: Option<&'a str>,
    action: Option<&'a str>,
    resource: Option<&'a str>,
    cursor: Option<&'a str>,
    limit: Option<u64>,
}

/// `registry/record/query` — exact fetch when all four key parts are present
/// (notFound on a miss, via the repository's `read`), filtered cursor-paginated
/// enumeration otherwise. Returns the page and the next cursor.
///
/// The cursor is an opaque-to-callers offset into the deterministically sorted
/// match set; enumeration order is therefore stable across the pages of one
/// traversal, as the spec requires. Records are returned whatever their
/// validity window: this task inspects what is stored.
async fn query_records<R>(
    repository: &R,
    f: RecordFilter<'_>,
) -> Result<(Vec<TrustRecord>, Option<String>), RejectReason>
where
    R: TrustRecordAdminRepository + ?Sized,
{
    // Fully keyed: an exact fetch of the single record, notFound on a miss.
    if let (Some(entity_id), Some(authority_id), Some(action), Some(resource)) =
        (f.entity_id, f.authority_id, f.action, f.resource)
    {
        let query = query_of(entity_id, authority_id, action, resource);
        return repository
            .read(query)
            .await
            .map(|record| (vec![record], None))
            .map_err(map_repo_err);
    }

    // Partially keyed (or unkeyed): filtered, paginated enumeration.
    let offset: usize = match f.cursor {
        None => 0,
        Some(cursor) => cursor.parse().map_err(|_| RejectReason::MalformedRequest {
            reason: "unrecognized cursor".to_string(),
        })?,
    };
    let limit = f
        .limit
        .map_or(QUERY_DEFAULT_LIMIT, |l| {
            usize::try_from(l).unwrap_or(usize::MAX)
        })
        .clamp(1, QUERY_MAX_LIMIT);

    let list = repository.list().await.map_err(map_repo_err)?;
    let field_matches =
        |filter: Option<&str>, value: &str| filter.is_none_or(|wanted| wanted == value);
    let mut matches: Vec<TrustRecord> = list
        .into_records()
        .into_iter()
        .filter(|r| {
            field_matches(f.entity_id, r.entity_id().as_str())
                && field_matches(f.authority_id, r.authority_id().as_str())
                && field_matches(f.action, r.action().as_str())
                && field_matches(f.resource, r.resource().as_str())
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
    let page = matches.into_iter().skip(offset).take(limit).collect();
    Ok((page, next_cursor))
}

/// `registry/record/query/0.1`. Its records have no validity window, so a
/// stored window is left out of the answer.
async fn handle_query<R>(repository: Arc<R>, doc: TrustTask<RecordQueryRequest>) -> TaskOutcome
where
    R: TrustRecordAdminRepository + ?Sized + 'static,
{
    let p = &doc.payload;
    let filter = RecordFilter {
        entity_id: p.entity_id.as_deref(),
        authority_id: p.authority_id.as_deref(),
        action: p.action.as_deref(),
        resource: p.resource.as_deref(),
        cursor: p.cursor.as_deref(),
        limit: p.limit.map(|l| l.get()),
    };
    let (page, next_cursor) = query_records(repository.as_ref(), filter)
        .await
        .map_err(|reason| doc.reject_with(new_id(), reason))?;
    let records = page
        .iter()
        .map(record_to_v1)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|reason| doc.reject_with(new_id(), RejectReason::InternalError { reason }))?;
    let response: RecordQueryResponse = RecordQueryResponse::builder()
        .records(records)
        .next_cursor(next_cursor)
        .try_into()
        .map_err(|e| reject_build_err(&doc, e))?;
    respond(&doc, response)
}

/// `registry/record/query/0.3`: lowerCamelCase records, window included.
async fn handle_query_v2<R>(
    repository: Arc<R>,
    doc: TrustTask<v2::RecordQueryRequest>,
) -> TaskOutcome
where
    R: TrustRecordAdminRepository + ?Sized + 'static,
{
    let p = &doc.payload;
    let filter = RecordFilter {
        entity_id: p.entity_id.as_deref(),
        authority_id: p.authority_id.as_deref(),
        action: p.action.as_deref(),
        resource: p.resource.as_deref(),
        cursor: p.cursor.as_deref(),
        limit: p.limit.map(|l| l.get()),
    };
    let (page, next_cursor) = query_records(repository.as_ref(), filter)
        .await
        .map_err(|reason| doc.reject_with(new_id(), reason))?;
    let records = page
        .iter()
        .map(record_to_v2)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|reason| doc.reject_with(new_id(), RejectReason::InternalError { reason }))?;
    let response: v2::RecordQueryResponse = v2::RecordQueryResponse::builder()
        .records(records)
        .next_cursor(next_cursor)
        .try_into()
        .map_err(|e| reject_build_err(&doc, e))?;
    respond(&doc, response)
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

    /// The generated request payloads are `#[non_exhaustive]`, so tests build
    /// them through the spec builder rather than a struct literal.
    fn recognition_request(
        entity_id: &str,
        authority_id: &str,
        action: &str,
        resource: &str,
    ) -> RecognitionRequest {
        RecognitionRequest::builder()
            .entity_id(entity_id)
            .authority_id(authority_id)
            .action(action)
            .resource(resource)
            .try_into()
            .expect("valid recognition request")
    }

    #[tokio::test]
    async fn recognition_returns_typed_response() {
        let repo = Arc::new(MockRepo {
            record: Some(sample_record()),
            ..Default::default()
        });
        let dispatcher = build_dispatcher(repo);

        let doc = value_doc(recognition_request(
            "did:example:entity",
            "did:example:authority",
            "issue",
            "vc",
        ));

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
        let doc = value_doc(recognition_request("x", "y", "a", "r"));
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
            ext: None,
            record: record_to_v1(&sample_record()).expect("domain -> spec record"),
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
            ext: None,
            record: record_to_v1(&sample_record()).expect("domain -> spec record"),
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
            ext: None,
            record: record_to_v1(&sample_record()).expect("domain -> spec record"),
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
            ext: None,
            record: record_to_v1(&sample_record()).expect("domain -> spec record"),
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
            limit: std::num::NonZeroU64::new(2),
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
            limit: std::num::NonZeroU64::new(2),
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
        let doc = value_doc(recognition_request("x", "y", "a", "r"));
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

    fn registered(dispatcher: &RegistryDispatcher) -> Vec<String> {
        let mut uris: Vec<String> = dispatcher
            .registered_uris()
            .into_iter()
            .map(|u| {
                u.to_string()
                    .trim_start_matches("https://trusttasks.org/spec/")
                    .to_string()
            })
            .collect();
        uris.sort();
        uris
    }

    #[test]
    fn dispatcher_registers_both_versions_of_all_five_ops() {
        let dispatcher = build_dispatcher(Arc::new(MockRepo::default()));
        assert_eq!(
            registered(&dispatcher),
            [
                "registry/authorization/0.1",
                "registry/authorization/0.2",
                "registry/recognition/0.1",
                "registry/recognition/0.2",
                "registry/record/delete/0.1",
                "registry/record/delete/0.2",
                "registry/record/put/0.1",
                "registry/record/put/0.3",
                "registry/record/query/0.1",
                "registry/record/query/0.3",
            ]
        );
    }

    #[test]
    fn query_dispatcher_registers_only_the_reads() {
        let dispatcher = build_query_dispatcher(Arc::new(MockRepo::default()));
        assert_eq!(
            registered(&dispatcher),
            [
                "registry/authorization/0.1",
                "registry/authorization/0.2",
                "registry/recognition/0.1",
                "registry/recognition/0.2",
            ]
        );
    }

    #[tokio::test]
    async fn query_dispatcher_handles_recognition() {
        let repo = Arc::new(MockRepo {
            record: Some(sample_record()),
            ..Default::default()
        });
        let dispatcher = build_query_dispatcher(repo);
        let doc = value_doc(recognition_request(
            "did:example:entity",
            "did:example:authority",
            "issue",
            "vc",
        ));
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
            ext: None,
            record: record_to_v1(&sample_record()).expect("domain -> spec record"),
            expected_existing: None,
        });
        let out = handle_document(&dispatcher, doc).await;
        assert!(
            out.is_err(),
            "write over the query dispatcher must be rejected"
        );
    }

    // --- validity window and the lowerCamelCase versions --------------------

    fn ts(s: &str) -> DateTime<Utc> {
        DateTime::parse_from_rfc3339(s)
            .expect("rfc3339")
            .with_timezone(&Utc)
    }

    /// `sample_record` with a window from 2026-01-01 to 2027-01-01.
    fn windowed_record() -> TrustRecord {
        TrustRecordBuilder::new()
            .entity_id(EntityId::new("did:example:entity"))
            .authority_id(AuthorityId::new("did:example:authority"))
            .action(Action::new("issue"))
            .resource(Resource::new("vc"))
            .recognized(true)
            .authorized(true)
            .record_type(RecordType::Authorization)
            .valid_from(Some(ts("2026-01-01T00:00:00Z")))
            .valid_until(Some(ts("2027-01-01T00:00:00Z")))
            .build()
            .expect("valid record")
    }

    fn raw_doc<P: Payload>(payload: Value) -> TrustTask<Value> {
        TrustTask::new(new_id(), P::type_uri(), payload)
    }

    async fn answer(repo: MockRepo, doc: TrustTask<Value>) -> Value {
        let dispatcher = build_dispatcher(Arc::new(repo));
        handle_document(&dispatcher, doc)
            .await
            .expect("ok response")
            .payload
    }

    fn windowed_repo() -> MockRepo {
        MockRepo {
            record: Some(windowed_record()),
            ..Default::default()
        }
    }

    fn v2_query(time: Option<&str>) -> Value {
        let mut q = serde_json::json!({
            "entityId": "did:example:entity",
            "authorityId": "did:example:authority",
            "action": "issue",
            "resource": "vc",
        });
        if let Some(t) = time {
            q["context"] = serde_json::json!({ "time": t });
        }
        q
    }

    #[tokio::test]
    async fn v2_authorization_inside_the_window_is_authorized_and_echoes_as_of() {
        let out = answer(
            windowed_repo(),
            raw_doc::<v2::AuthorizationRequest>(v2_query(Some("2026-06-01T00:00:00Z"))),
        )
        .await;
        assert_eq!(out["authorized"], true);
        assert_eq!(out["entityId"], "did:example:entity");
        assert_eq!(out["asOf"], "2026-06-01T00:00:00Z");
        assert!(out["evaluatedAt"].is_string());
        assert!(
            out.get("time_evaluated").is_none(),
            "0.2 is lowerCamelCase: {out}"
        );
    }

    #[tokio::test]
    async fn v2_authorization_outside_the_window_is_false_with_a_reason() {
        for (time, reason) in [
            ("2025-12-31T23:59:59Z", "not valid until"),
            // validUntil is exclusive.
            ("2027-01-01T00:00:00Z", "stopped being valid"),
        ] {
            let out = answer(
                windowed_repo(),
                raw_doc::<v2::AuthorizationRequest>(v2_query(Some(time))),
            )
            .await;
            assert_eq!(out["authorized"], false, "{time}: {out}");
            assert!(
                out["message"].as_str().unwrap_or_default().contains(reason),
                "{time}: {out}"
            );
        }
    }

    #[tokio::test]
    async fn explicit_time_gets_no_start_leeway() {
        // 30 s before validFrom: inside the 60 s allowance, but the client
        // named the instant, so it is judged exactly.
        let out = answer(
            windowed_repo(),
            raw_doc::<v2::RecognitionRequest>(v2_query(Some("2025-12-31T23:59:30Z"))),
        )
        .await;
        assert_eq!(out["recognized"], false, "{out}");
    }

    #[tokio::test]
    async fn the_0_1_queries_apply_the_window_too() {
        let out = answer(
            windowed_repo(),
            raw_doc::<AuthorizationRequest>(serde_json::json!({
                "entity_id": "did:example:entity",
                "authority_id": "did:example:authority",
                "action": "issue",
                "resource": "vc",
                "context": { "time": "2030-01-01T00:00:00Z" },
            })),
        )
        .await;
        assert_eq!(out["authorized"], false, "{out}");
        assert_eq!(out["time_requested"], "2030-01-01T00:00:00Z");
    }

    #[tokio::test]
    async fn v2_put_stores_the_window() {
        let repo = Arc::new(MockRepo::default());
        let dispatcher = build_dispatcher(repo.clone());
        let out = handle_document(
            &dispatcher,
            raw_doc::<v2::RecordPutRequest>(serde_json::json!({
                "record": {
                    "entityId": "did:example:entity",
                    "authorityId": "did:example:authority",
                    "action": "issue",
                    "resource": "vc",
                    "authorized": true,
                    "recordType": "authorization",
                    "validFrom": "2026-01-01T00:00:00Z",
                    "validUntil": "2027-01-01T00:00:00Z",
                }
            })),
        )
        .await
        .expect("stored");
        assert_eq!(out.payload["wasCreated"], true);
        let created = repo.created.lock().expect("lock");
        assert_eq!(created[0].valid_from(), Some(ts("2026-01-01T00:00:00Z")));
        assert_eq!(created[0].valid_until(), Some(ts("2027-01-01T00:00:00Z")));
    }

    #[tokio::test]
    async fn v2_put_with_an_inverted_window_is_malformed() {
        let repo = Arc::new(MockRepo::default());
        let dispatcher = build_dispatcher(repo.clone());
        let err = handle_document(
            &dispatcher,
            raw_doc::<v2::RecordPutRequest>(serde_json::json!({
                "record": {
                    "entityId": "e", "authorityId": "a", "action": "x", "resource": "r",
                    "recordType": "recognition",
                    "validFrom": "2027-01-01T00:00:00Z",
                    "validUntil": "2026-01-01T00:00:00Z",
                }
            })),
        )
        .await
        .expect_err("refused");
        assert_eq!(err.payload.code.to_string(), "malformedRequest");
        assert!(repo.created.lock().expect("lock").is_empty());
    }

    #[tokio::test]
    async fn query_0_3_returns_the_window_and_0_1_leaves_it_out() {
        let keyed = |camel: bool| {
            let (e, a) = if camel {
                ("entityId", "authorityId")
            } else {
                ("entity_id", "authority_id")
            };
            serde_json::json!({ e: "did:example:entity", a: "did:example:authority", "action": "issue", "resource": "vc" })
        };
        let v2_out = answer(
            windowed_repo(),
            raw_doc::<v2::RecordQueryRequest>(keyed(true)),
        )
        .await;
        let record = &v2_out["records"][0];
        assert_eq!(record["validFrom"], "2026-01-01T00:00:00Z");
        assert_eq!(record["recordType"], "authorization");

        // A 0.1 reader rejects unknown members, so the window is not sent.
        let v1_out = answer(windowed_repo(), raw_doc::<RecordQueryRequest>(keyed(false))).await;
        let record = &v1_out["records"][0];
        assert_eq!(record["record_type"], "authorization");
        assert!(
            record.get("valid_from").is_none() && record.get("validFrom").is_none(),
            "{record}"
        );
    }

    #[tokio::test]
    async fn v2_delete_uses_camel_case_members() {
        let out = answer(
            MockRepo::default(),
            raw_doc::<v2::RecordDeleteRequest>(serde_json::json!({
                "entityId": "e", "authorityId": "a", "action": "x", "resource": "r",
            })),
        )
        .await;
        assert_eq!(out["ok"], true);
    }

    #[tokio::test]
    async fn the_old_spelling_is_refused_at_the_new_version() {
        let dispatcher = build_dispatcher(Arc::new(windowed_repo()));
        let snake = serde_json::json!({
            "entity_id": "did:example:entity",
            "authority_id": "did:example:authority",
            "action": "issue",
            "resource": "vc",
        });
        let err = handle_document(&dispatcher, raw_doc::<v2::AuthorizationRequest>(snake))
            .await
            .expect_err("snake_case at 0.2 is malformed");
        assert_eq!(err.payload.code.to_string(), "malformedRequest");
    }
}
