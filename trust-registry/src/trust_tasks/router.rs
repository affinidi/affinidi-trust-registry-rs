//! The `registry/*` Trust Task handlers and the dispatchers that route to them.
//!
//! [`build_dispatcher`] and [`build_query_dispatcher`] register the registry's
//! own tasks on a [`trust_tasks_rs::Dispatcher`] whose handlers call the
//! [`TrustRecordRepository`]/[`TrustRecordAdminRepository`]. The
//! [`CapabilitySet`](crate::capabilities::CapabilitySet) composes them with the
//! governance surface and the enabled capabilities into the live dispatchers.
//!
//! Nothing here checks who is asking. Party resolution, proofs, the admin list,
//! the authority binding, the replay record and the audit entry are applied
//! before dispatch, for every transport, by
//! [`TaskHandler`](crate::trust_tasks::TaskHandler); see the numbered list in
//! [`crate::trust_tasks::handler`]. What each task needs of that pipeline is in
//! [`crate::trust_tasks::descriptor`].
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

use affinidi_did_common::scid::strip_scid_src;
use chrono::{DateTime, Utc};
use futures::future::BoxFuture;
use serde::Serialize;
use serde::de::DeserializeOwned;
use serde_json::Value;
use trust_tasks_rs::{Dispatcher, ErrorResponse, Payload, RejectReason, TrustTask};
use uuid::Uuid;

use crate::domain::{Action, AuthorityId, EntityId, Resource};
use crate::domain::{Evaluation, TrustRecord};
use crate::storage::repository::{
    RepositoryError, TrustRecordAdminRepository, TrustRecordQuery, TrustRecordRepository,
    find_either_spelling,
};

use super::descriptor::{TaskError, spec_error};
use super::payloads::{
    AuthorizationRequest, AuthorizationResponse, AuthorizationResponseMessage, RecognitionRequest,
    RecognitionResponse, RecognitionResponseMessage, RecordDeleteRequest, RecordDeleteResponse,
    RecordPutRequest, RecordPutResponse, RecordQueryRequest, RecordQueryResponse, camel,
    query_as_written, query_of, record_from_v1, record_from_v2, record_to_v1, record_to_v2,
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

/// A fresh document identifier for a reply.
pub(crate) fn new_id() -> String {
    Uuid::new_v4().to_string()
}

/// Map a repository error to the closest framework [`RejectReason`].
///
/// A missing or already-present record is `taskFailed` here; a task whose
/// specification declares codes of its own for those answers through
/// [`reject_repo_err`] instead.
pub(crate) fn map_repo_err(err: RepositoryError) -> RejectReason {
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

/// The error response for a repository error from `doc`'s task: a missing or
/// already-present record is answered with the extension code the task's
/// specification declares for it (`registry/record/put:alreadyExists`,
/// `registry/record/delete:notFound`, ...), anything else as
/// [`map_repo_err`] maps it.
pub(crate) fn reject_repo_err<P>(doc: &TrustTask<P>, err: RepositoryError) -> ErrorResponse {
    match err {
        RepositoryError::RecordNotFound(message) => spec_error(doc, TaskError::NotFound, message),
        RepositoryError::RecordAlreadyExists(message) => {
            spec_error(doc, TaskError::AlreadyExists, message)
        }
        other => doc.reject_with(new_id(), map_repo_err(other)),
    }
}

/// Build a success response document from a serialisable payload, or an
/// internal-error response if serialisation fails.
pub(crate) fn respond<P, T: Serialize>(doc: &TrustTask<P>, payload: T) -> TaskOutcome {
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
pub(crate) fn reject_build_err<P>(
    doc: &TrustTask<P>,
    err: impl std::fmt::Display,
) -> ErrorResponse {
    doc.reject_with(
        new_id(),
        RejectReason::InternalError {
            reason: format!("could not build response payload: {err}"),
        },
    )
}

/// Register the handler `$handler::<_, $payload>` for `$payload` over `$repo`.
macro_rules! register {
    ($dispatcher:expr, $repo:expr, $payload:ty, $handler:ident) => {{
        let repo = $repo.clone();
        $dispatcher.on::<$payload, _>(move |doc| -> TaskFuture {
            Box::pin($handler::<_, $payload>(repo.clone(), doc))
        })
    }};
}

/// Build a [`RegistryDispatcher`] over `repository`: the reads of
/// [`build_query_dispatcher`] plus record put, delete and query, at every
/// version served. (`registry/did/rotate` is executed by the
/// [`TaskHandler`](crate::trust_tasks::TaskHandler) itself.)
pub fn build_dispatcher<R>(repository: Arc<R>) -> RegistryDispatcher
where
    R: TrustRecordAdminRepository + ?Sized + 'static,
{
    let dispatcher = build_query_dispatcher(repository.clone());
    let dispatcher = register!(dispatcher, repository, RecordPutRequest, handle_put);
    let dispatcher = register!(dispatcher, repository, camel::RecordPutRequest, handle_put);
    let dispatcher = register!(dispatcher, repository, RecordQueryRequest, handle_query);
    let dispatcher = register!(
        dispatcher,
        repository,
        camel::RecordQueryRequest,
        handle_query
    );
    let dispatcher = register!(dispatcher, repository, RecordDeleteRequest, handle_delete);
    register!(
        dispatcher,
        repository,
        camel::RecordDeleteRequest,
        handle_delete
    )
}

/// Build a read-only [`RegistryDispatcher`] over `repository`.
///
/// Registers only the public TRQP queries (`registry/recognition` and
/// `registry/authorization`, every version served), which need just
/// [`TrustRecordRepository`]. It is the base of the read-only surface (the
/// HTTP binding, or a host serving callers it does not authenticate), which
/// never carries record put, delete or query.
pub fn build_query_dispatcher<R>(repository: Arc<R>) -> RegistryDispatcher
where
    R: TrustRecordRepository + ?Sized + 'static,
{
    let dispatcher = Dispatcher::new();
    let dispatcher = register!(dispatcher, repository, RecognitionRequest, handle_trqp);
    let dispatcher = register!(
        dispatcher,
        repository,
        camel::RecognitionRequest,
        handle_trqp
    );
    let dispatcher = register!(dispatcher, repository, AuthorizationRequest, handle_trqp);
    register!(
        dispatcher,
        repository,
        camel::AuthorizationRequest,
        handle_trqp
    )
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
// Each task has one generic handler, written against a small trait that each
// served version's generated payload implements: the trait reads that
// version's payload and builds its response. The versions differ only in wire
// spelling (and, for records, whether the validity window can be carried),
// never in what the registry decides.

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
    let record = find_either_spelling(
        repository,
        TrustRecordQuery::new(
            EntityId::as_written(ids.0),
            AuthorityId::as_written(ids.1),
            Action::new(ids.2),
            Resource::new(ids.3),
        ),
    )
    .await?;
    let evaluation = Evaluation::of(record.as_ref(), asked, Utc::now());
    Ok((record, evaluation))
}

/// Which of the two TRQP questions a query asks.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Question {
    Recognized,
    Authorized,
}

/// The advisory `message`. The spec caps it at 1024 characters, so an answer
/// whose message would exceed that (pathologically long identifiers) goes
/// without one rather than failing on a field nothing decides on.
fn query_message<M>(
    record: Option<&TrustRecord>,
    evaluation: &Evaluation,
    question: Question,
) -> Option<M>
where
    M: TryFrom<String>,
{
    let tr = record?;
    let verb = match question {
        Question::Recognized => "recognized",
        Question::Authorized => "authorized",
    };
    let text = match evaluation.out_of_window_reason(tr) {
        Some(reason) => format!(
            "{} not {verb} by {}: {reason}",
            tr.entity_id().as_str(),
            tr.authority_id().as_str()
        ),
        None if question == Question::Authorized => format!(
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

/// One version of a TRQP query (`registry/recognition`,
/// `registry/authorization`).
trait TrqpWire: Payload + Send + 'static {
    const QUESTION: Question;
    /// The four identifiers asked about.
    fn ids(&self) -> (&str, &str, &str, &str);
    /// The instant asked about, if any.
    fn asked(&self) -> Option<DateTime<Utc>>;
    /// This version's response: the identifiers echoed, the answer, when it
    /// was evaluated and the instant asked about, and the advisory message.
    fn response(
        &self,
        holds: bool,
        asked: Option<DateTime<Utc>>,
        message: Option<String>,
    ) -> Result<impl Serialize, String>;
}

/// [`TrqpWire`] for one version. `$evaluated`/`$asked` are the builder
/// setters for that version's two time members (`time_evaluated` /
/// `time_requested` in 0.1, `evaluated_at` / `as_of` in 0.2).
macro_rules! trqp_wire {
    ($req:ty, $resp:ty, $msg:ty, $question:ident, $flag:ident, $evaluated:ident, $asked:ident) => {
        impl TrqpWire for $req {
            const QUESTION: Question = Question::$question;
            fn ids(&self) -> (&str, &str, &str, &str) {
                (
                    &self.entity_id,
                    &self.authority_id,
                    &self.action,
                    &self.resource,
                )
            }
            fn asked(&self) -> Option<DateTime<Utc>> {
                self.context.as_ref().and_then(|c| c.time)
            }
            fn response(
                &self,
                holds: bool,
                asked: Option<DateTime<Utc>>,
                message: Option<String>,
            ) -> Result<impl Serialize, String> {
                let message: Option<$msg> = message.and_then(|m| m.try_into().ok());
                let response: Result<$resp, _> = <$resp>::builder()
                    .entity_id(self.entity_id.clone())
                    .authority_id(self.authority_id.clone())
                    .action(self.action.clone())
                    .resource(self.resource.clone())
                    .$flag(holds)
                    .$evaluated(Utc::now())
                    .$asked(asked)
                    .message(message)
                    .try_into();
                response.map_err(|e| e.to_string())
            }
        }
    };
}

trqp_wire!(
    RecognitionRequest,
    RecognitionResponse,
    RecognitionResponseMessage,
    Recognized,
    recognized,
    time_evaluated,
    time_requested
);
trqp_wire!(
    AuthorizationRequest,
    AuthorizationResponse,
    AuthorizationResponseMessage,
    Authorized,
    authorized,
    time_evaluated,
    time_requested
);
trqp_wire!(
    camel::RecognitionRequest,
    camel::RecognitionResponse,
    camel::RecognitionResponseMessage,
    Recognized,
    recognized,
    evaluated_at,
    as_of
);
trqp_wire!(
    camel::AuthorizationRequest,
    camel::AuthorizationResponse,
    camel::AuthorizationResponseMessage,
    Authorized,
    authorized,
    evaluated_at,
    as_of
);

/// `registry/recognition` and `registry/authorization`, every version.
async fn handle_trqp<R, P>(repository: Arc<R>, doc: TrustTask<P>) -> TaskOutcome
where
    R: TrustRecordRepository + ?Sized + 'static,
    P: TrqpWire,
{
    let p = &doc.payload;
    let asked = p.asked();
    let (record, evaluation) = match evaluate_query(repository.as_ref(), p.ids(), asked).await {
        Ok(found) => found,
        Err(e) => return Err(doc.reject_with(new_id(), map_repo_err(e))),
    };
    // Outside its window, a record answers false whatever it stores.
    let holds = evaluation.in_window()
        && record.as_ref().is_some_and(|tr| match P::QUESTION {
            Question::Recognized => tr.is_recognized(),
            Question::Authorized => tr.is_authorized(),
        });
    let message: Option<String> = query_message(record.as_ref(), &evaluation, P::QUESTION);
    let response = p
        .response(holds, asked, message)
        .map_err(|e| reject_build_err(&doc, e))?;
    respond(&doc, response)
}

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

/// One version of `registry/record/put`.
trait PutWire: Payload + Send + 'static {
    /// The record to store, refused as malformed when it cannot be one.
    fn record(&self) -> Result<TrustRecord, String>;
    fn expected_existing(&self) -> Option<bool>;
    fn response(created: bool) -> Result<impl Serialize, String>;
}

/// `registry/record/put/0.1`. The record has no validity window, so a put
/// replaces any window the stored record had.
impl PutWire for RecordPutRequest {
    fn record(&self) -> Result<TrustRecord, String> {
        record_from_v1(&self.record)
    }
    fn expected_existing(&self) -> Option<bool> {
        self.expected_existing
    }
    fn response(created: bool) -> Result<impl Serialize, String> {
        let response: Result<RecordPutResponse, _> = RecordPutResponse::builder()
            .ok(true)
            .created(created)
            .try_into();
        response.map_err(|e| e.to_string())
    }
}

/// `registry/record/put/0.3`: lowerCamelCase, with the optional validity
/// window. A window whose `validFrom` is not before its `validUntil` is
/// refused as `malformedRequest`.
impl PutWire for camel::RecordPutRequest {
    fn record(&self) -> Result<TrustRecord, String> {
        record_from_v2(&self.record)
    }
    fn expected_existing(&self) -> Option<bool> {
        self.expected_existing
    }
    fn response(created: bool) -> Result<impl Serialize, String> {
        let response: Result<camel::RecordPutResponse, _> = camel::RecordPutResponse::builder()
            .ok(true)
            .was_created(created)
            .try_into();
        response.map_err(|e| e.to_string())
    }
}

async fn handle_put<R, P>(repository: Arc<R>, doc: TrustTask<P>) -> TaskOutcome
where
    R: TrustRecordAdminRepository + ?Sized + 'static,
    P: PutWire,
{
    let record = doc
        .payload
        .record()
        .map_err(|reason| doc.reject_with(new_id(), RejectReason::MalformedRequest { reason }))?;
    match put_record(repository.as_ref(), record, doc.payload.expected_existing()).await {
        Ok(created) => {
            let response = P::response(created).map_err(|e| reject_build_err(&doc, e))?;
            respond(&doc, response)
        }
        Err(e) => Err(reject_repo_err(&doc, e)),
    }
}

/// One version of `registry/record/delete`.
trait DeleteWire: Payload + Send + 'static {
    /// The four-part key of the record to delete.
    fn key(&self) -> (&str, &str, &str, &str);
    fn response() -> Result<impl Serialize, String>;
}

macro_rules! delete_wire {
    ($req:ty, $resp:ty) => {
        impl DeleteWire for $req {
            fn key(&self) -> (&str, &str, &str, &str) {
                (
                    &self.entity_id,
                    &self.authority_id,
                    &self.action,
                    &self.resource,
                )
            }
            fn response() -> Result<impl Serialize, String> {
                let response: Result<$resp, _> = <$resp>::builder().ok(true).try_into();
                response.map_err(|e| e.to_string())
            }
        }
    };
}

delete_wire!(RecordDeleteRequest, RecordDeleteResponse);
delete_wire!(camel::RecordDeleteRequest, camel::RecordDeleteResponse);

async fn handle_delete<R, P>(repository: Arc<R>, doc: TrustTask<P>) -> TaskOutcome
where
    R: TrustRecordAdminRepository + ?Sized + 'static,
    P: DeleteWire,
{
    let (entity_id, authority_id, action, resource) = doc.payload.key();
    let query = query_of(entity_id, authority_id, action, resource);
    let deleted = match repository.delete(query).await {
        Err(RepositoryError::RecordNotFound(missing)) => {
            match query_as_written(entity_id, authority_id, action, resource) {
                Some(as_written) => repository.delete(as_written).await,
                None => Err(RepositoryError::RecordNotFound(missing)),
            }
        }
        other => other,
    };
    match deleted {
        Ok(()) => {
            let response = P::response().map_err(|e| reject_build_err(&doc, e))?;
            respond(&doc, response)
        }
        Err(e) => Err(reject_repo_err(&doc, e)),
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
) -> Result<(Vec<TrustRecord>, Option<String>), QueryFailure>
where
    R: TrustRecordAdminRepository + ?Sized,
{
    // Fully keyed: an exact fetch of the single record, notFound on a miss.
    if let (Some(entity_id), Some(authority_id), Some(action), Some(resource)) =
        (f.entity_id, f.authority_id, f.action, f.resource)
    {
        let query = query_of(entity_id, authority_id, action, resource);
        let found = match repository.read(query).await {
            Err(RepositoryError::RecordNotFound(missing)) => {
                match query_as_written(entity_id, authority_id, action, resource) {
                    Some(as_written) => repository.read(as_written).await,
                    None => Err(RepositoryError::RecordNotFound(missing)),
                }
            }
            other => other,
        };
        return found
            .map(|record| (vec![record], None))
            .map_err(QueryFailure::Repository);
    }

    // Partially keyed (or unkeyed): filtered, paginated enumeration.
    let offset: usize = match f.cursor {
        None => 0,
        Some(cursor) => cursor.parse().map_err(|_| {
            QueryFailure::Rejected(RejectReason::MalformedRequest {
                reason: "unrecognized cursor".to_string(),
            })
        })?,
    };
    let limit = f
        .limit
        .map_or(QUERY_DEFAULT_LIMIT, |l| {
            usize::try_from(l).unwrap_or(usize::MAX)
        })
        .clamp(1, QUERY_MAX_LIMIT);

    // The repository reads only what the filter can match where its backend
    // allows (a key-prefix scan from the authority); the filter below is
    // applied again regardless.
    let list = repository
        .list_matching(&crate::storage::repository::TrustRecordFilter {
            entity_id: f.entity_id.map(crate::domain::EntityId::new),
            authority_id: f.authority_id.map(crate::domain::AuthorityId::new),
            action: f.action.map(crate::domain::Action::new),
            resource: f.resource.map(crate::domain::Resource::new),
        })
        .await
        .map_err(QueryFailure::Repository)?;
    // Compared in the normalised form records are stored in, so a filter
    // naming a did:scid with its `?src=` locator matches, and so does a
    // record stored with one before references were normalised.
    let field_matches = |filter: Option<&str>, value: &str| {
        filter.is_none_or(|wanted| strip_scid_src(wanted) == strip_scid_src(value))
    };
    // A stored record the backend could not decode fails the query only if it
    // could be one of the matches: answering without it would silently drop a
    // result. One that cannot match is left out (the adapter logged it). The
    // reason names no key: the record may belong to another authority.
    let unreadable_could_match = list.unreadable().iter().any(|unreadable| {
        unreadable.could_match(|key| {
            field_matches(f.entity_id, key.entity_id().as_str())
                && field_matches(f.authority_id, key.authority_id().as_str())
                && field_matches(f.action, key.action().as_str())
                && field_matches(f.resource, key.resource().as_str())
        })
    });
    if unreadable_could_match {
        return Err(QueryFailure::Rejected(RejectReason::InternalError {
            reason: "a stored record that may match this query could not be read".to_string(),
        }));
    }
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

/// Why [`query_records`] could not answer.
#[derive(Debug)]
enum QueryFailure {
    Repository(RepositoryError),
    Rejected(RejectReason),
}

/// One version of `registry/record/query`.
trait QueryWire: Payload + Send + 'static {
    /// The record in this version's wire form.
    type Record: DeserializeOwned;
    fn filter(&self) -> RecordFilter<'_>;
    fn to_wire(record: &TrustRecord) -> Result<Self::Record, String>;
    fn response(
        records: Vec<Self::Record>,
        next_cursor: Option<String>,
    ) -> Result<impl Serialize, String>;
}

/// [`QueryWire`] for one version. `$to_wire` is the record mapping: 0.1
/// records have no validity window, so a stored window is left out of the
/// answer; 0.3 records are lowerCamelCase, window included.
macro_rules! query_wire {
    ($req:ty, $resp:ty, $record:ty, $to_wire:ident) => {
        impl QueryWire for $req {
            type Record = $record;
            fn filter(&self) -> RecordFilter<'_> {
                RecordFilter {
                    entity_id: self.entity_id.as_deref(),
                    authority_id: self.authority_id.as_deref(),
                    action: self.action.as_deref(),
                    resource: self.resource.as_deref(),
                    cursor: self.cursor.as_deref(),
                    limit: self.limit.map(|l| l.get()),
                }
            }
            fn to_wire(record: &TrustRecord) -> Result<Self::Record, String> {
                $to_wire(record)
            }
            fn response(
                records: Vec<Self::Record>,
                next_cursor: Option<String>,
            ) -> Result<impl Serialize, String> {
                let response: Result<$resp, _> = <$resp>::builder()
                    .records(records)
                    .next_cursor(next_cursor)
                    .try_into();
                response.map_err(|e| e.to_string())
            }
        }
    };
}

query_wire!(
    RecordQueryRequest,
    RecordQueryResponse,
    crate::specs::registry::record::query::v0_1::TrustRecord,
    record_to_v1
);
query_wire!(
    camel::RecordQueryRequest,
    camel::RecordQueryResponse,
    crate::specs::registry::record::query::v0_3::TrustRecord,
    record_to_v2
);

async fn handle_query<R, P>(repository: Arc<R>, doc: TrustTask<P>) -> TaskOutcome
where
    R: TrustRecordAdminRepository + ?Sized + 'static,
    P: QueryWire,
{
    let (page, next_cursor) = query_records(repository.as_ref(), doc.payload.filter())
        .await
        .map_err(|failure| match failure {
            QueryFailure::Repository(e) => reject_repo_err(&doc, e),
            QueryFailure::Rejected(reason) => doc.reject_with(new_id(), reason),
        })?;
    let records = page
        .iter()
        .map(P::to_wire)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|reason| doc.reject_with(new_id(), RejectReason::InternalError { reason }))?;
    let response = P::response(records, next_cursor).map_err(|e| reject_build_err(&doc, e))?;
    respond(&doc, response)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;
    use crate::domain::{
        Action, AuthorityId, EntityId, RecordType, Resource, TrustRecord, TrustRecordBuilder,
    };
    use crate::storage::repository::{TrustRecordList, TrustRecordQuery, UnreadableRecord};
    use std::sync::Mutex;
    use trust_tasks_rs::Payload;

    #[derive(Default)]
    struct MockRepo {
        record: Option<TrustRecord>,
        /// Extra records returned by `list` (after `record`), for enumeration
        /// and pagination tests.
        listing: Vec<TrustRecord>,
        /// Stored values `list` reports as undecodable.
        unreadable: Vec<UnreadableRecord>,
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
            Ok(TrustRecordList::with_unreadable(
                self.record
                    .clone()
                    .into_iter()
                    .chain(self.listing.iter().cloned())
                    .collect(),
                self.unreadable.clone(),
            ))
        }
        async fn read(&self, _query: TrustRecordQuery) -> Result<TrustRecord, RepositoryError> {
            self.record
                .clone()
                .ok_or_else(|| RepositoryError::RecordNotFound("none".into()))
        }
    }

    fn filter<'a>(authority_id: Option<&'a str>, action: Option<&'a str>) -> RecordFilter<'a> {
        RecordFilter {
            entity_id: None,
            authority_id,
            action,
            resource: None,
            cursor: None,
            limit: None,
        }
    }

    /// An undecodable stored record fails a query it could match, and only
    /// such a query; the reason never names its key.
    #[tokio::test]
    async fn an_unreadable_record_fails_only_a_query_it_could_match() {
        let other = crate::domain::key::TrustRecordKey::from_record(
            &TrustRecordBuilder::new()
                .entity_id(EntityId::new("did:example:e"))
                .authority_id(AuthorityId::new("did:example:other#authority"))
                .action(Action::new("issue"))
                .resource(Resource::new("vc"))
                .recognized(true)
                .authorized(true)
                .record_type(RecordType::Authorization)
                .build()
                .expect("valid record"),
        )
        .sk();
        let repo = MockRepo {
            record: Some(sample_record()),
            unreadable: vec![UnreadableRecord::new(other.clone())],
            ..Default::default()
        };

        // A query for another authority answers without it.
        let (page, _) = query_records(&repo, filter(Some("did:example:authority"), None))
            .await
            .expect("answered");
        assert_eq!(page, vec![sample_record()]);

        // A query it could match fails, without naming its key.
        for could_match in [
            filter(Some("did:example:other#authority"), None),
            filter(None, Some("issue")),
            filter(None, None),
        ] {
            match query_records(&repo, could_match).await {
                Err(QueryFailure::Rejected(RejectReason::InternalError { reason })) => {
                    assert!(!reason.contains("other"), "{reason}");
                }
                other => panic!("expected an internal error, got {other:?}"),
            }
        }

        // A key that does not decode could be anything: fail closed.
        let repo = MockRepo {
            record: Some(sample_record()),
            unreadable: vec![UnreadableRecord::new("TR#not-a-key")],
            ..Default::default()
        };
        assert!(
            query_records(&repo, filter(Some("did:example:authority"), None))
                .await
                .is_err()
        );
    }

    /// Answers only filtered listings, recording each filter; a full listing
    /// fails the test.
    #[derive(Default)]
    struct FilterOnlyRepo {
        records: Vec<TrustRecord>,
        asked: Mutex<Vec<crate::storage::repository::TrustRecordFilter>>,
    }

    #[async_trait::async_trait]
    impl TrustRecordRepository for FilterOnlyRepo {
        async fn find_by_query(
            &self,
            _query: TrustRecordQuery,
        ) -> Result<Option<TrustRecord>, RepositoryError> {
            Ok(None)
        }
    }

    #[async_trait::async_trait]
    impl TrustRecordAdminRepository for FilterOnlyRepo {
        async fn create(&self, _record: TrustRecord) -> Result<(), RepositoryError> {
            Ok(())
        }
        async fn update(&self, _record: TrustRecord) -> Result<(), RepositoryError> {
            Ok(())
        }
        async fn delete(&self, _query: TrustRecordQuery) -> Result<(), RepositoryError> {
            Ok(())
        }
        async fn list(&self) -> Result<TrustRecordList, RepositoryError> {
            panic!("a filtered query must not enumerate every record");
        }
        async fn list_matching(
            &self,
            filter: &crate::storage::repository::TrustRecordFilter,
        ) -> Result<TrustRecordList, RepositoryError> {
            self.asked.lock().unwrap().push(filter.clone());
            Ok(TrustRecordList::new(
                self.records
                    .iter()
                    .filter(|record| filter.matches(record))
                    .cloned()
                    .collect(),
            ))
        }
    }

    /// #216: the query passes its filter down rather than loading the whole
    /// store and filtering after the fact.
    #[tokio::test]
    async fn a_partially_keyed_query_passes_its_filter_to_the_repository() {
        let other_authority = TrustRecordBuilder::new()
            .entity_id(EntityId::new("did:example:entity"))
            .authority_id(AuthorityId::new("did:example:other"))
            .action(Action::new("issue"))
            .resource(Resource::new("vc"))
            .recognized(true)
            .authorized(true)
            .record_type(RecordType::Authorization)
            .build()
            .expect("valid record");
        let repo = FilterOnlyRepo {
            records: vec![sample_record(), other_authority],
            ..Default::default()
        };

        let (page, next) =
            query_records(&repo, filter(Some("did:example:authority"), Some("issue")))
                .await
                .expect("answered");
        assert_eq!(page, vec![sample_record()]);
        assert_eq!(next, None);
        assert_eq!(
            *repo.asked.lock().unwrap(),
            vec![crate::storage::repository::TrustRecordFilter {
                authority_id: Some(AuthorityId::new("did:example:authority")),
                action: Some(Action::new("issue")),
                ..Default::default()
            }]
        );
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
            raw_doc::<camel::AuthorizationRequest>(v2_query(Some("2026-06-01T00:00:00Z"))),
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
                raw_doc::<camel::AuthorizationRequest>(v2_query(Some(time))),
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
            raw_doc::<camel::RecognitionRequest>(v2_query(Some("2025-12-31T23:59:30Z"))),
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
            raw_doc::<camel::RecordPutRequest>(serde_json::json!({
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
            raw_doc::<camel::RecordPutRequest>(serde_json::json!({
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
            raw_doc::<camel::RecordQueryRequest>(keyed(true)),
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
            raw_doc::<camel::RecordDeleteRequest>(serde_json::json!({
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
        let err = handle_document(&dispatcher, raw_doc::<camel::AuthorizationRequest>(snake))
            .await
            .expect_err("snake_case at 0.2 is malformed");
        assert_eq!(err.payload.code.to_string(), "malformedRequest");
    }

    // --- the specifications' own error codes ----------------------------------

    fn snake_record() -> Value {
        serde_json::json!({
            "entity_id": "did:example:entity", "authority_id": "did:example:authority",
            "action": "issue", "resource": "vc", "record_type": "authorization",
            "recognized": true, "authorized": true,
        })
    }

    fn camel_record() -> Value {
        serde_json::json!({
            "entityId": "did:example:entity", "authorityId": "did:example:authority",
            "action": "issue", "resource": "vc", "recordType": "authorization",
            "recognized": true, "authorized": true,
        })
    }

    async fn code_of(dispatcher: &RegistryDispatcher, doc: TrustTask<Value>) -> (String, bool) {
        let err = handle_document(dispatcher, doc).await.expect_err("refused");
        (err.payload.code.to_string(), err.payload.retryable)
    }

    #[tokio::test]
    async fn a_strict_put_answers_the_put_specifications_codes() {
        use crate::storage::adapters::local_storage::LocalStorage;
        for camel_case in [false, true] {
            let dispatcher = build_dispatcher(Arc::new(LocalStorage::new()));
            let put = |expected: bool| {
                if camel_case {
                    raw_doc::<camel::RecordPutRequest>(serde_json::json!({
                        "record": camel_record(), "expectedExisting": expected,
                    }))
                } else {
                    raw_doc::<RecordPutRequest>(serde_json::json!({
                        "record": snake_record(), "expectedExisting": expected,
                    }))
                }
            };
            assert_eq!(
                code_of(&dispatcher, put(true)).await,
                ("registry/record/put:notFound".to_string(), false),
                "camel case: {camel_case}"
            );
            handle_document(&dispatcher, put(false))
                .await
                .expect("created");
            assert_eq!(
                code_of(&dispatcher, put(false)).await,
                ("registry/record/put:alreadyExists".to_string(), false),
                "camel case: {camel_case}"
            );
        }
    }

    #[tokio::test]
    async fn a_delete_or_keyed_query_of_a_missing_record_answers_not_found() {
        use crate::storage::adapters::local_storage::LocalStorage;
        let dispatcher = build_dispatcher(Arc::new(LocalStorage::new()));
        let snake_key = serde_json::json!({
            "entity_id": "e", "authority_id": "a", "action": "x", "resource": "r",
        });
        let camel_key = serde_json::json!({
            "entityId": "e", "authorityId": "a", "action": "x", "resource": "r",
        });
        for (doc, expected) in [
            (
                raw_doc::<RecordDeleteRequest>(snake_key.clone()),
                "registry/record/delete:notFound",
            ),
            (
                raw_doc::<camel::RecordDeleteRequest>(camel_key.clone()),
                "registry/record/delete:notFound",
            ),
            (
                raw_doc::<RecordQueryRequest>(snake_key),
                "registry/record/query:notFound",
            ),
            (
                raw_doc::<camel::RecordQueryRequest>(camel_key),
                "registry/record/query:notFound",
            ),
        ] {
            assert_eq!(
                code_of(&dispatcher, doc).await,
                (expected.to_string(), false)
            );
        }
    }

    /// A record an earlier release stored under a did:scid with its locator
    /// is still answered, fetched and deleted by the spelling it was stored
    /// under.
    #[tokio::test]
    async fn a_record_stored_with_a_locator_is_reached_by_that_spelling() {
        use crate::storage::adapters::local_storage::LocalStorage;
        const LOCATED: &str = "did:scid:vh:1:abc?src=example.com";
        let repo = Arc::new(LocalStorage::new());
        repo.create(TrustRecord::new(
            EntityId::new("did:example:entity"),
            AuthorityId::as_written(LOCATED),
            Action::new("issue"),
            Resource::new("vc"),
            true,
            true,
            crate::domain::Context::empty(),
            RecordType::Authorization,
        ))
        .await
        .unwrap();
        let dispatcher = build_dispatcher(repo);
        let key = serde_json::json!({
            "entityId": "did:example:entity", "authorityId": LOCATED,
            "action": "issue", "resource": "vc",
        });

        let out = handle_document(
            &dispatcher,
            raw_doc::<camel::AuthorizationRequest>(key.clone()),
        )
        .await
        .expect("answered");
        assert_eq!(out.payload["authorized"], true);
        handle_document(
            &dispatcher,
            raw_doc::<camel::RecordQueryRequest>(key.clone()),
        )
        .await
        .expect("fetched");
        handle_document(
            &dispatcher,
            raw_doc::<camel::RecordDeleteRequest>(key.clone()),
        )
        .await
        .expect("deleted");
        assert_eq!(
            code_of(&dispatcher, raw_doc::<camel::RecordDeleteRequest>(key)).await,
            ("registry/record/delete:notFound".to_string(), false)
        );
    }

    /// A record stored, or a filter written, with a did:scid `?src=` locator
    /// is the same reference as the bare DID.
    #[tokio::test]
    async fn a_did_scid_locator_does_not_split_an_authority() {
        use crate::storage::adapters::local_storage::LocalStorage;
        let dispatcher = build_dispatcher(Arc::new(LocalStorage::new()));
        let mut record = camel_record();
        record["authorityId"] = serde_json::json!("did:scid:vh:1:abc?src=example.com");
        handle_document(
            &dispatcher,
            raw_doc::<camel::RecordPutRequest>(serde_json::json!({ "record": record })),
        )
        .await
        .expect("stored");

        let out = handle_document(
            &dispatcher,
            raw_doc::<camel::AuthorizationRequest>(serde_json::json!({
                "entityId": "did:example:entity", "authorityId": "did:scid:vh:1:abc",
                "action": "issue", "resource": "vc",
            })),
        )
        .await
        .expect("answered");
        assert_eq!(
            out.payload["authorized"], true,
            "the bare DID finds it: {}",
            out.payload
        );

        for authority in ["did:scid:vh:1:abc", "did:scid:vh:1:abc?src=other.example"] {
            let out = handle_document(
                &dispatcher,
                raw_doc::<camel::RecordQueryRequest>(serde_json::json!({
                    "authorityId": authority,
                })),
            )
            .await
            .expect("answered");
            assert_eq!(out.payload["records"].as_array().unwrap().len(), 1);
            assert_eq!(
                out.payload["records"][0]["authorityId"], "did:scid:vh:1:abc",
                "stored in its normalised form"
            );
        }
    }
}
