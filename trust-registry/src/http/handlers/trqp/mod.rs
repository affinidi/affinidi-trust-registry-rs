//! The TRQP v2.0 REST endpoints, `POST /authorization` and `POST /recognition`.
//!
//! Each answers one question about one stored record, decided by
//! [`Evaluation::answer`], the same decision the `registry/*` Trust Tasks and
//! the DIDComm `trqp/1.0` protocol use, so the surfaces cannot disagree:
//!
//! - the queried flag (`authorized` on `/authorization`, `recognized` on
//!   `/recognition`) is always present and always a boolean. It is `true`
//!   only when the record is inside its validity window and stores `true`; a
//!   stored `false`, or no stored value, answers `false` (R3.4). The other
//!   flag is not part of the answer and is not sent;
//! - `message` follows that answer;
//! - `context` is the record's stored context, exactly as stored. The
//!   request's `context` is read (for `context.time`) but never merged into
//!   the answer or echoed, as on the Trust Task answers, so nothing in the
//!   response is attributed to the registry that it does not hold.
//!
//! The identifiers are validated with the domain's own rules
//! ([`crate::domain::parse_ids`]) before the lookup, so an invalid one is a
//! `400` rather than the `404` that means "valid but not recognised".

use crate::{
    domain::{
        Action, Answer, AuthorityId, Context, EntityId, Evaluation, Question, RecordType, Resource,
        TrustRecord, parse_ids,
    },
    storage::repository::{TrustRecordQuery, TrustRecordRepository, find_either_spelling},
};
use axum::{
    Json,
    extract::{State, rejection::JsonRejection},
};
use chrono::{DateTime, SecondsFormat, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::SharedData;
use crate::http::error::AppError;

/// The members every TRQP answer carries, besides its one flag.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct AnswerFields {
    pub entity_id: EntityId,
    pub authority_id: AuthorityId,
    pub action: Action,
    pub resource: Resource,
    /// The stored record's context, as stored.
    pub context: Context,
    pub record_type: RecordType,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub valid_from: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub valid_until: Option<DateTime<Utc>>,
    pub time_requested: String,
    pub time_evaluated: String,
    pub message: String,
}

/// The `POST /authorization` answer: `authorized` is always present.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct AuthorizationAnswer {
    #[serde(flatten)]
    pub fields: AnswerFields,
    pub authorized: bool,
}

/// The `POST /recognition` answer: `recognized` is always present.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct RecognitionAnswer {
    #[serde(flatten)]
    pub fields: AnswerFields,
    pub recognized: bool,
}

/// A TRQP query as sent. The identifiers are plain strings here and are
/// validated with [`parse_ids`] before the lookup, so a bad one is named in
/// the `400`.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct InputDto {
    pub entity_id: String,
    pub authority_id: String,
    pub action: String,
    pub resource: String,
    pub context: Option<Context>,
}

/// A TRQP query that passed validation.
struct ValidQuery {
    query: TrustRecordQuery,
    /// `context.time`, when the client supplied one.
    time: Option<DateTime<Utc>>,
}

/// TRQP v2.0: `context`, when present, is a JSON object, and its `time` member
/// is an RFC 3339 date-time. A blank `time` is treated as absent, as the
/// `registry/*` Trust Task schema specifies.
fn validate_context(context: &Context) -> Result<Option<DateTime<Utc>>, AppError> {
    let Some(object) = context.as_value().as_object() else {
        return Err(AppError::InvalidRequest {
            detail: "`context` must be a JSON object".into(),
        });
    };
    match object.get("time") {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(s)) if s.trim().is_empty() => Ok(None),
        Some(Value::String(s)) => DateTime::parse_from_rfc3339(s)
            .map(|t| Some(t.with_timezone(&Utc)))
            .map_err(|e| AppError::InvalidRequest {
                detail: format!("`context.time` is not an RFC 3339 date-time: {e}"),
            }),
        Some(_) => Err(AppError::InvalidRequest {
            detail: "`context.time` must be an RFC 3339 date-time string".into(),
        }),
    }
}

fn validate(input: InputDto) -> Result<ValidQuery, AppError> {
    let (_, _, action, resource) = parse_ids(
        &input.entity_id,
        &input.authority_id,
        &input.action,
        &input.resource,
    )
    .map_err(|e| AppError::InvalidRequest {
        detail: e.to_string(),
    })?;
    let time = match &input.context {
        Some(c) => validate_context(c)?,
        None => None,
    };
    // Validated above. The party references go in as written so the lookup
    // ([`find_either_spelling`]) tries the normalised key first and can fall
    // back to a record stored under a did:scid `?src=` spelling.
    Ok(ValidQuery {
        query: TrustRecordQuery::new(
            EntityId::as_written(input.entity_id),
            AuthorityId::as_written(input.authority_id),
            action,
            resource,
        ),
        time,
    })
}

/// `time_requested` echoes `context.time` when the client sent one (the TRQP
/// response schema and the `registry/*` Trust Task schema both say so), and
/// falls back to the time the request arrived.
///
/// The answer is judged against the record's validity window as of that
/// instant; the registry keeps current records, not their history.
/// `time_evaluated` is the server time the answer was produced.
fn response_times(asked: Option<DateTime<Utc>>, received_at: DateTime<Utc>) -> (String, String) {
    let requested = asked.map_or_else(
        || received_at.to_rfc3339_opts(SecondsFormat::Secs, true),
        |t| t.to_rfc3339_opts(SecondsFormat::AutoSi, true),
    );
    let evaluated = Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true);
    (requested, evaluated)
}

/// Validate the query, find its record and answer `question` about it.
async fn answer<R>(
    state: SharedData<R>,
    payload: Result<Json<InputDto>, JsonRejection>,
    question: Question,
) -> Result<(AnswerFields, bool), AppError>
where
    R: TrustRecordRepository + Send + ?Sized + 'static,
{
    let received_at = Utc::now();
    let max_bytes = state.config.server_config.http_limits.max_body_bytes;
    let Json(input) = payload.map_err(|e| AppError::from_json_rejection(e, max_bytes))?;
    let query = validate(input)?;
    let record: TrustRecord = find_either_spelling(state.repository.as_ref(), query.query)
        .await
        .map_err(|e| AppError::Internal {
            internal_error: e.into(),
        })?
        .ok_or_else(|| AppError::NotFound {
            detail: "No trust record matches the four identifiers".into(),
        })?;

    let Answer { holds, message } =
        Evaluation::of(Some(&record), query.time, Utc::now()).answer(&record, question);
    let (time_requested, time_evaluated) = response_times(query.time, received_at);
    let fields = AnswerFields {
        entity_id: record.entity_id().clone(),
        authority_id: record.authority_id().clone(),
        action: record.action().clone(),
        resource: record.resource().clone(),
        context: record.context().clone(),
        record_type: record.record_type().clone(),
        valid_from: record.valid_from(),
        valid_until: record.valid_until(),
        time_requested,
        time_evaluated,
        message,
    };
    Ok((fields, holds))
}

pub async fn handle_trqp_authorization<R>(
    State(state): State<SharedData<R>>,
    payload: Result<Json<InputDto>, JsonRejection>,
) -> Result<Json<AuthorizationAnswer>, AppError>
where
    R: TrustRecordRepository + Send + ?Sized + 'static,
{
    let (fields, authorized) = answer(state, payload, Question::Authorized).await?;
    Ok(Json(AuthorizationAnswer { fields, authorized }))
}

pub async fn handle_trqp_recognition<R>(
    State(state): State<SharedData<R>>,
    payload: Result<Json<InputDto>, JsonRejection>,
) -> Result<Json<RecognitionAnswer>, AppError>
where
    R: TrustRecordRepository + Send + ?Sized + 'static,
{
    let (fields, recognized) = answer(state, payload, Question::Recognized).await?;
    Ok(Json(RecognitionAnswer { fields, recognized }))
}

#[cfg(test)]
mod tests {
    //! One test per row of the claim table in issue #161, run through the
    //! mountable router the way an embedding host uses it.

    use std::sync::Arc;

    use axum::body::{Body, to_bytes};
    use axum::http::{Request, StatusCode, header};
    use serde_json::{Value, json};
    use tower::ServiceExt;

    use crate::TrustRegistry;
    use crate::capabilities::MemoryCapabilityStore;
    use crate::configs::TrustRegistryConfig;
    use crate::domain::*;
    use crate::http::error::PROBLEM_JSON;
    use crate::storage::adapters::local_storage::LocalStorage;
    use crate::storage::repository::TrustRecordAdminRepository;

    const ENTITY: &str = "did:example:entity";
    const AUTHORITY: &str = "did:example:authority";
    const WINDOWED: &str = "did:example:windowed";
    const REVOKED: &str = "did:example:revoked";
    const RECOGNIZED_ONLY: &str = "did:example:recognized-only";
    const AUTHORIZED_ONLY: &str = "did:example:authorized-only";

    fn record(entity: &str) -> TrustRecord {
        TrustRecordBuilder::new()
            .entity_id(EntityId::new(entity))
            .authority_id(AuthorityId::new(AUTHORITY))
            .action(Action::new("issue"))
            .resource(Resource::new("vc"))
            .recognized(true)
            .authorized(true)
            .context(Context::new(json!({"seeded": "yes"})))
            .record_type(RecordType::Authorization)
            .build()
            .expect("valid record")
    }

    async fn app() -> axum::Router {
        app_with(TrustRegistryConfig::embedded("/tmp/tr-trqp-test")).await
    }

    async fn app_with(config: TrustRegistryConfig) -> axum::Router {
        let repository: Arc<dyn TrustRecordAdminRepository> = Arc::new(LocalStorage::new());
        repository.create(record(ENTITY)).await.expect("seeded");
        // Seeded so the invalid-identifier test proves validation runs before
        // the lookup: without it, a 404 would pass for the wrong reason.
        repository
            .create(record("has spaces and <angle brackets>"))
            .await
            .expect("seeded");
        // Valid for 2026 only.
        let year_2026 = TrustRecordBuilder::new()
            .entity_id(EntityId::new(WINDOWED))
            .authority_id(AuthorityId::new(AUTHORITY))
            .action(Action::new("issue"))
            .resource(Resource::new("vc"))
            .recognized(true)
            .authorized(true)
            .record_type(RecordType::Authorization)
            .valid_from(Some("2026-01-01T00:00:00Z".parse().expect("instant")))
            .valid_until(Some("2027-01-01T00:00:00Z".parse().expect("instant")))
            .build()
            .expect("valid record");
        repository.create(year_2026).await.expect("seeded");
        // Stored under the bare did:scid (a put normalises), and one an
        // earlier release stored with its locator.
        repository
            .create(record(SCID_ENTITY_LOCATED))
            .await
            .expect("seeded");
        let legacy = TrustRecordBuilder::new()
            .entity_id(EntityId::as_written(LEGACY_ENTITY_LOCATED))
            .authority_id(AuthorityId::new(AUTHORITY))
            .action(Action::new("issue"))
            .resource(Resource::new("vc"))
            .recognized(true)
            .authorized(true)
            .record_type(RecordType::Authorization)
            .build()
            .expect("valid record");
        repository.create(legacy).await.expect("seeded");
        // In window, but storing `false` (as after a git-trust revoke) or no
        // value at all for one of the flags.
        for (entity, recognized, authorized) in [
            (REVOKED, Some(false), Some(false)),
            (RECOGNIZED_ONLY, Some(true), None),
            (AUTHORIZED_ONLY, None, Some(true)),
        ] {
            let mut builder = TrustRecordBuilder::new()
                .entity_id(EntityId::new(entity))
                .authority_id(AuthorityId::new(AUTHORITY))
                .action(Action::new("issue"))
                .resource(Resource::new("vc"))
                .record_type(RecordType::Authorization);
            if let Some(r) = recognized {
                builder = builder.recognized(r);
            }
            if let Some(a) = authorized {
                builder = builder.authorized(a);
            }
            repository
                .create(builder.build().expect("valid record"))
                .await
                .expect("seeded");
        }
        TrustRegistry::builder(config)
            .repository(repository)
            .capability_store(Box::new(MemoryCapabilityStore::default()))
            .build()
            .await
            .expect("builds")
            .router()
    }

    fn query() -> Value {
        json!({
            "entity_id": ENTITY,
            "authority_id": AUTHORITY,
            "action": "issue",
            "resource": "vc",
        })
    }

    async fn post_raw(path: &str, body: String) -> (StatusCode, String, Value) {
        send(path, Some("application/json"), body).await
    }

    async fn send(
        path: &str,
        content_type: Option<&str>,
        body: String,
    ) -> (StatusCode, String, Value) {
        let mut request = Request::builder().method("POST").uri(path);
        if let Some(content_type) = content_type {
            request = request.header(header::CONTENT_TYPE, content_type);
        }
        let response = app()
            .await
            .oneshot(request.body(Body::from(body)).expect("request"))
            .await
            .expect("router responds");
        let status = response.status();
        let content_type = response
            .headers()
            .get(header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .unwrap_or_default()
            .to_string();
        let bytes = to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("body");
        let json = serde_json::from_slice(&bytes).expect("JSON body");
        (status, content_type, json)
    }

    async fn post(path: &str, body: Value) -> (StatusCode, String, Value) {
        post_raw(path, body.to_string()).await
    }

    fn with(mut body: Value, field: &str, value: Value) -> Value {
        body[field] = value;
        body
    }

    fn assert_problem(got: &(StatusCode, String, Value), status: StatusCode, title: &str) {
        let (s, content_type, body) = got;
        assert_eq!(*s, status, "body: {body}");
        assert_eq!(content_type, PROBLEM_JSON);
        assert_eq!(body["type"], "about:blank");
        assert_eq!(body["title"], title);
        assert_eq!(body["status"], status.as_u16());
        assert_eq!(body["code"], status.as_u16(), "kept for older clients");
        assert!(body["detail"].is_string());
    }

    const SCID_ENTITY_LOCATED: &str = "did:scid:vh:1:entity?src=example.com";
    const LEGACY_ENTITY_LOCATED: &str = "did:scid:vh:1:legacy?src=example.com";

    #[tokio::test]
    async fn a_did_scid_locator_is_answered_either_way() {
        for entity in [SCID_ENTITY_LOCATED, LEGACY_ENTITY_LOCATED] {
            let (status, _, body) =
                post("/authorization", with(query(), "entity_id", json!(entity))).await;
            assert_eq!(status, StatusCode::OK, "{entity}: {body}");
            assert_eq!(body["authorized"], true);
        }
        let (status, _, body) = post(
            "/authorization",
            with(query(), "entity_id", json!("did:scid:vh:1:entity")),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "the bare DID: {body}");
    }

    #[tokio::test]
    async fn known_statement_is_authorized() {
        let (status, content_type, body) = post("/authorization", query()).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(content_type, "application/json");
        assert_eq!(body["authorized"], true);
        assert!(body["context"].is_object());
    }

    #[tokio::test]
    async fn malformed_json_is_a_400_problem() {
        let got = post_raw("/authorization", "{not json".into()).await;
        assert_problem(&got, StatusCode::BAD_REQUEST, "bad_request");
    }

    #[tokio::test]
    async fn missing_field_is_a_400_problem_that_names_it() {
        let mut body = query();
        body.as_object_mut().unwrap().remove("action");
        let got = post("/authorization", body).await;
        assert_problem(&got, StatusCode::BAD_REQUEST, "bad_request");
        assert!(
            got.2["detail"].as_str().unwrap().contains("action"),
            "the extractor's reason is passed on: {}",
            got.2
        );
    }

    #[tokio::test]
    async fn malformed_json_says_where() {
        let got = post_raw("/recognition", "{not json".into()).await;
        let detail = got.2["detail"].as_str().unwrap();
        assert!(detail.contains("line 1"), "{detail}");
    }

    #[tokio::test]
    async fn a_body_not_declared_as_json_is_a_415_problem() {
        for content_type in [None, Some("text/plain")] {
            let got = send("/authorization", content_type, query().to_string()).await;
            assert_problem(
                &got,
                StatusCode::UNSUPPORTED_MEDIA_TYPE,
                "unsupported_media_type",
            );
        }
    }

    #[tokio::test]
    async fn an_oversize_body_is_a_413_problem() {
        let filler = "x".repeat(crate::http::limits::DEFAULT_MAX_BODY_BYTES + 1);
        let body = with(query(), "context", json!({ "filler": filler }));
        assert_problem(
            &post("/authorization", body).await,
            StatusCode::PAYLOAD_TOO_LARGE,
            "payload_too_large",
        );
    }

    #[tokio::test]
    async fn unknown_entity_is_a_404_problem() {
        let body = with(query(), "entity_id", json!("did:example:nobody"));
        assert_problem(
            &post("/recognition", body).await,
            StatusCode::NOT_FOUND,
            "not_found",
        );
    }

    #[tokio::test]
    async fn non_rfc3986_identifiers_are_refused_before_lookup() {
        for path in ["/authorization", "/recognition"] {
            for bad in ["not a uri <x>", "has spaces and <angle brackets>"] {
                for field in ["entity_id", "authority_id", "action", "resource"] {
                    let got = post(path, with(query(), field, json!(bad))).await;
                    assert_problem(&got, StatusCode::BAD_REQUEST, "invalid_request");
                    assert!(
                        got.2["detail"].as_str().unwrap().contains(field),
                        "detail names the field: {}",
                        got.2
                    );
                }
            }
        }
    }

    #[tokio::test]
    async fn empty_identifiers_are_refused() {
        for field in ["entity_id", "authority_id", "action", "resource"] {
            let got = post("/authorization", with(query(), field, json!(""))).await;
            assert_problem(&got, StatusCode::BAD_REQUEST, "invalid_request");
        }
    }

    #[tokio::test]
    async fn an_overlong_identifier_is_refused() {
        let long = format!("did:example:{}", "a".repeat(MAX_IDENTIFIER_BYTES));
        let got = post("/recognition", with(query(), "entity_id", json!(long))).await;
        assert_problem(&got, StatusCode::BAD_REQUEST, "invalid_request");
    }

    /// In window, a stored `false` or no stored value answers an explicit
    /// `false`, and the message does not claim the opposite (#208, #209).
    #[tokio::test]
    async fn a_false_or_absent_flag_answers_an_explicit_false() {
        for (path, flag, entity) in [
            ("/authorization", "authorized", REVOKED),
            ("/recognition", "recognized", REVOKED),
            ("/authorization", "authorized", RECOGNIZED_ONLY),
            ("/recognition", "recognized", AUTHORIZED_ONLY),
        ] {
            let (status, _, body) = post(path, with(query(), "entity_id", json!(entity))).await;
            assert_eq!(status, StatusCode::OK, "{body}");
            assert_eq!(body[flag], false, "{path} {entity}: {body}");
            let message = body["message"].as_str().unwrap();
            assert!(
                message.contains(&format!("not {flag}")),
                "{path} {entity}: {message}"
            );
        }
    }

    /// Each endpoint answers its own question only.
    #[tokio::test]
    async fn only_the_queried_flag_is_sent() {
        let (_, _, body) = post("/authorization", query()).await;
        assert!(body.get("recognized").is_none(), "{body}");
        let (_, _, body) = post("/recognition", query()).await;
        assert!(body.get("authorized").is_none(), "{body}");
        assert_eq!(body["recognized"], true);
        assert_eq!(
            body["message"],
            format!("{ENTITY} recognized by {AUTHORITY}")
        );
    }

    /// The request `context` never overrides or extends the stored one
    /// (#247): the answer's `context` is the record's, as stored.
    #[tokio::test]
    async fn the_stored_context_is_returned_as_stored() {
        for path in ["/authorization", "/recognition"] {
            let (status, _, body) = post(
                path,
                with(
                    query(),
                    "context",
                    json!({ "seeded": "overridden", "extra": 1 }),
                ),
            )
            .await;
            assert_eq!(status, StatusCode::OK, "{body}");
            assert_eq!(body["context"], json!({"seeded": "yes"}), "{body}");
        }
    }

    #[tokio::test]
    async fn non_object_context_is_refused() {
        for context in [json!("2026-03-01T00:00:00Z"), json!([1]), json!(7)] {
            let got = post("/authorization", with(query(), "context", context)).await;
            assert_problem(&got, StatusCode::BAD_REQUEST, "invalid_request");
        }
    }

    #[tokio::test]
    async fn null_context_is_treated_as_absent() {
        let (status, _, body) = post("/authorization", with(query(), "context", Value::Null)).await;
        assert_eq!(status, StatusCode::OK, "{body}");
    }

    #[tokio::test]
    async fn non_rfc3339_time_is_refused() {
        for time in [json!("yesterday"), json!("2026-03-01"), json!(1700000000)] {
            let got = post(
                "/authorization",
                with(query(), "context", json!({ "time": time })),
            )
            .await;
            assert_problem(&got, StatusCode::BAD_REQUEST, "invalid_request");
        }
    }

    #[tokio::test]
    async fn time_requested_echoes_context_time() {
        for (asked, echoed) in [
            ("1970-01-01T00:00:00Z", "1970-01-01T00:00:00Z"),
            ("2999-01-01T00:00:00Z", "2999-01-01T00:00:00Z"),
            // Normalised to UTC; sub-second precision is kept.
            ("2026-03-01T10:00:00.250+02:00", "2026-03-01T08:00:00.250Z"),
        ] {
            let (status, _, body) = post(
                "/recognition",
                with(
                    query(),
                    "context",
                    json!({ "time": asked, "extra": {"a": 1} }),
                ),
            )
            .await;
            assert_eq!(status, StatusCode::OK, "{body}");
            assert_eq!(body["time_requested"], echoed);
            assert_ne!(
                body["time_evaluated"], echoed,
                "evaluated is the server clock"
            );
            // The request context is read, not merged into the answer.
            assert_eq!(body["context"], json!({"seeded": "yes"}));
        }
    }

    #[tokio::test]
    async fn blank_time_falls_back_to_the_server_clock() {
        let (status, _, body) = post(
            "/authorization",
            with(query(), "context", json!({ "time": "" })),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert!(body["time_requested"].as_str().unwrap().ends_with('Z'));
    }

    fn windowed_query(time: &str) -> Value {
        with(
            with(query(), "entity_id", json!(WINDOWED)),
            "context",
            json!({ "time": time }),
        )
    }

    #[tokio::test]
    async fn inside_its_window_a_record_answers_true() {
        for path in ["/authorization", "/recognition"] {
            let (status, _, body) = post(path, windowed_query("2026-06-01T00:00:00Z")).await;
            assert_eq!(status, StatusCode::OK, "{body}");
            let flag = if path == "/authorization" {
                "authorized"
            } else {
                "recognized"
            };
            assert_eq!(body[flag], true, "{body}");
            // The plain TRQP binding keeps TRQP's snake_case names.
            assert_eq!(body["valid_from"], "2026-01-01T00:00:00Z", "{body}");
        }
    }

    /// Outside its window a record is still recognised as existing (no 404),
    /// but the statement does not hold.
    #[tokio::test]
    async fn outside_its_window_a_record_answers_false_with_the_reason() {
        for (time, reason) in [
            ("2025-06-01T00:00:00Z", "not valid until"),
            ("2027-01-01T00:00:00Z", "stopped being valid"),
        ] {
            let (status, _, body) = post("/authorization", windowed_query(time)).await;
            assert_eq!(status, StatusCode::OK, "{body}");
            assert_eq!(body["authorized"], false, "{time}: {body}");
            assert!(body["message"].as_str().unwrap().contains(reason), "{body}");
            assert_eq!(body["time_requested"], time);
        }
    }

    #[tokio::test]
    async fn without_a_time_a_record_is_judged_now() {
        // The seeded record is valid for 2026 only; with no `context.time` the
        // registry's own clock decides the answer.
        let body_now = post(
            "/authorization",
            with(query(), "entity_id", json!(WINDOWED)),
        )
        .await
        .2;
        let now = chrono::Utc::now();
        let expected = now
            >= "2026-01-01T00:00:00Z"
                .parse::<chrono::DateTime<chrono::Utc>>()
                .unwrap()
            && now
                < "2027-01-01T00:00:00Z"
                    .parse::<chrono::DateTime<chrono::Utc>>()
                    .unwrap();
        assert_eq!(body_now["authorized"], expected, "{body_now}");
    }

    // The registry's other routes, as mounted next to these (#211, #251).

    async fn call(router: axum::Router, request: Request<Body>) -> (StatusCode, String, Value) {
        let response = router.oneshot(request).await.expect("router responds");
        let status = response.status();
        let content_type = response
            .headers()
            .get(header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .unwrap_or_default()
            .to_string();
        let bytes = to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("body");
        (
            status,
            content_type,
            serde_json::from_slice(&bytes).expect("JSON"),
        )
    }

    fn get_did_json() -> Request<Body> {
        Request::get("/.well-known/did.json")
            .body(Body::empty())
            .expect("request")
    }

    /// A registry with no DID (REST-only, embedded) does not serve Trust
    /// Tasks: never a reply issued by `""` without a proof.
    #[tokio::test]
    async fn without_a_did_trust_tasks_are_not_served() {
        let task = json!({
            "id": "req-1",
            "type": "https://trusttasks.org/spec/registry/recognition/0.1",
            "payload": {
                "entity_id": ENTITY, "authority_id": AUTHORITY,
                "action": "issue", "resource": "vc"
            }
        });
        let got = call(
            app().await,
            Request::post("/trust-tasks")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(task.to_string()))
                .expect("request"),
        )
        .await;
        assert_problem(&got, StatusCode::NOT_FOUND, "not_found");
        assert!(
            got.2["detail"].as_str().unwrap().contains("no DID"),
            "{}",
            got.2
        );
    }

    #[tokio::test]
    async fn without_a_did_document_did_json_is_a_404() {
        let got = call(app().await, get_did_json()).await;
        assert_problem(&got, StatusCode::NOT_FOUND, "not_found");
    }

    #[tokio::test]
    async fn a_configured_did_document_is_served_as_configured() {
        let document = json!({"id": "did:web:registry.example", "service": []});
        let mut config = TrustRegistryConfig::embedded("/tmp/tr-trqp-test");
        config.didcomm_config.did_document = Some(document.clone());
        let (status, _, body) = call(app_with(config).await, get_did_json()).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body, document);
    }
}
