use crate::{
    domain::{Context, Evaluation, TrustRecord, TrustRecordIds},
    storage::repository::{TrustRecordQuery, TrustRecordRepository},
};
use anyhow::anyhow;
use axum::{
    Json,
    extract::{State, rejection::JsonRejection},
};
use chrono::{DateTime, SecondsFormat, Utc};
use fluent_uri::UriRef;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use super::SharedData;
use crate::http::error::AppError;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct OutputDto {
    #[serde(flatten)]
    trust_record: TrustRecord,
    time_requested: String,
    time_evaluated: String,
    message: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct InputDto {
    #[serde(flatten)]
    ids: TrustRecordIds,
    context: Option<Context>,
}

/// A TRQP query that passed validation.
struct ValidQuery {
    ids: TrustRecordIds,
    context: Option<Context>,
    /// `context.time`, when the client supplied one.
    time: Option<DateTime<Utc>>,
}

/// TRQP v2.0 Identifiers: every identifier is a single RFC 3986 string, and
/// none of the four may be empty (`action`/`resource` by the spec's own rule,
/// `entity_id`/`authority_id` because an empty string identifies nothing).
///
/// Invalid identifiers are refused here, before the lookup, so they get a 400
/// rather than the 404 that means "valid but not recognised".
fn validate_identifier(field: &str, value: &str) -> Result<(), AppError> {
    if value.is_empty() {
        return Err(AppError::InvalidRequest {
            detail: format!("`{field}` must not be empty"),
        });
    }
    UriRef::parse(value).map_err(|e| AppError::InvalidRequest {
        detail: format!("`{field}` is not an RFC 3986 URI reference: {e}"),
    })?;
    Ok(())
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
    let ids = input.ids;
    validate_identifier("entity_id", ids.entity_id().as_str())?;
    validate_identifier("authority_id", ids.authority_id().as_str())?;
    validate_identifier("action", ids.action().as_str())?;
    validate_identifier("resource", ids.resource().as_str())?;
    let time = match &input.context {
        Some(c) => validate_context(c)?,
        None => None,
    };
    Ok(ValidQuery {
        ids,
        context: input.context,
        time,
    })
}

async fn handle_trqp<R>(
    state: SharedData<R>,
    payload: Result<Json<InputDto>, JsonRejection>,
) -> Result<(TrustRecord, Option<DateTime<Utc>>), AppError>
where
    R: TrustRecordRepository + Send + ?Sized + 'static,
{
    let body = payload.map_err(|e| AppError::BadRequest {
        details: Some(json!([{ "issue": e.body_text() }])),
        internal_error: e.into(),
    })?;
    let query = validate(body.0)?;
    let query_result = state
        .repository
        .find_by_query(TrustRecordQuery::from_ids(query.ids))
        .await;
    let mut trust_record = query_result
        .map_err(|e| AppError::Internal {
            internal_error: e.into(),
            details: None,
        })?
        .ok_or(AppError::NotFound {
            internal_error: anyhow!("Trust record not found"),
            details: None,
        })?;

    if let Some(c) = query.context {
        trust_record = trust_record.merge_contexts(c);
    }

    Ok((trust_record, query.time))
}

/// `time_requested` echoes `context.time` when the client sent one (the TRQP
/// response schema and the `registry/*` Trust Task schema both say so), and
/// falls back to the time the request arrived.
///
/// The answer is judged against the record's validity window as of that
/// instant (see [`apply_window`]); the registry keeps current records, not
/// their history. `time_evaluated` is the server time the answer was produced.
fn response_times(asked: Option<DateTime<Utc>>, received_at: DateTime<Utc>) -> (String, String) {
    let requested = asked.map_or_else(
        || received_at.to_rfc3339_opts(SecondsFormat::Secs, true),
        |t| t.to_rfc3339_opts(SecondsFormat::AutoSi, true),
    );
    let evaluated = Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true);
    (requested, evaluated)
}

/// Answer `false` for a record outside its validity window, and say why.
///
/// The record exists, so its identifiers are recognised and the answer is not
/// a 404: it is a statement that does not hold at the instant asked. Returns
/// the record with its flag set accordingly, and the reason when it was out of
/// window.
fn apply_window(
    record: TrustRecord,
    asked: Option<DateTime<Utc>>,
    authorization: bool,
) -> (TrustRecord, Option<String>) {
    let evaluation = Evaluation::of(Some(&record), asked, Utc::now());
    match evaluation.out_of_window_reason(&record) {
        None => (record, None),
        Some(reason) if authorization => (record.with_authorized(false), Some(reason)),
        Some(reason) => (record.with_recognized(false), Some(reason)),
    }
}

pub async fn handle_trqp_authorization<R>(
    State(state): State<SharedData<R>>,
    payload: Result<Json<InputDto>, JsonRejection>,
) -> Result<Json<OutputDto>, AppError>
where
    R: TrustRecordRepository + Send + ?Sized + 'static,
{
    let received_at = Utc::now();
    let (trust_record, asked) = handle_trqp(state, payload).await?;
    let (trust_record, out_of_window) = apply_window(trust_record, asked, true);
    // in order to follow spec remove this field from output
    let trust_record = trust_record.none_recognized();
    let message = match out_of_window {
        Some(reason) => format!(
            "{} not authorized by {}: {reason}",
            trust_record.entity_id(),
            trust_record.authority_id()
        ),
        None => format!(
            "{} authorized to {}+{} by {}",
            trust_record.entity_id(),
            trust_record.action(),
            trust_record.resource(),
            trust_record.authority_id()
        ),
    };
    let (time_requested, time_evaluated) = response_times(asked, received_at);

    Ok(Json(OutputDto {
        trust_record,
        time_requested,
        time_evaluated,
        message,
    }))
}

pub async fn handle_trqp_recognition<R>(
    State(state): State<SharedData<R>>,
    payload: Result<Json<InputDto>, JsonRejection>,
) -> Result<Json<OutputDto>, AppError>
where
    R: TrustRecordRepository + Send + ?Sized + 'static,
{
    let received_at = Utc::now();
    let (trust_record, asked) = handle_trqp(state, payload).await?;
    let (trust_record, out_of_window) = apply_window(trust_record, asked, false);
    // in order to follow spec remove this field from output
    let trust_record = trust_record.none_authorized();
    let message = match out_of_window {
        Some(reason) => format!(
            "{} not recognized by {}: {reason}",
            trust_record.entity_id(),
            trust_record.authority_id()
        ),
        None => format!(
            "{} recognized by {}",
            trust_record.entity_id(),
            trust_record.authority_id()
        ),
    };
    let (time_requested, time_evaluated) = response_times(asked, received_at);

    Ok(Json(OutputDto {
        trust_record,
        time_requested,
        time_evaluated,
        message,
    }))
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
        TrustRegistry::builder(TrustRegistryConfig::embedded("/tmp/tr-trqp-test"))
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
        let response = app()
            .await
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(path)
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(body))
                    .expect("request"),
            )
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
    async fn missing_field_is_a_400_problem() {
        let mut body = query();
        body.as_object_mut().unwrap().remove("action");
        assert_problem(
            &post("/authorization", body).await,
            StatusCode::BAD_REQUEST,
            "bad_request",
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

    /// The identifiers vtc-service sends (and other typical ones) must keep
    /// working: relative references like `issue` are RFC 3986 strings.
    #[test]
    fn typical_identifiers_are_accepted() {
        for id in [
            "did:webvh:QmHash:example.com%3A8080:path",
            "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK",
            "did:example:entity#key-1",
            "https://example.com/schemas/vc?x=1",
            "recognise",
            "trust-graph",
            "auth-service-A",
        ] {
            assert!(super::validate_identifier("entity_id", id).is_ok(), "{id}");
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
            // The request context still merges into the record's.
            assert_eq!(body["context"]["seeded"], "yes");
            assert_eq!(body["context"]["extra"]["a"], 1);
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
}
