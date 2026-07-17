//! HTTP transport binding for the Trust Registry's Trust Task queries.
//!
//! Exposes `POST /trust-tasks` — the Trust Tasks HTTPS binding
//! (`trusttasks.org/binding/https/0.1`) — as the Trust Task equivalent of the
//! existing REST TRQP endpoints. Mirroring that surface, the HTTP binding is
//! **read-only**: it routes the `registry/recognition` and
//! `registry/authorization` query tasks. Record CRUD stays on the DIDComm
//! transport (which carries the admin-DID ACL).
//!
//! A single `TrustTask` JSON document is posted in the body; the handler runs
//! the framework freshness checks, routes through the read-only dispatcher, and
//! returns the `#response` (200) or a `trust-task-error` document with the HTTP
//! status mapped from its code. Bearer-auth identity (for authenticated callers)
//! is a follow-up; today the HTTP caller is anonymous, which is sufficient for
//! the read-only query surface.

use axum::{
    Json,
    body::Bytes,
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use chrono::Utc;
use serde_json::Value;
use trust_tasks_https::{HttpsHandler, status_for_code};
use trust_tasks_rs::{ErrorResponse, RejectReason, TransportHandler, TrustTask};
use uuid::Uuid;

use crate::SharedData;
use crate::storage::repository::TrustRecordRepository;
use crate::trust_tasks::handle_document;

fn new_id() -> String {
    Uuid::new_v4().to_string()
}

/// Serialise an [`ErrorResponse`] to an HTTP response, mapping its Trust Task
/// code to the corresponding status.
fn error_response(err: ErrorResponse) -> Response {
    let status =
        StatusCode::from_u16(status_for_code(&err.payload.code)).unwrap_or(StatusCode::BAD_REQUEST);
    let body = serde_json::to_value(&err).unwrap_or_else(|_| serde_json::json!({}));
    (status, Json(body)).into_response()
}

/// `POST /trust-tasks` — route a single Trust Task query document.
pub async fn handle_trust_task<R>(State(state): State<SharedData<R>>, body: Bytes) -> Response
where
    R: TrustRecordRepository + Send + ?Sized + 'static,
{
    let my_vid = state.config.didcomm_config.profile_config.did.clone();

    // Parse the framework document. A malformed body cannot be addressed as a
    // conformant error response, so return a plain 400.
    let doc: TrustTask<Value> = match serde_json::from_slice(&body) {
        Ok(doc) => doc,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({
                    "code": "malformedRequest",
                    "message": format!("invalid Trust Task document: {e}"),
                })),
            )
                .into_response();
        }
    };

    // HTTP transport: anonymous caller (no bearer auth wired yet), our VID local.
    let transport = HttpsHandler::new(Some(my_vid.clone()), None);
    if let Err(consistency) = transport.resolve_parties(&doc) {
        return error_response(doc.reject_with(new_id(), RejectReason::from(consistency)));
    }
    if let Err(reason) = doc.validate_basic(Utc::now(), &my_vid) {
        return error_response(doc.reject_with(new_id(), reason));
    }

    let dispatcher = state.query_dispatcher.read().await.clone();
    match handle_document(&dispatcher, doc).await {
        Ok(response) => {
            let body = serde_json::to_value(&response).unwrap_or_else(|_| serde_json::json!({}));
            (StatusCode::OK, Json(body)).into_response()
        }
        Err(err) => error_response(err),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn error_for(reason: RejectReason) -> ErrorResponse {
        let doc: TrustTask<Value> = TrustTask::new(
            "req-1",
            "https://trusttasks.org/spec/registry/recognition/0.1"
                .parse()
                .expect("valid type uri"),
            serde_json::json!({}),
        );
        doc.reject_with(new_id(), reason)
    }

    #[test]
    fn malformed_request_maps_to_400() {
        let resp = error_response(error_for(RejectReason::MalformedRequest {
            reason: "bad".into(),
        }));
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[test]
    fn unsupported_type_maps_to_client_error() {
        let resp = error_response(error_for(RejectReason::UnsupportedType {
            type_uri: "https://trusttasks.org/spec/registry/nope/0.1".into(),
        }));
        assert!(resp.status().is_client_error());
    }
}
