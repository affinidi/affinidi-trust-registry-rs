//! HTTP transport binding for the Trust Registry's Trust Task queries.
//!
//! Exposes `POST /trust-tasks` — the Trust Tasks HTTPS binding
//! (`trusttasks.org/binding/https/0.1`) — as the Trust Task equivalent of the
//! existing REST TRQP endpoints. Mirroring that surface, the HTTP binding is
//! **read-only**: it routes the `registry/recognition` and
//! `registry/authorization` query tasks. Record writes, `registry/record/query`
//! and governance tasks are served only over DIDComm and TSP, which
//! authenticate the sender; the HTTP caller is anonymous.
//!
//! A single `TrustTask` JSON document is posted in the body; the handler runs
//! the framework freshness checks, routes through the read-only dispatcher, and
//! returns the `#response` (200) or a `trust-task-error` document with the HTTP
//! status mapped from its code.
//!
//! A registry with no DID of its own (REST-only, or an embedded config with no
//! profile) has nothing to issue or sign replies as, so it answers `404` with a
//! problem document saying so, rather than replies with an empty `issuer` and
//! no proof.

use axum::{
    Json,
    body::Bytes,
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use serde_json::Value;
use trust_tasks_https::{HttpsHandler, status_for_code};
use trust_tasks_rs::{ErrorResponse, RejectReason, TransportHandler, TrustTask};
use uuid::Uuid;

use crate::SharedData;
use crate::embed::with_reply_signer;
use crate::http::error::AppError;
use crate::storage::repository::TrustRecordRepository;
use crate::trust_tasks::TaskHandler;

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
pub async fn handle_trust_task<R>(
    State(state): State<SharedData<R>>,
    body: Result<Bytes, axum::extract::rejection::BytesRejection>,
) -> Response
where
    R: TrustRecordRepository + Send + ?Sized + 'static,
{
    let body = match body {
        Ok(body) => body,
        Err(e) if e.status() == StatusCode::PAYLOAD_TOO_LARGE => {
            return crate::http::limits::trust_task_too_large(
                state.config.server_config.http_limits.max_body_bytes,
            );
        }
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({
                    "code": "malformedRequest",
                    "message": format!("could not read the Trust Task document: {}", e.body_text()),
                })),
            )
                .into_response();
        }
    };
    let my_vid = state.config.didcomm_config.profile_config.did.clone();
    // No DID, no identity to issue or sign replies as: refuse rather than
    // answer with `issuer: ""` and no proof (or reject every document that
    // names a recipient as `wrongRecipient`).
    if my_vid.is_empty() {
        return AppError::NotFound {
            detail: "This registry has no DID, so it does not serve Trust Tasks over HTTP; \
                     query it with POST /recognition or POST /authorization"
                .into(),
        }
        .into_response();
    }

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

    // The read-only query dispatcher, and no dedup store: there is no mutation
    // to replay, and keying read answers by message id would change their
    // semantics. `sender_did: None` says the caller is unauthenticated, so the
    // shared handler denies any write outright — the surface stays read-only
    // even if it is ever pointed at a dispatcher that does register writes.
    let tasks = with_reply_signer(
        TaskHandler::new(
            state.query_dispatcher.clone(),
            my_vid.clone(),
            Vec::new(),
            state.verifier.clone(),
        )
        .with_audit(state.audit.clone()),
        &state.config,
    );

    // HTTP transport: anonymous caller (no bearer auth wired yet), our VID local.
    let transport = HttpsHandler::new(Some(my_vid), None);
    if let Err(consistency) = transport.resolve_parties(&doc) {
        let rejection = doc.reject_with(new_id(), RejectReason::from(consistency));
        return error_response(tasks.seal_reply(rejection).await);
    }

    match tasks.handle(doc, None).await {
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
