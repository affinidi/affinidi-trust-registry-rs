//! HTTP error responses for the TRQP endpoints.
//!
//! TRQP v2.0 (`conformance.md`, HTTPS Binding 4) requires errors to be RFC 9457
//! Problem Details, and RFC 9457 identifies that format by the
//! `application/problem+json` media type, so every error is served with it.
//!
//! The body carries the RFC 9457 members `type`, `title`, `status` and
//! `detail`. `title` is stable per kind of error; `detail` says what was wrong
//! with this request (for a body that could not be read, the specific reason,
//! such as the missing field). `code` duplicates `status`; it is an extension
//! member kept for clients written against earlier releases.

use anyhow::Error;
use axum::{
    extract::rejection::JsonRejection,
    http::{HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
};
use serde_json::{Map, Value};
use tracing::{debug, error};

/// The RFC 9457 media type for a JSON problem details document.
pub const PROBLEM_JSON: &str = "application/problem+json";

#[derive(Debug)]
pub enum AppError {
    /// The body is not JSON, or does not have the query's shape (a missing
    /// field, a member of the wrong type). `detail` is the extractor's
    /// explanation, which describes only the client's own input.
    BadRequest { detail: String },
    /// The request did not say its body is JSON (`Content-Type` missing or
    /// not `application/json`): `415`.
    UnsupportedMediaType { detail: String },
    /// The request parsed but a field breaks the TRQP rules (an identifier
    /// that is empty, too long or not an RFC 3986 string, a non-object
    /// `context`, a `context.time` that is not RFC 3339). `detail` is sent to
    /// the client, so it must only describe the client's own input.
    InvalidRequest { detail: String },
    /// The body is larger than the server accepts.
    PayloadTooLarge { max_bytes: usize },
    /// Nothing here answers the request. `detail` is sent to the client.
    NotFound { detail: String },
    /// The registry failed. The error is logged, never sent.
    Internal { internal_error: Error },
}

impl AppError {
    /// The error for a body the JSON extractor refused: `413` when it is over
    /// `max_bytes`, `415` when it is not declared as JSON, and otherwise `400`
    /// with the extractor's reason as `detail`.
    pub fn from_json_rejection(rejection: JsonRejection, max_bytes: usize) -> Self {
        if rejection.status() == StatusCode::PAYLOAD_TOO_LARGE {
            return AppError::PayloadTooLarge { max_bytes };
        }
        let detail = rejection.body_text();
        match rejection {
            JsonRejection::MissingJsonContentType(_) => AppError::UnsupportedMediaType { detail },
            _ => AppError::BadRequest { detail },
        }
    }

    fn into_parts(self) -> (StatusCode, &'static str, String, Option<Error>) {
        match self {
            AppError::BadRequest { detail } => {
                (StatusCode::BAD_REQUEST, "bad_request", detail, None)
            }
            AppError::UnsupportedMediaType { detail } => (
                StatusCode::UNSUPPORTED_MEDIA_TYPE,
                "unsupported_media_type",
                detail,
                None,
            ),
            AppError::PayloadTooLarge { max_bytes } => (
                StatusCode::PAYLOAD_TOO_LARGE,
                "payload_too_large",
                format!("The request body is larger than {max_bytes} bytes"),
                None,
            ),
            AppError::InvalidRequest { detail } => {
                (StatusCode::BAD_REQUEST, "invalid_request", detail, None)
            }
            AppError::NotFound { detail } => (StatusCode::NOT_FOUND, "not_found", detail, None),
            AppError::Internal { internal_error } => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal_error",
                "An unexpected error occurred".into(),
                Some(internal_error),
            ),
        }
    }
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let (status, title, detail, internal_error) = self.into_parts();
        match internal_error {
            Some(internal_error) => {
                error!(%internal_error, title, %detail, "HTTP request failed with an error");
            }
            // A 4xx is an ordinary answer to the caller's request, such as a
            // record that does not exist: logged for debugging, not as a
            // warning, so callers do not decide the warning log's volume.
            None => debug!(title, %detail, status = status.as_u16(), "HTTP request refused"),
        }

        let mut payload = Map::new();
        payload.insert("type".to_string(), Value::String("about:blank".to_string()));
        payload.insert("title".to_string(), Value::String(title.to_string()));
        payload.insert("status".to_string(), Value::Number(status.as_u16().into()));
        payload.insert("detail".to_string(), Value::String(detail));
        payload.insert("code".to_string(), Value::Number(status.as_u16().into()));

        // A map of strings and numbers cannot fail to serialize.
        let body = serde_json::to_vec(&Value::Object(payload)).unwrap_or_default();
        (
            status,
            [(header::CONTENT_TYPE, HeaderValue::from_static(PROBLEM_JSON))],
            body,
        )
            .into_response()
    }
}
