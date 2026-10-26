//! HTTP error responses for the TRQP endpoints.
//!
//! TRQP v2.0 (`conformance.md`, HTTPS Binding 4) requires errors to be RFC 9457
//! Problem Details, and RFC 9457 identifies that format by the
//! `application/problem+json` media type, so every error is served with it.
//!
//! The body carries the RFC 9457 members `type`, `title`, `status` and
//! `detail`. `code` duplicates `status`; it is an extension member kept for
//! clients written against earlier releases.

use anyhow::Error;
use axum::{
    http::{HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
};
use serde_json::{Map, Value};
use tracing::{error, warn};

const LAST_WARNING_ERROR_CODE: u16 = 499;

/// The RFC 9457 media type for a JSON problem details document.
pub const PROBLEM_JSON: &str = "application/problem+json";

pub enum AppError {
    /// The body is not JSON, or a required field is missing.
    BadRequest {
        internal_error: Error,
        details: Option<Value>,
    },
    /// The request parsed but a field breaks the TRQP rules (an identifier
    /// that is empty or not an RFC 3986 string, a non-object `context`, a
    /// `context.time` that is not RFC 3339). `detail` is sent to the client,
    /// so it must only describe the client's own input.
    InvalidRequest { detail: String },
    NotFound {
        internal_error: Error,
        details: Option<Value>,
    },
    Internal {
        internal_error: Error,
        details: Option<Value>,
    },
}

struct Parts {
    status: StatusCode,
    title: &'static str,
    detail: String,
    details: Option<Value>,
    internal_error: Option<Error>,
}

impl AppError {
    fn into_parts(self) -> Parts {
        match self {
            AppError::BadRequest {
                internal_error,
                details,
            } => Parts {
                status: StatusCode::BAD_REQUEST,
                title: "bad_request",
                detail: "The request is not valid JSON or is missing required fields".into(),
                details,
                internal_error: Some(internal_error),
            },
            AppError::InvalidRequest { detail } => Parts {
                status: StatusCode::BAD_REQUEST,
                title: "invalid_request",
                detail,
                details: None,
                internal_error: None,
            },
            AppError::NotFound {
                internal_error,
                details,
            } => Parts {
                status: StatusCode::NOT_FOUND,
                title: "not_found",
                detail: "The requested resource could not be found".into(),
                details,
                internal_error: Some(internal_error),
            },
            AppError::Internal {
                internal_error,
                details,
            } => Parts {
                status: StatusCode::INTERNAL_SERVER_ERROR,
                title: "internal_error",
                detail: "An unexpected error occurred".into(),
                details,
                internal_error: Some(internal_error),
            },
        }
    }
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let Parts {
            status,
            title,
            detail,
            details,
            internal_error,
        } = self.into_parts();
        let internal_error = internal_error
            .map(|e| e.to_string())
            .unwrap_or_else(|| detail.clone());
        if status.as_u16() > LAST_WARNING_ERROR_CODE {
            error!(%internal_error, title, %detail, "HTTP request failed with error. details: {:?}", details);
        } else {
            warn!(%internal_error, title, %detail, "HTTP request failed with exception. details: {:?}", details);
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
