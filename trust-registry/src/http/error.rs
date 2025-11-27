use anyhow::Error;
use axum::{
    Json,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use serde_json::{Map, Value};
use tracing::{error, warn};

const LAST_WARNING_ERROR_CODE: u16 = 499;

pub enum AppError {
    BadRequest {
        internal_error: Error,
        details: Option<Value>,
    },
    NotFound {
        internal_error: Error,
        details: Option<Value>,
    },
    Internal {
        internal_error: Error,
        details: Option<Value>,
    },
}

impl AppError {
    fn into_parts(self) -> (StatusCode, &'static str, &'static str, Option<Value>, Error) {
        match self {
            AppError::BadRequest {
                internal_error,
                details,
            } => (
                StatusCode::BAD_REQUEST,
                "bad_request",
                "The request missing required fields",
                details,
                internal_error,
            ),
            AppError::NotFound {
                internal_error,
                details,
            } => (
                StatusCode::NOT_FOUND,
                "not_found",
                "The requested resource could not be found",
                details,
                internal_error,
            ),
            AppError::Internal {
                internal_error,
                details,
            } => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal_error",
                "An unexpected error occurred",
                details,
                internal_error,
            ),
        }
    }
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let (status, title, message, details, internal_error) = self.into_parts();
        if status.as_u16() > LAST_WARNING_ERROR_CODE {
            error!(%internal_error, title, message, "HTTP request failed with error. details: {:?}", details);
        } else {
            warn!(%internal_error, title, message, "HTTP request failed with exception. details: {:?}", details);
        }

        let mut payload = Map::new();
        payload.insert("title".to_string(), Value::String(title.to_string()));
        payload.insert("type".to_string(), Value::String("about:blank".to_string()));
        payload.insert("code".to_string(), Value::Number(status.as_u16().into()));

        (status, Json(Value::Object(payload))).into_response()
    }
}
