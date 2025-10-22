use anyhow::Error;
use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
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
              details 
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
        let (status, code, message, details, internal_error) = self.into_parts();
        if status.as_u16() > LAST_WARNING_ERROR_CODE {
            error!(%internal_error, code, message, "HTTP request failed with error");
        } else {
            warn!(%internal_error, code, message, "HTTP request failed with exception");
        }
        

        let mut payload = Map::with_capacity(3);
        payload.insert("code".to_string(), Value::String(code.to_string()));
        payload.insert("message".to_string(), Value::String(message.to_string()));
        if let Some(details) = details {
            payload.insert("details".to_string(), details);
        }

        (status, Json(Value::Object(payload))).into_response()
    }
}
