use crate::SharedData;
use crate::http::error::AppError;
use crate::storage::repository::TrustRecordRepository;
use axum::{
    Json,
    extract::State,
    response::{IntoResponse, Response},
};

/// `GET /.well-known/did.json`: the registry's DID document, parsed once when
/// the configuration was loaded, or `404` when none is configured (a REST-only
/// or embedded registry publishes none). Nothing is logged per request.
pub async fn handle_wellknown_did_json<R>(State(state): State<SharedData<R>>) -> Response
where
    R: TrustRecordRepository + Send + ?Sized + 'static,
{
    match &state.config.didcomm_config.did_document {
        Some(document) => Json(document).into_response(),
        None => AppError::NotFound {
            detail: "This registry publishes no DID document".into(),
        }
        .into_response(),
    }
}
