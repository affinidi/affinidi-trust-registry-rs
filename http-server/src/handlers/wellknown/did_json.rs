use crate::SharedData;
use app::storage::repository::TrustRecordRepository;
use axum::{Json, extract::State, http::StatusCode, response::IntoResponse};
use serde_json::json;

pub async fn handle_wellknown_did_json<R>(
    State(state): State<SharedData<R>>,
) -> impl IntoResponse
where
    R: TrustRecordRepository + Send + ?Sized + 'static,
{
    if let Some(document) = state.config.did_web_document {
        (StatusCode::OK, Json(document))
    } else {
        (StatusCode::NOT_FOUND, Json(json!({})))
    }
    
}
