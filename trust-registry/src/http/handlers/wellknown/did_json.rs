use crate::SharedData;
use crate::storage::repository::TrustRecordRepository;
use axum::{Json, extract::State, http::StatusCode, response::IntoResponse};
use tracing::warn;

pub async fn handle_wellknown_did_json<R>(
    State(state): State<SharedData<R>>,
) -> impl IntoResponse
where
    R: TrustRecordRepository + Send + ?Sized + 'static,
{
    let did_doc = state.config.didcomm_config.did_document.clone();

    let did_doc_value = serde_json::from_str::<serde_json::Value>(&did_doc).unwrap_or_else(|e| {
        warn!("Failed to parse DID document: {}", e);
        warn!("DID doc string: {}", did_doc);
        serde_json::json!({})
    });

    (StatusCode::OK, Json(did_doc_value))
}
