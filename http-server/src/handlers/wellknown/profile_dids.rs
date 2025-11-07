use crate::SharedData;
use app::storage::repository::TrustRecordRepository;
use axum::{Json, extract::State, http::StatusCode, response::IntoResponse};
use serde_json::{Value, json};

pub async fn handle_wellknown_profile_dids<R>(
    State(state): State<SharedData<R>>,
) -> impl IntoResponse
where
    R: TrustRecordRepository + Send + ?Sized + 'static,
{
    let dids: Vec<String> = state
        .config
        .profile_configs
        .iter()
        .map(|c| c.did.clone())
        .collect();

    (StatusCode::OK, Json(json!({ "dids": dids })))
}
