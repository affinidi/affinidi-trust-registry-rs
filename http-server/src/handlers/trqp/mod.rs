use app::{domain::{TrustRecord, TrustRecordIds}, storage::repository::{TrustRecordQuery, TrustRecordRepository}};
use axum::{
    extract::{rejection::JsonRejection, State},
    Json,
};
use anyhow::anyhow;
use serde_json::json;

use crate::{AppError, SharedData};

pub async fn handle_trqp_authorization<R: TrustRecordRepository>(
    State(state): State<SharedData<R>>,
    payload: Result<Json<TrustRecordIds>, JsonRejection>,
) -> Result<Json<TrustRecord>, AppError> {
    let body = payload
        .map_err(|e| AppError::BadRequest { details: Some(json!([{ "issue": e.body_text() }])), internal_error: e.into() })?;
    let query_result = state.repository.find_by_query(TrustRecordQuery::from_ids(body.0)).await;
    let trust_record = query_result
        .map_err(|e| AppError::Internal { internal_error: e.into(), details: None })?
        .ok_or(AppError::NotFound { internal_error: anyhow!("Trust record not found"), details: None })?;
    Ok(Json(trust_record))
}
