use anyhow::anyhow;
use app::{
    domain::{Context, TrustRecord, TrustRecordIds},
    storage::repository::{TrustRecordQuery, TrustRecordRepository},
};
use axum::{
    Json,
    extract::{State, rejection::JsonRejection},
};
use chrono::{SecondsFormat, Utc};
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::{AppError, SharedData};

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct OutputDto {
    #[serde(flatten)]
    trust_record: TrustRecord,
    time_requested: String,
    time_evaluated: String,
    message: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct InputDto {
    #[serde(flatten)]
    ids: TrustRecordIds,
    context: Option<Context>,
}

async fn handle_trqp<R>(
    state: SharedData<R>,
    payload: Result<Json<InputDto>, JsonRejection>,
) -> Result<TrustRecord, AppError>
where
    R: TrustRecordRepository + Send + ?Sized + 'static,
{
    let body = payload.map_err(|e| AppError::BadRequest {
        details: Some(json!([{ "issue": e.body_text() }])),
        internal_error: e.into(),
    })?;
    let input = body.0;
    let query_result = state
        .repository
        .find_by_query(TrustRecordQuery::from_ids(input.ids))
        .await;
    let mut trust_record = query_result
        .map_err(|e| AppError::Internal {
            internal_error: e.into(),
            details: None,
        })?
        .ok_or(AppError::NotFound {
            internal_error: anyhow!("Trust record not found"),
            details: None,
        })?;

    if let Some(c) = input.context {
        trust_record = trust_record.merge_contexts(c);
    }

    Ok(trust_record)
}

pub async fn handle_trqp_authorization<R>(
    State(state): State<SharedData<R>>,
    payload: Result<Json<InputDto>, JsonRejection>,
) -> Result<Json<OutputDto>, AppError>
where
    R: TrustRecordRepository + Send + ?Sized + 'static,
{
    let requested_at = Utc::now();
    let mut trust_record = handle_trqp(state, payload).await?;
    // in order to follow spec remove this field from output
    trust_record = trust_record.none_recognized();
    let message = format!(
        "{} authorized to {} by {}",
        trust_record.entity_id(),
        trust_record.assertion_id(),
        trust_record.authority_id()
    );
    let evaluated_at = Utc::now();

    Ok(Json(OutputDto {
        trust_record,
        time_requested: requested_at.to_rfc3339_opts(SecondsFormat::Secs, true),
        time_evaluated: evaluated_at.to_rfc3339_opts(SecondsFormat::Secs, true),
        message,
    }))
}

pub async fn handle_trqp_recognition<R>(
    State(state): State<SharedData<R>>,
    payload: Result<Json<InputDto>, JsonRejection>,
) -> Result<Json<OutputDto>, AppError>
where
    R: TrustRecordRepository + Send + ?Sized + 'static,
{
    let requested_at = Utc::now();
    let mut trust_record = handle_trqp(state, payload).await?;
    // in order to follow spec remove this field from output
    trust_record = trust_record.none_assertion_verified();
    let message = format!(
        "{} recognized to {} by {}",
        trust_record.entity_id(),
        trust_record.assertion_id(),
        trust_record.authority_id()
    );
    let evaluated_at = Utc::now();

    Ok(Json(OutputDto {
        trust_record,
        time_requested: requested_at.to_rfc3339_opts(SecondsFormat::Secs, true),
        time_evaluated: evaluated_at.to_rfc3339_opts(SecondsFormat::Secs, true),
        message,
    }))
}
