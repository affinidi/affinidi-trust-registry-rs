use app::{domain::TrustRecordIds, storage::repository::{TrustRecordQuery, TrustRecordRepository}};
use axum::{
    extract::{rejection::JsonRejection, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde_json::json;
use tracing::{error, warn};

use crate::SharedData;

pub async fn handle_trqp_authorization<R: TrustRecordRepository>(
    State(state): State<SharedData<R>>,
    payload: Result<Json<TrustRecordIds>, JsonRejection>,
) -> Response {
    match payload {
        Ok(Json(body)) => {
            let result = state.repository.find_by_query(TrustRecordQuery::from_ids(body)).await;
            match result {
                // TODO: handle errors outside of controller for common cases
                Err(e) => {
                    error!("Failed to retrieve TrustRecord: {}", e);
                    let response = json!({
                        "code": "INTERNAL_SERVER_ERROR",
                        "message": "INTERNAL_SERVER_ERROR",
                    });
                    return (StatusCode::INTERNAL_SERVER_ERROR, Json(response)).into_response()
                }
                Ok(None) => {
                    warn!("no TrustRecord found TrustRecord");
                    let response = json!({
                        "code": "NOT_FOUND",
                        "message": "Record not found",
                    });
                    return (StatusCode::NOT_FOUND, Json(response)).into_response()
                },
                Ok(Some(t)) => {
                    return (StatusCode::OK, Json(t)).into_response()
                }
            }
        }
        Err(rejection) => {
            let response = json!({
                "code": "invalid_request",
                "message": "Invalid trust record identifiers",
                "details": rejection.body_text(),
            });
            (StatusCode::BAD_REQUEST, Json(response)).into_response()
        }
    }
}
