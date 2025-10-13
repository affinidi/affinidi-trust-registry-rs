use crate::SharedData;

use axum::{
    Json, Router,
    // extract::State,
    routing::{post},
};
use serde_json::{json, Value};

async fn handle_trqp_authorization(
    // State(state): State<SharedData>,
    // Json(body): Json<Value>,
) -> Json<Value> {
    Json(json!({ "foo": "bar" }))
}

async fn handle_trqp_recognition() -> Json<Value> {
    Json(json!({ "bar": "foo" }))
}


pub fn application_routes(api_prefix: &str, shared_data: &SharedData) -> Router {
    let all_handlers = Router::new()
        .route("/authorization", post(handle_trqp_authorization))
        .route("/recognition", post(handle_trqp_recognition));

    let shared_data_clone = shared_data.clone();
    let mut router = Router::new();
    router = if api_prefix.is_empty() || api_prefix == "/" {
        router.merge(all_handlers)
    } else {
        router.nest(api_prefix, all_handlers)
    };
    router.with_state(shared_data_clone)
}