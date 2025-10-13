use axum::{routing::get, Json, Router};
use dotenvy::dotenv;
use serde_json::{json, Value};

use crate::{configs::HttpServerConfigs, SharedData, CONFIG};

async fn health_checker_handler() -> Json<Value> {
    Json(json!({
      "status": "OK"
    }))
}

pub async fn start() {
    dotenv().ok();

    let config: HttpServerConfigs = CONFIG.clone();
    let lesten_address = &config.listen_address.clone();

    let shared_data = SharedData {
        config,
        service_start_timestamp: chrono::Utc::now(),
    };
  
    let router= Router::new()
      //  .layer(configs.security.cors_allow_origin)
      // .layer(RequestBodyLimitLayer::new(configs.limits.http_size as usize))
      .route(
            "/health",
            get(health_checker_handler),
      )
      .with_state(shared_data);

    let listener = tokio::net::TcpListener::bind(lesten_address).await.unwrap();
    axum::serve(listener, router).await.unwrap();
}