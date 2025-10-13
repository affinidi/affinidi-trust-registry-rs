use axum::{routing::get, Json, Router};
use dotenvy::dotenv;
use serde_json::{json, Value};

use crate::{configs::HttpServerConfigs, handlers::application_routes, SharedData, CONFIG};

async fn health_checker_handler() -> Json<Value> {
    // TODO: connection to storage, any other checks?
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
  
    let mut main_router = Router::new()
      .route(
            "/health",
            get(health_checker_handler),
      )
      .with_state(shared_data.clone());
    let router = application_routes("", &shared_data.clone());

    main_router = main_router.merge(router);

    println!("Server is starting on {}...", lesten_address);

    let listener = tokio::net::TcpListener::bind(lesten_address).await.unwrap();
    axum::serve(listener, main_router).await.unwrap();
}