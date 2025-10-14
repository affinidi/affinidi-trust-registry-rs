use axum::{Json, Router, routing::get};
use dotenvy::dotenv;
use serde_json::{Value, json};

use crate::{CONFIG, SharedData, configs::HttpServerConfigs, handlers::application_routes};

async fn health_checker_handler() -> Json<Value> {
    // TODO: connection to storage, any other checks?
    Json(json!({
      "status": "OK"
    }))
}

pub async fn start() {
    dotenv().ok();

    let config: HttpServerConfigs = CONFIG.clone();
    let listen_address = &config.listen_address.clone();

    let shared_data = SharedData {
        config,
        service_start_timestamp: chrono::Utc::now(),
    };

    let mut main_router = Router::new()
        .route("/health", get(health_checker_handler))
        .with_state(shared_data.clone());
    let router = application_routes("", &shared_data.clone());

    main_router = main_router.merge(router);

    println!("Server is starting on {}...", listen_address);

    let listener = tokio::net::TcpListener::bind(listen_address).await.unwrap();
    axum::serve(listener, main_router).await.unwrap();
}
