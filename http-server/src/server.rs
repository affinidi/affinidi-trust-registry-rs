use app::storage::adapters::csv_file_storage::FileStorage;
use axum::{Json, Router, routing::get};
use dotenvy::dotenv;
use serde_json::{Value, json};
use std::sync::Arc;
use tracing::{error, info};
use tracing_subscriber::EnvFilter;

use crate::{CONFIG, SharedData, configs::HttpServerConfigs, handlers::application_routes};

fn setup_logging() {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        // .with_max_level(tracing::Level::DEBUG)
        .with_env_filter(EnvFilter::from_default_env()) // reads RUST_LOG
        .with_target(false)
        .with_level(true)
        .with_thread_ids(true)
        .init();
}

async fn health_checker_handler() -> Json<Value> {
    // TODO: connection to storage, any other checks?
    Json(json!({
      "status": "OK"
    }))
}

pub async fn start() {
    dotenv().ok();
    setup_logging();

    let config: HttpServerConfigs = CONFIG.clone();
    let listen_address = config.listen_address.clone();
    let file_storage_path = config.trust_registry_file_path.clone();
    let file_storage_update_interval_sec = config.trust_registry_update_interval_sec;

    let repository =
        match FileStorage::try_new(file_storage_path, file_storage_update_interval_sec).await {
            Ok(storage) => storage,
            Err(err) => {
                error!("Failed to initialize file storage repository: {err}");
                panic!("Failed to initialize trust registry repository");
            }
        };

    let shared_data = SharedData {
        config,
        service_start_timestamp: chrono::Utc::now(),
        repository: Arc::new(repository),
    };

    let mut main_router = Router::new()
        .route("/health", get(health_checker_handler))
        .with_state(shared_data.clone());
    let router = application_routes("", shared_data);

    main_router = main_router.merge(router);

    info!("Server is starting on {}...", listen_address);

    let listener = tokio::net::TcpListener::bind(&listen_address)
        .await
        .unwrap();
    axum::serve(listener, main_router).await.unwrap();
}
