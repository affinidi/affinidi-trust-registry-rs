use app::storage::factory::TrustStorageRepoFactory;
use axum::{Json, Router, routing::get};
use dotenvy::dotenv;
use serde_json::{Value, json};
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

    let repository_factory = TrustStorageRepoFactory::new(config.storage_backend);

    let repository = match repository_factory.create().await {
        Ok(r) => r,
        Err(e) => {
            error!("Failed to initialize trust record repository {}", e);
            panic!("Failed to initialize trust record repository {}", e);
        }
    };

    let shared_data = SharedData {
        config,
        service_start_timestamp: chrono::Utc::now(),
        repository: repository,
    };

    let mut main_router = Router::new().route("/health", get(health_checker_handler));
    let router = application_routes("", shared_data);

    main_router = main_router.merge(router);

    info!("Server is starting on {}...", listen_address);

    let listener = tokio::net::TcpListener::bind(&listen_address)
        .await
        .unwrap();
    axum::serve(listener, main_router).await.unwrap();
}
