use app::{configs::Configs, storage::factory::TrustStorageRepoFactory};
use axum::{Json, Router, routing::get};
use dotenvy::dotenv;
use serde_json::{Value, json};
use tower_http::cors::CorsLayer;
use tracing::{error, info};
use tracing_subscriber::EnvFilter;

use crate::{SharedData, configs::HttpServerConfigs, handlers::application_routes};

fn setup_logging() {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        // .with_max_level(tracing::Level::DEBUG)
        .with_env_filter(EnvFilter::from_default_env()) // reads RUST_LOG
        .with_target(false)
        .with_level(true)
        .with_thread_ids(true)
        .try_init();
}

async fn health_checker_handler() -> Json<Value> {
    // TODO: connection to storage, any other checks?
    Json(json!({
      "status": "OK"
    }))
}

fn build_cors_layer(allowed_origins: &[String]) -> CorsLayer {
    if allowed_origins.is_empty() {
        info!("CORS: No allowed origins configured, allowing all origins");
        return CorsLayer::permissive();
    }

    if allowed_origins.len() == 1 && allowed_origins[0] == "*" {
        info!("CORS: Wildcard configured, allowing all origins");
        return CorsLayer::permissive();
    }

    info!("CORS: Configured allowed origins: {:?}", allowed_origins);

    let origins: Vec<_> = allowed_origins
        .iter()
        .filter_map(|origin| origin.parse().ok())
        .collect();

    CorsLayer::new()
        .allow_origin(origins)
        .allow_methods(tower_http::cors::Any)
        .allow_headers(tower_http::cors::Any)
}

pub async fn start() {
    dotenv().ok();
    setup_logging();

    let config = match HttpServerConfigs::load().await {
        Ok(config) => config,
        Err(e) => {
            error!("Failed to load configuration: {}", e);
            panic!("Failed to load configuration: {}", e);
        }
    };

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
        config: config.clone(),
        service_start_timestamp: chrono::Utc::now(),
        repository: repository,
    };

    let cors = build_cors_layer(&config.cors_allowed_origins);

    let mut main_router = Router::new().route("/health", get(health_checker_handler));
    let router = application_routes("", shared_data);

    main_router = main_router.merge(router).layer(cors);

    info!("Server is starting on {}...", listen_address);

    let listener = tokio::net::TcpListener::bind(&listen_address)
        .await
        .unwrap();
    axum::serve(listener, main_router).await.unwrap();
}
