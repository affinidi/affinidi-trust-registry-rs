use std::sync::Arc;

use crate::storage::{
    factory::TrustStorageRepoFactory,
    repository::{TrustRecordAdminRepository, TrustRecordRepository},
};
use axum::{Json, Router, routing::get};
use dotenvy::dotenv;
use serde_json::json;
use tower_http::cors::CorsLayer;
use tracing::{debug, error, info, warn};
use tracing_subscriber::EnvFilter;

use crate::{
    SharedData,
    configs::{Configs, DidcommConfig, TrsutRegistryConfig},
    didcomm::listener::start_didcomm_listener,
    http::application_routes,
};

fn setup_logging() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        // .with_max_level(tracing::Level::DEBUG)
        .with_env_filter(EnvFilter::from_default_env()) // reads RUST_LOG
        .with_target(false)
        .with_level(true)
        .with_thread_ids(true)
        .try_init();
}

async fn start_didcomm_server(
    config: DidcommConfig,
    repository: Arc<dyn TrustRecordAdminRepository>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    start_didcomm_listener(config, repository).await?;

    Ok(())
}

/// The main purpose is just to handle health check of container
async fn start_http_server(
    config: Arc<TrsutRegistryConfig>,
    repository: Arc<dyn TrustRecordRepository>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let listen_address = config.server_config.listen_address.clone();

    let shared_data = SharedData {
        config: config.clone(),
        service_start_timestamp: chrono::Utc::now(),
        repository,
    };

    let cors = build_cors_layer(&config.server_config.cors_allowed_origins);

    let health_route =
        Router::new().route("/health", get(|| async { Json(json!({ "status": "OK" })) }));

    let main_router = health_route
        .merge(application_routes("", shared_data))
        .layer(cors);

    info!("HTTP server is starting on {}...", listen_address);
    debug!("CONFIGS: {:?}", &config);

    let listener = tokio::net::TcpListener::bind(&listen_address).await?;
    axum::serve(listener, main_router).await?;

    Ok(())
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
    // resources section
    dotenv().ok();

    setup_logging();

    let config = match TrsutRegistryConfig::load().await {
        Ok(c) => Arc::new(c),
        Err(e) => {
            error!(
                "Failed to load configs. End of work. Original error is: {}",
                e
            );
            panic!("Failed to load configs");
        }
    };

    let repository_factory = TrustStorageRepoFactory::new(Arc::clone(&config));

    let repository = match repository_factory.create().await {
        Ok(r) => r,
        Err(e) => {
            error!("Failed to initialize trust record repository: {}", e);
            panic!("Failed to initialize trust record repository: {}", e);
        }
    };

    // tasks section
    let http_task = tokio::spawn(start_http_server(config.clone(), repository.clone()));

    if config.didcomm_config.is_enabled {
        let didcomm_task = tokio::spawn(start_didcomm_server(
            config.didcomm_config.clone(),
            repository,
        ));

        tokio::select! {
            result = didcomm_task => {
                error!("didcomm_task failed: {:?}", result);
            }
            result = http_task => {
                error!("http_task failed: {:?}", result);
            }
        }
    } else {
        warn!("DIDComm server is disabled.");

        if let Err(e) = http_task.await {
            error!("http_task failed: {:?}", e);
        }
    }

    std::process::exit(1);
}
