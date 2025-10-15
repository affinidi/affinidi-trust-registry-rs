use axum::{Json, Router, routing::get};
use dotenvy::dotenv;
use serde_json::json;
use tracing::{debug, error, info};
use tracing_subscriber::EnvFilter;

use crate::{CONFIG, configs::DidcommServerConfigs, listener::start_didcomm_listeners};

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

async fn start_didcomm_server() -> Result<(), std::io::Error> {
    let config: DidcommServerConfigs = CONFIG.clone();

    start_didcomm_listeners(config).await?;

    Ok(())
}

/// The main purpose is just to handle health check of container
async fn start_http_server_healthcheck() -> Result<(), std::io::Error> {
    let config: DidcommServerConfigs = CONFIG.clone();
    let listen_address = &config.listen_address.clone();

    let service_start_timestamp = chrono::Utc::now().timestamp_millis();

    let main_router = Router::new().route(
        "/health",
        get(async move || {
            Json(json!({ "status": "OK", "service_start_timestamp": service_start_timestamp }))
        }),
    );

    info!("DIDComm server is starting on {}...", listen_address);
    debug!("CONFIGS: {:?}", &config);

    let listener = tokio::net::TcpListener::bind(listen_address).await?;
    axum::serve(listener, main_router).await?;

    Ok(())
}

pub async fn start() {
    dotenv().ok();

    setup_logging();

    let http_task = tokio::spawn(start_http_server_healthcheck());

    let didcomm_task = tokio::spawn(start_didcomm_server());

    tokio::select! {
        result = didcomm_task => {
            error!("didcomm_task failed: {:?}", result);
        }
        result = http_task => {
            error!("http_task failed: {:?}", result);
        }
    }

    std::process::exit(1);
}
