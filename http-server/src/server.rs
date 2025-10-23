use app::storage::{
    adapters::{
        csv_file_storage::FileStorage,
        ddb_storage::{DynamoDbConfig, DynamoDbStorage},
    },
    repository::TrustRecordRepository,
};
use axum::{Json, Router, routing::get};
use dotenvy::dotenv;
use serde_json::{Value, json};
use std::sync::Arc;
use tracing::{error, info};
use tracing_subscriber::EnvFilter;

use crate::{
    CONFIG, SharedData,
    configs::{HttpServerConfigs, TrustStorageBackend},
    handlers::application_routes,
};

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

    let repository: Arc<dyn TrustRecordRepository> = match config.storage_backend {
        TrustStorageBackend::Csv => {
            let file_storage_config = config.clone().file_storage.unwrap();
            let file_storage_path = file_storage_config.path.clone();
            let file_storage_update_interval_sec = file_storage_config.update_interval_sec;
            let file_storage =
                match FileStorage::try_new(file_storage_path, file_storage_update_interval_sec)
                    .await
                {
                    Ok(storage) => storage,
                    Err(err) => {
                        error!("Failed to initialize file storage repository: {err}");
                        panic!("Failed to initialize trust registry repository");
                    }
                };
            Arc::new(file_storage)
        }
        TrustStorageBackend::DynamoDb => {
            let ddb_config = config.clone().dynamodb_storage.unwrap();
            let ddb_internal_config = DynamoDbConfig::new(ddb_config.table_name.clone())
                .set_endpoint_url(ddb_config.endpoint_url.clone())
                .set_region(ddb_config.region.clone())
                .set_profile(ddb_config.profile.clone());
            let ddb = match DynamoDbStorage::new(ddb_internal_config).await {
                Ok(storage) => storage,
                Err(err) => {
                    error!("Failed to initialize file storage repository: {err}");
                    panic!("Failed to initialize trust registry repository");
                }
            };
            Arc::new(ddb)
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
