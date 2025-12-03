use std::env;

use super::Configs;

const DEFAULT_TRUST_REGISTRY_FILE_PATH: &str = "trust_records.csv";
const DEFAULT_TRUST_REGISTRY_UPDATE_INTERVAL_SEC: u64 = 60;
const DEFAULT_REGION: &str = "ap-southeast-1";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrustStorageBackend {
    Csv,
    DynamoDb,
}

#[derive(Debug, Clone, Default)]
pub struct FileStorageConfig {
    pub is_enabled: bool,
    pub path: String,
    pub update_interval_sec: u64,
}

#[derive(Debug, Clone, Default)]
pub struct DynamoDbStorageConfig {
    pub is_enabled: bool,
    pub table_name: String,
    pub region: Option<String>,
    pub profile: Option<String>,
    pub endpoint_url: Option<String>,
}

#[derive(Debug, Clone)]
pub struct StorageConfig {
    pub ddb_storage_config: DynamoDbStorageConfig,
    pub file_storage_config: FileStorageConfig,
    pub storage_backend: TrustStorageBackend,
}

fn load_storage_backend() -> TrustStorageBackend {
    let storage_backend_str = env::var("TR_STORAGE_BACKEND")
        .unwrap_or("csv".to_string())
        .to_lowercase();
    match storage_backend_str.as_str() {
        "dynamodb" | "ddb" => TrustStorageBackend::DynamoDb,
        _ => TrustStorageBackend::Csv,
    }
}

#[async_trait::async_trait]
impl Configs for FileStorageConfig {
    async fn load() -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        if load_storage_backend() == TrustStorageBackend::Csv {
            Ok(FileStorageConfig {
                is_enabled: true,
                path: env::var("FILE_STORAGE_PATH")
                    .unwrap_or_else(|_| DEFAULT_TRUST_REGISTRY_FILE_PATH.to_string()),
                update_interval_sec: env::var("FILE_STORAGE_UPDATE_INTERVAL_SEC")
                    .unwrap_or_else(|_| DEFAULT_TRUST_REGISTRY_UPDATE_INTERVAL_SEC.to_string())
                    .parse::<u64>()?,
            })
        } else {
            Ok(Default::default())
        }
    }
}

#[async_trait::async_trait]
impl Configs for DynamoDbStorageConfig {
    async fn load() -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        if load_storage_backend() == TrustStorageBackend::DynamoDb {
            Ok(DynamoDbStorageConfig {
                is_enabled: true,
                table_name: env::var("DDB_TABLE_NAME")
                    .map_err(|_| "Missing required environment variable: DDB_TABLE_NAME")?,
                region: Some(env::var("AWS_REGION").unwrap_or_else(|_| DEFAULT_REGION.to_string())),
                profile: env::var("AWS_PROFILE").ok(),
                endpoint_url: env::var("AWS_ENDPOINT")
                    .or_else(|_| env::var("DYNAMODB_ENDPOINT"))
                    .ok(),
            })
        } else {
            Ok(Default::default())
        }
    }
}

#[async_trait::async_trait]
impl Configs for StorageConfig {
    async fn load() -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let storage_backend = load_storage_backend();
        Ok(StorageConfig {
            ddb_storage_config: DynamoDbStorageConfig::load().await?,
            file_storage_config: FileStorageConfig::load().await?,
            storage_backend,
        })
    }
}
