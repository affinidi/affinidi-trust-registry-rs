use std::env;

use super::Configs;

const DEFAULT_TRUST_REGISTRY_FILE_PATH: &str = "trust_records.csv";
const DEFAULT_TRUST_REGISTRY_UPDATE_INTERVAL_SEC: u64 = 60;
const DEFAULT_REGION: &str = "ap-southeast-1";

#[derive(Debug, Clone, Copy)]
pub enum TrustStorageBackend {
    Csv,
    DynamoDb,
}

#[derive(Debug, Clone)]
pub struct FileStorageConfig {
    pub path: String,
    pub update_interval_sec: u64,
}

#[derive(Debug, Clone)]
pub struct DynamoDbStorageConfig {
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

#[async_trait::async_trait]
impl Configs for FileStorageConfig {
    async fn load() -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        Ok(FileStorageConfig {
            path: env::var("FILE_STORAGE_PATH")
                .unwrap_or_else(|_| DEFAULT_TRUST_REGISTRY_FILE_PATH.to_string()),
            update_interval_sec: env::var("FILE_STORAGE_UPDATE_INTERVAL_SEC")
                .unwrap_or_else(|_| DEFAULT_TRUST_REGISTRY_UPDATE_INTERVAL_SEC.to_string())
                .parse::<u64>()?,
        })
    }
}

#[async_trait::async_trait]
impl Configs for DynamoDbStorageConfig {
    async fn load() -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        Ok(DynamoDbStorageConfig {
            table_name: env::var("DDB_TABLE_NAME")
                .map_err(|_| "Missing required environment variable: DDB_TABLE_NAME")?,
            region: Some(env::var("AWS_REGION").unwrap_or_else(|_| DEFAULT_REGION.to_string())),
            profile: env::var("AWS_PROFILE").ok(),
            endpoint_url: env::var("AWS_ENDPOINT")
                .or_else(|_| env::var("DYNAMODB_ENDPOINT"))
                .ok(),
        })
    }
}

#[async_trait::async_trait]
impl Configs for StorageConfig {
    async fn load() -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let storage_backend_str = env::var("TR_STORAGE_BACKEND")
            .unwrap_or("csv".to_string())
            .to_lowercase();
        let storage_backend = match storage_backend_str.as_str() {
            "dynamodb" | "ddb" => TrustStorageBackend::DynamoDb,
            _ => TrustStorageBackend::Csv,
        };
        Ok(StorageConfig {
            ddb_storage_config: DynamoDbStorageConfig::load().await?,
            file_storage_config: FileStorageConfig::load().await?,
            storage_backend,
        })
    }
}
