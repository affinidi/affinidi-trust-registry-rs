use super::{Configs, loaders::environment::*};

const DEFAULT_TRUST_REGISTRY_FILE_PATH: &str = "trust_records.csv";
const DEFAULT_TRUST_REGISTRY_UPDATE_INTERVAL_SEC: u64 = 60;
const DEFAULT_REGION: &str = "ap-southeast-1";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrustStorageBackend {
    Csv,
    DynamoDb,
    Redis,
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

#[derive(Debug, Clone, Default)]
pub struct RedisStorageConfig {
    pub is_enabled: bool,
    pub redis_url: String,
}

#[derive(Debug, Clone)]
pub struct StorageConfig {
    pub ddb_storage_config: DynamoDbStorageConfig,
    pub file_storage_config: FileStorageConfig,
    pub redis_storage_config: RedisStorageConfig,
    pub storage_backend: TrustStorageBackend,
}

fn load_storage_backend() -> TrustStorageBackend {
    let storage_backend_str = env_or("TR_STORAGE_BACKEND", "csv").to_lowercase();
    match storage_backend_str.as_str() {
        "dynamodb" | "ddb" => TrustStorageBackend::DynamoDb,
        "redis" => TrustStorageBackend::Redis,
        _ => TrustStorageBackend::Csv,
    }
}

#[async_trait::async_trait]
impl Configs for FileStorageConfig {
    async fn load() -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        if load_storage_backend() == TrustStorageBackend::Csv {
            Ok(FileStorageConfig {
                is_enabled: true,
                path: env_or("FILE_STORAGE_PATH", DEFAULT_TRUST_REGISTRY_FILE_PATH),
                update_interval_sec: env_or(
                    "FILE_STORAGE_UPDATE_INTERVAL_SEC",
                    &DEFAULT_TRUST_REGISTRY_UPDATE_INTERVAL_SEC.to_string(),
                )
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
                table_name: required_env("DDB_TABLE_NAME")?,
                region: Some(env_or("AWS_REGION", DEFAULT_REGION)),
                profile: optional_env("AWS_PROFILE"),
                endpoint_url: optional_env("AWS_ENDPOINT")
                    .or_else(|| optional_env("DYNAMODB_ENDPOINT")),
            })
        } else {
            Ok(Default::default())
        }
    }
}

#[async_trait::async_trait]
impl Configs for RedisStorageConfig {
    async fn load() -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        if load_storage_backend() == TrustStorageBackend::Redis {
            Ok(RedisStorageConfig {
                is_enabled: true,
                redis_url: required_env("REDIS_URL")?,
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
            redis_storage_config: RedisStorageConfig::load().await?,
            storage_backend,
        })
    }
}
