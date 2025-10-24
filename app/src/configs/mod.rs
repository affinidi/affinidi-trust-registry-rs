use std::env;

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

impl Configs for FileStorageConfig {
    fn load() -> Result<Self, Box<dyn std::error::Error>> {
        Ok(FileStorageConfig {
            path: env::var("FILE_STORAGE_PATH")
                .unwrap_or_else(|_| DEFAULT_TRUST_REGISTRY_FILE_PATH.to_string()),
            update_interval_sec: env::var("FILE_STORAGE_UPDATE_INTERVAL_SEC")
                .unwrap_or_else(|_| DEFAULT_TRUST_REGISTRY_UPDATE_INTERVAL_SEC.to_string())
                .parse::<u64>()?,
        })
    }
}

impl Configs for DynamoDbStorageConfig {
    fn load() -> Result<Self, Box<dyn std::error::Error>> {
        Ok(DynamoDbStorageConfig {
            table_name: env::var("DDB_TABLE_NAME")?,
            region: Some(env::var("AWS_REGION").unwrap_or_else(|_| DEFAULT_REGION.to_string())),
            profile: env::var("AWS_PROFILE").ok(),
            endpoint_url: env::var("AWS_ENDPOINT")
                .or_else(|_| env::var("DYNAMODB_ENDPOINT"))
                .ok(),
        })
    }
}

pub trait Configs: Sized {
    fn load() -> Result<Self, Box<dyn std::error::Error>>;
}
