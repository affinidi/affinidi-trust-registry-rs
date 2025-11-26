use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::env;
use std::fmt;

pub mod did_document_loader;

const DEFAULT_TRUST_REGISTRY_FILE_PATH: &str = "trust_records.csv";
const DEFAULT_TRUST_REGISTRY_UPDATE_INTERVAL_SEC: u64 = 60;
const DEFAULT_REGION: &str = "ap-southeast-1";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AuditLogFormat {
    Text,
    Json,
}

impl Default for AuditLogFormat {
    fn default() -> Self {
        Self::Text
    }
}

impl fmt::Display for AuditLogFormat {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Text => write!(f, "text"),
            Self::Json => write!(f, "json"),
        }
    }
}

impl std::str::FromStr for AuditLogFormat {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "text" => Ok(Self::Text),
            "json" => Ok(Self::Json),
            _ => Err(format!("Invalid audit log format: {}", s)),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditConfig {
    pub log_format: AuditLogFormat,
}

#[async_trait]
impl Configs for AuditConfig {
    async fn load() -> Result<Self, Box<dyn std::error::Error>> {
        let log_format = env::var("AUDIT_LOG_FORMAT")
            .unwrap_or_else(|_| "text".to_string())
            .parse::<AuditLogFormat>()?;

        Ok(AuditConfig { log_format })
    }
}

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

#[async_trait]
impl Configs for FileStorageConfig {
    async fn load() -> Result<Self, Box<dyn std::error::Error>> {
        Ok(FileStorageConfig {
            path: env::var("FILE_STORAGE_PATH")
                .unwrap_or_else(|_| DEFAULT_TRUST_REGISTRY_FILE_PATH.to_string()),
            update_interval_sec: env::var("FILE_STORAGE_UPDATE_INTERVAL_SEC")
                .unwrap_or_else(|_| DEFAULT_TRUST_REGISTRY_UPDATE_INTERVAL_SEC.to_string())
                .parse::<u64>()
                .map_err(|_| "FILE_STORAGE_UPDATE_INTERVAL_SEC must be a valid number")?,
        })
    }
}

#[async_trait]
impl Configs for DynamoDbStorageConfig {
    async fn load() -> Result<Self, Box<dyn std::error::Error>> {
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

#[async_trait]
pub trait Configs: Sized {
    async fn load() -> Result<Self, Box<dyn std::error::Error>>;
}
