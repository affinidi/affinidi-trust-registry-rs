pub mod didcomm;
pub mod loaders;
pub mod server;
pub mod storage;

pub use didcomm::{AdminConfig, AuditConfig, AuditLogFormat, DidcommConfig, ProfileConfig};
pub use server::ServerConfig;
pub use storage::{DynamoDbStorageConfig, FileStorageConfig, TrustStorageBackend};

use crate::configs::storage::StorageConfig;

#[async_trait::async_trait]
pub trait Configs: Sized {
    async fn load() -> Result<Self, Box<dyn std::error::Error + Send + Sync>>;
}

#[derive(Debug)]
pub struct TrsutRegistryConfig {
    pub server_config: ServerConfig,
    pub storage_config: StorageConfig,
    pub didcomm_config: DidcommConfig,
}

#[async_trait::async_trait]
impl Configs for TrsutRegistryConfig {
    async fn load() -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        Ok(Self {
            server_config: ServerConfig::load().await?,
            storage_config: StorageConfig::load().await?,
            didcomm_config: DidcommConfig::load().await?,
        })
    }
}
