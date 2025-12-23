use std::sync::Arc;

use anyhow::anyhow;

use crate::{
    configs::{TrsutRegistryConfig, TrustStorageBackend},
    storage::{
        adapters::{csv_file_storage::FileStorage, ddb_storage::DynamoDbStorage, redis_storage::RedisStorage},
        repository::TrustRecordAdminRepository,
    },
};

pub struct TrustStorageRepoFactory {
    config: Arc<TrsutRegistryConfig>,
}

impl TrustStorageRepoFactory {
    pub fn new(config: Arc<TrsutRegistryConfig>) -> Self {
        Self { config }
    }
    pub async fn create(
        &self,
    ) -> Result<Arc<dyn TrustRecordAdminRepository>, Box<dyn std::error::Error>> {
        let repository: Arc<dyn TrustRecordAdminRepository> =
            match self.config.storage_config.storage_backend {
                TrustStorageBackend::Csv => {
                    let config = self.config.storage_config.file_storage_config.clone();
                    let file_storage =
                        FileStorage::try_new(config.path, config.update_interval_sec)
                            .await
                            .map_err(|e| anyhow!(e.to_string()))?;
                    Arc::new(file_storage)
                }
                TrustStorageBackend::DynamoDb => {
                    let ddb_config = self.config.storage_config.ddb_storage_config.clone();
                    let ddb = DynamoDbStorage::new(ddb_config)
                        .await
                        .map_err(|e| anyhow!(e.to_string()))?;
                    Arc::new(ddb)
                }
                TrustStorageBackend::Redis => {
                    let redis_config = self.config.storage_config.redis_storage_config.clone();
                    let redis = RedisStorage::new(&redis_config.redis_url)
                        .await
                        .map_err(|e| anyhow!(e.to_string()))?;
                    Arc::new(redis)
                }
            };

        Ok(repository)
    }
}
