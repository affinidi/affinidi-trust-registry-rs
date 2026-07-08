use std::sync::Arc;

use anyhow::anyhow;

use crate::{
    configs::{TrustRegistryConfig, TrustStorageBackend},
    storage::{
        adapters::{
            csv_file_storage::FileStorage, ddb_storage::DynamoDbStorage,
            redis_storage::RedisStorage,
        },
        repository::TrustRecordAdminRepository,
    },
};

pub struct TrustStorageRepoFactory {
    config: Arc<TrustRegistryConfig>,
}

impl TrustStorageRepoFactory {
    pub fn new(config: Arc<TrustRegistryConfig>) -> Self {
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
                TrustStorageBackend::Fjall => {
                    #[cfg(feature = "storage-fjall")]
                    {
                        let fjall_config = self.config.storage_config.fjall_storage_config.clone();
                        let fjall = crate::storage::adapters::fjall_storage::FjallStorage::new(
                            &fjall_config.path,
                        )
                        .map_err(|e| anyhow!(e.to_string()))?;
                        Arc::new(fjall)
                    }
                    #[cfg(not(feature = "storage-fjall"))]
                    {
                        return Err(anyhow!(
                            "TR_STORAGE_BACKEND=fjall selected but fjall support was not compiled; \
                             rebuild with --features storage-fjall"
                        )
                        .into());
                    }
                }
            };

        Ok(repository)
    }
}
