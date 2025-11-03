use std::sync::Arc;

use anyhow::anyhow;

use crate::{
    configs::{Configs, DynamoDbStorageConfig, FileStorageConfig, TrustStorageBackend},
    storage::{
        adapters::{csv_file_storage::FileStorage, ddb_storage::DynamoDbStorage},
        repository::TrustRecordAdminRepository,
    },
};

pub struct TrustStorageRepoFactory {
    storage_backend: TrustStorageBackend,
}

impl TrustStorageRepoFactory {
    pub fn new(storage_backend: TrustStorageBackend) -> Self {
        Self { storage_backend }
    }
    pub async fn create(
        &self,
    ) -> Result<Arc<dyn TrustRecordAdminRepository>, Box<dyn std::error::Error>> {
        let repository: Arc<dyn TrustRecordAdminRepository> = match self.storage_backend {
            TrustStorageBackend::Csv => {
                let config = FileStorageConfig::load()?;
                let file_storage = FileStorage::try_new(config.path, config.update_interval_sec)
                    .await
                    .map_err(|e| anyhow!(e.to_string()))?;
                Arc::new(file_storage)
            }
            TrustStorageBackend::DynamoDb => {
                let ddb_config = DynamoDbStorageConfig::load()?;
                let ddb = DynamoDbStorage::new(ddb_config)
                    .await
                    .map_err(|e| anyhow!(e.to_string()))?;
                Arc::new(ddb)
            }
        };

        Ok(repository)
    }
}
