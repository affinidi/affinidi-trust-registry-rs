use std::sync::Arc;

use anyhow::anyhow;

use crate::{
    configs::{TrustRegistryConfig, TrustStorageBackend},
    storage::repository::TrustRecordAdminRepository,
};

/// Error for a backend that was selected in config but not compiled in.
///
/// Each backend is behind a feature so an embedding host only pays for what it
/// uses. Selecting one that is absent is a startup failure naming the feature to
/// add — never a silent fallback to a different store, which would look like
/// data loss.
#[cfg_attr(
    all(
        feature = "storage-csv",
        feature = "storage-ddb",
        feature = "storage-redis",
        feature = "storage-fjall"
    ),
    allow(dead_code)
)]
fn backend_not_compiled(selected: &str, feature: &str) -> Box<dyn std::error::Error> {
    anyhow!(
        "TR_STORAGE_BACKEND={selected} was selected but that backend is not compiled in; \
         rebuild with --features {feature}"
    )
    .into()
}

pub struct TrustStorageRepoFactory {
    config: Arc<TrustRegistryConfig>,
}

impl TrustStorageRepoFactory {
    pub fn new(config: Arc<TrustRegistryConfig>) -> Self {
        Self { config }
    }

    /// Build the configured backend.
    ///
    /// With no `storage-*` feature compiled every arm below diverges, so the
    /// tail is genuinely dead. That is a legitimate build: a host that hands the
    /// registry its own `Arc<dyn TrustRecordAdminRepository>` through the
    /// builder never calls this factory at all.
    #[cfg_attr(
        not(any(
            feature = "storage-csv",
            feature = "storage-ddb",
            feature = "storage-redis",
            feature = "storage-fjall"
        )),
        allow(unreachable_code, unused_variables)
    )]
    pub async fn create(
        &self,
    ) -> Result<Arc<dyn TrustRecordAdminRepository>, Box<dyn std::error::Error>> {
        let repository: Arc<dyn TrustRecordAdminRepository> =
            match self.config.storage_config.storage_backend {
                TrustStorageBackend::Csv => {
                    #[cfg(feature = "storage-csv")]
                    {
                        let config = self.config.storage_config.file_storage_config.clone();
                        let file_storage =
                            crate::storage::adapters::csv_file_storage::FileStorage::try_new(
                                config.path,
                                config.update_interval_sec,
                            )
                            .await
                            .map_err(|e| anyhow!(e.to_string()))?;
                        Arc::new(file_storage)
                    }
                    #[cfg(not(feature = "storage-csv"))]
                    return Err(backend_not_compiled("csv", "storage-csv"));
                }
                TrustStorageBackend::DynamoDb => {
                    #[cfg(feature = "storage-ddb")]
                    {
                        let ddb_config = self.config.storage_config.ddb_storage_config.clone();
                        let ddb =
                            crate::storage::adapters::ddb_storage::DynamoDbStorage::new(ddb_config)
                                .await
                                .map_err(|e| anyhow!(e.to_string()))?;
                        Arc::new(ddb)
                    }
                    #[cfg(not(feature = "storage-ddb"))]
                    return Err(backend_not_compiled("dynamodb", "storage-ddb"));
                }
                TrustStorageBackend::Redis => {
                    #[cfg(feature = "storage-redis")]
                    {
                        let redis_config = self.config.storage_config.redis_storage_config.clone();
                        let redis = crate::storage::adapters::redis_storage::RedisStorage::new(
                            &redis_config.redis_url,
                        )
                        .await
                        .map_err(|e| anyhow!(e.to_string()))?;
                        Arc::new(redis)
                    }
                    #[cfg(not(feature = "storage-redis"))]
                    return Err(backend_not_compiled("redis", "storage-redis"));
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
                    return Err(backend_not_compiled("fjall", "storage-fjall"));
                }
            };

        Ok(repository)
    }
}
