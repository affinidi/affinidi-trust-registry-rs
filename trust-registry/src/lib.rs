use crate::storage::repository::TrustRecordRepository;
use chrono::{DateTime, Utc};
use std::{fmt, sync::Arc};

pub mod audit;
pub mod configs;
pub mod didcomm;
pub mod domain;
pub mod http;
pub mod server;
pub mod storage;

pub struct SharedData<R>
where
    R: TrustRecordRepository + ?Sized,
{
    pub config: configs::ServerConfig,
    pub service_start_timestamp: DateTime<Utc>,
    pub repository: Arc<R>,
}

impl<R: TrustRecordRepository> fmt::Debug for SharedData<R> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SharedData")
            .field("config", &self.config)
            .field("service_start_timestamp", &self.service_start_timestamp)
            .finish()
    }
}

impl<R> Clone for SharedData<R>
where
    R: TrustRecordRepository + ?Sized,
{
    fn clone(&self) -> Self {
        Self {
            config: self.config.clone(),
            service_start_timestamp: self.service_start_timestamp.clone(),
            repository: Arc::clone(&self.repository),
        }
    }
}
