use app::{configs::Configs, storage::repository::TrustRecordRepository};

use chrono::{DateTime, Utc};
use std::{fmt, sync::Arc};

use crate::configs::HttpServerConfigs;

pub mod configs;
pub mod error;
pub mod handlers;
pub mod server;

pub use error::AppError;

pub struct SharedData<R>
where
    R: TrustRecordRepository + ?Sized,
{
    pub config: HttpServerConfigs,
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
