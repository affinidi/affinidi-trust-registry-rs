use app::{
    configs::Configs,
    storage::repository::TrustRecordRepository,
};

use chrono::{DateTime, Utc};
use dotenvy::dotenv;
use once_cell::sync::Lazy;
use std::{fmt, sync::Arc};
use tracing::error;

use crate::configs::HttpServerConfigs;

pub mod configs;
pub mod error;
pub mod handlers;
pub mod server;

pub use error::AppError;

pub static CONFIG: Lazy<HttpServerConfigs> = Lazy::new(|| {
    dotenv().ok();
    match HttpServerConfigs::load() {
        Ok(config) => config,
        Err(e) => {
            error!("Missing environment variable: {}", e);
            panic!("Failed to load configuration due to missing environment variable");
        }
    }
});

#[derive(Clone)]
pub struct SharedData<R: TrustRecordRepository> {
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
