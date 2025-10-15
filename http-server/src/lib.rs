use app::configs::Configs;

use chrono::{DateTime, Utc};
use dotenvy::dotenv;
use once_cell::sync::Lazy;
use std::fmt::Debug;
use tracing::error;

use crate::configs::HttpServerConfigs;

pub mod configs;
pub mod handlers;
pub mod server;

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
pub struct SharedData {
    pub config: HttpServerConfigs,
    pub service_start_timestamp: DateTime<Utc>,
}

impl Debug for SharedData {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SharedData")
            .field("config", &self.config)
            .field("service_start_timestamp", &self.service_start_timestamp)
            .finish()
    }
}
