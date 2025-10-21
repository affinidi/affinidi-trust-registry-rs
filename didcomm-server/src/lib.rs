use app::configs::Configs as _;
use dotenvy::dotenv;
use once_cell::sync::Lazy;
use tracing::error;

use crate::configs::DidcommServerConfigs;

pub mod configs;
pub mod handlers;
pub mod listener;
pub mod server;
pub mod handlers;

pub static CONFIG: Lazy<DidcommServerConfigs> = Lazy::new(|| {
    dotenv().ok();
    match DidcommServerConfigs::load() {
        Ok(config) => config,
        Err(e) => {
            error!("Missing environment variable: {}", e);
            panic!(
                "Failed to load configuration due to missing environment variable OR wrong env value"
            );
        }
    }
});
