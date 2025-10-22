use app::configs::Configs;
use std::env;

const DEFAULT_LISTEN_ADDRESS: &str = "0.0.0.0:3232";
const DEFAULT_TRUST_REGISTRY_FILE_PATH: &str = "trust_records.csv";
const DEFAULT_TRUST_REGISTRY_UPDATE_INTERVAL_SEC: u64 = 60;

#[derive(Debug, Clone)]
pub struct HttpServerConfigs {
    pub(crate) listen_address: String,
    pub(crate) trust_registry_file_path: String,
    pub(crate) trust_registry_update_interval_sec: u64,
}

impl Configs for HttpServerConfigs {
    fn load() -> Result<Self, Box<dyn std::error::Error>> {
        Ok(HttpServerConfigs {
            listen_address: env::var("LISTEN_ADDRESS")
                .unwrap_or(DEFAULT_LISTEN_ADDRESS.to_string()),
            trust_registry_file_path: env::var("FILE_STORAGE_PATH")
                .unwrap_or_else(|_| DEFAULT_TRUST_REGISTRY_FILE_PATH.to_string()),
            trust_registry_update_interval_sec: env::var("FILE_STORAGE_UPDATE_INTERVAL_SEC")
                .unwrap_or_else(|_| DEFAULT_TRUST_REGISTRY_UPDATE_INTERVAL_SEC.to_string())
                .parse::<u64>()?,
        })
    }
}
