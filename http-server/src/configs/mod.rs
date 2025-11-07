use app::configs::{Configs, TrustStorageBackend};
use serde::{Deserialize, Serialize};
use std::env;
use tracing::warn;

const DEFAULT_LISTEN_ADDRESS: &str = "0.0.0.0:3232";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProfileConfig {
    pub did: String,
}

#[derive(Debug, Clone)]
pub struct HttpServerConfigs {
    pub(crate) listen_address: String,
    pub(crate) storage_backend: TrustStorageBackend,
    pub(crate) cors_allowed_origins: Vec<String>,
    pub(crate) profile_configs: Vec<ProfileConfig>,
}

impl Configs for HttpServerConfigs {
    fn load() -> Result<Self, Box<dyn std::error::Error>> {
        let backend = env::var("TR_STORAGE_BACKEND")
            .unwrap_or_else(|_| "csv".into())
            .to_lowercase();

        let storage_backend = match backend.as_str() {
            "csv" => TrustStorageBackend::Csv,
            "ddb" | "dynamodb" => TrustStorageBackend::DynamoDb,
            other => return Err(format!("Unsupported TR_STORAGE_BACKEND={other}").into()),
        };

        let listen_address =
            env::var("LISTEN_ADDRESS").unwrap_or(DEFAULT_LISTEN_ADDRESS.to_string());

        let cors_allowed_origins = env::var("CORS_ALLOWED_ORIGINS")
            .unwrap_or_else(|_| String::new())
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();

        let profile_configs = match env::var("PROFILE_CONFIGS") {
            Ok(s) => match serde_json::from_str::<Vec<ProfileConfig>>(&s) {
                Ok(cfgs) => cfgs,
                Err(e) => {
                    warn!("Failed to parse PROFILE_CONFIGS as JSON: {e}");
                    Vec::new()
                }
            },
            Err(_) => {
                warn!("Env var PROFILE_CONFIGS is not provided. The list will be empty");
                Vec::new()
            }
        };

        Ok(HttpServerConfigs {
            listen_address,
            storage_backend,
            cors_allowed_origins,
            profile_configs,
        })
    }
}
