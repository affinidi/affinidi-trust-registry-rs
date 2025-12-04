use serde::{Deserialize, Serialize};

use super::{Configs, loaders::environment::*};

const DEFAULT_LISTEN_ADDRESS: &str = "0.0.0.0:3232";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProfileConfig {
    pub did: String,
}

#[derive(Debug, Clone)]
pub struct ServerConfig {
    pub listen_address: String,
    pub cors_allowed_origins: Vec<String>,
}

#[async_trait::async_trait]
impl Configs for ServerConfig {
    async fn load() -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let listen_address = env_or("LISTEN_ADDRESS", DEFAULT_LISTEN_ADDRESS);

        let cors_allowed_origins = optional_env("CORS_ALLOWED_ORIGINS")
            .unwrap_or_default()
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();

        Ok(ServerConfig {
            listen_address,
            cors_allowed_origins,
        })
    }
}
