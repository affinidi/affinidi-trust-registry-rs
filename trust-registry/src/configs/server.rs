use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use super::{Configs, loaders::environment::*};

const DEFAULT_LISTEN_ADDRESS: &str = "0.0.0.0:3232";
pub const DEFAULT_CAPABILITY_STATE_PATH: &str = "./.trust-registry/capabilities.json";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProfileConfig {
    pub did: String,
}

#[derive(Debug, Clone)]
pub struct ServerConfig {
    pub listen_address: String,
    pub cors_allowed_origins: Vec<String>,
    /// Where capability enablement state is persisted.
    ///
    /// `None` means "use [`DEFAULT_CAPABILITY_STATE_PATH`]", which is relative
    /// to the process working directory. A host embedding the registry should
    /// set this explicitly: the default would otherwise land the registry's
    /// state file in whatever directory the host happens to run from, and two
    /// embedded registries in one process would silently share it.
    pub capability_state_path: Option<PathBuf>,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            listen_address: DEFAULT_LISTEN_ADDRESS.to_string(),
            cors_allowed_origins: Vec::new(),
            capability_state_path: None,
        }
    }
}

impl ServerConfig {
    /// The capability state path to use, applying the default when unset.
    pub fn capability_state_path(&self) -> PathBuf {
        self.capability_state_path
            .clone()
            .unwrap_or_else(|| PathBuf::from(DEFAULT_CAPABILITY_STATE_PATH))
    }
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
            capability_state_path: optional_env("TR_CAPABILITY_STATE").map(PathBuf::from),
        })
    }
}
