use std::env;

use affinidi_tdk::secrets_resolver::secrets::Secret;
use app::{configs::Configs, storage::adapters::csv_file_storage::FileStorage};
use serde_derive::{Deserialize, Serialize};

const DEFAULT_LISTEN_ADDRESS: &str = "0.0.0.0:3131";

// TODO: is this place good enough to define this struct?
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProfileConfig {
    pub did: String,
    pub alias: String,
    pub secrets: Vec<Secret>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileStorageConfig {
    pub enabled: bool,
    pub file_path: String,
    pub update_interval_sec: u64,
}

#[derive(Debug, Clone)]
pub struct DidcommServerConfigs {
    pub(crate) listen_address: String,
    pub(crate) profile_configs: Vec<ProfileConfig>,
    pub(crate) mediator_did: String,
    pub(crate) file_storage_config: Option<FileStorageConfig>,
}

pub(crate) fn parse_profile_config_from_str(
    did_and_secrets_as_str: &str,
) -> Result<Vec<ProfileConfig>, Box<dyn std::error::Error>> {
    let profile_configs: Vec<ProfileConfig> = serde_json::from_str(did_and_secrets_as_str)?;
    Ok(profile_configs)
}

impl Configs for DidcommServerConfigs {
    fn load() -> Result<Self, Box<dyn std::error::Error>> {
        let use_file_storage = env::var("FILE_STORAGE_ENABLED")
            .unwrap_or("false".to_string())
            .to_lowercase()
            == "true";
        let file_storage_config = if use_file_storage {
            Some(FileStorageConfig {
                enabled: true,
                file_path: env::var("FILE_STORAGE_PATH").unwrap_or("trust_records.csv".to_string()),
                update_interval_sec: env::var("FILE_STORAGE_UPDATE_INTERVAL_SEC")
                    .unwrap_or("60".to_string())
                    .parse::<u64>()?,
            })
        } else {
            None
        };
        Ok(DidcommServerConfigs {
            listen_address: env::var("LISTEN_ADDRESS")
                .unwrap_or(DEFAULT_LISTEN_ADDRESS.to_string()),
            mediator_did: env::var("MEDIATOR_DID")?,
            profile_configs: parse_profile_config_from_str(&env::var("PROFILE_CONFIGS")?)?,
            file_storage_config,
        })
    }
}
