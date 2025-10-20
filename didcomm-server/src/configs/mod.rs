use std::env;

use affinidi_tdk::secrets_resolver::secrets::Secret;
use app::configs::Configs;
use serde_derive::{Deserialize, Serialize};

const DEFAULT_LISTEN_ADDRESS: &str = "0.0.0.0:3131";

// TODO: is this place good enough to define this struct?
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProfileConfig {
    pub did: String,
    pub alias: String,
    pub secrets: Vec<Secret>,
}

#[derive(Debug, Clone)]
pub struct DidcommServerConfigs {
    pub(crate) listen_address: String,
    pub(crate) profile_configs: Vec<ProfileConfig>,
    pub(crate) mediator_did: String,
}

pub(crate) fn parse_profile_config_from_str(
    did_and_secrets_as_str: &str,
) -> Result<Vec<ProfileConfig>, Box<dyn std::error::Error>> {
    let profile_configs: Vec<ProfileConfig> = serde_json::from_str(did_and_secrets_as_str)?;
    Ok(profile_configs)
}

impl Configs for DidcommServerConfigs {
    fn load() -> Result<Self, Box<dyn std::error::Error>> {
        Ok(DidcommServerConfigs {
            listen_address: env::var("LISTEN_ADDRESS")
                .unwrap_or(DEFAULT_LISTEN_ADDRESS.to_string()),
            mediator_did: env::var("MEDIATOR_DID")?,
            profile_configs: parse_profile_config_from_str(&env::var("PROFILE_CONFIGS")?)?,
        })
    }
}
