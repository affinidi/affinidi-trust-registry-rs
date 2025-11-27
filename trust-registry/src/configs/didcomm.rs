use affinidi_tdk::secrets_resolver::secrets::Secret;
use serde_derive::{Deserialize, Serialize};
use std::{env, fmt};
use tracing::warn;

use super::Configs;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AuditLogFormat {
    Text,
    Json,
}

impl Default for AuditLogFormat {
    fn default() -> Self {
        Self::Text
    }
}

impl fmt::Display for AuditLogFormat {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Text => write!(f, "text"),
            Self::Json => write!(f, "json"),
        }
    }
}

impl std::str::FromStr for AuditLogFormat {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "text" => Ok(Self::Text),
            "json" => Ok(Self::Json),
            _ => Err(format!("Invalid audit log format: {}", s)),
        }
    }
}

#[derive(Debug, Clone)]
pub struct AuditConfig {
    pub log_format: AuditLogFormat,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProfileConfig {
    pub did: String,
    pub alias: String,
    pub secrets: Vec<Secret>,
}

#[derive(Debug, Clone)]
pub struct AdminConfig {
    pub admin_dids: Vec<String>,
    pub audit_config: AuditConfig,
}

#[derive(Debug, Clone)]
pub struct DidcommConfig {
    pub profile_configs: Vec<ProfileConfig>,
    pub mediator_did: String,
    pub admin_config: AdminConfig,
}

pub fn parse_profile_config_from_str(
    did_and_secrets_as_str: &str,
) -> Result<Vec<ProfileConfig>, Box<dyn std::error::Error + Send + Sync>> {
    let profile_configs: Vec<ProfileConfig> = serde_json::from_str(did_and_secrets_as_str)?;
    Ok(profile_configs)
}

#[async_trait::async_trait]
impl Configs for DidcommConfig {
    async fn load() -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let admin_dids_str = env::var("ADMIN_DIDS")
            .inspect_err(|_| {
                warn!("Missing environment variable: ADMIN_DIDS. The admin list is empty");
            })
            .unwrap_or_default();
        let admin_dids: Vec<String> = admin_dids_str
            .split(',')
            .map(|e| e.trim().to_string())
            .collect();

        let log_format = env::var("AUDIT_LOG_FORMAT")
            .unwrap_or_else(|_| "text".to_string())
            .parse::<AuditLogFormat>()
            .unwrap_or(AuditLogFormat::Text);

        let admin_config = AdminConfig {
            admin_dids,
            audit_config: AuditConfig { log_format },
        };

        let mediator_did = env::var("MEDIATOR_DID")
            .map_err(|_| "Missing required environment variable: MEDIATOR_DID")?;

        let profile_configs_str = env::var("PROFILE_CONFIGS")
            .map_err(|_| "Missing required environment variable: PROFILE_CONFIGS")?;
        Ok(DidcommConfig {
            mediator_did,
            profile_configs: parse_profile_config_from_str(&profile_configs_str)?,
            admin_config,
        })
    }
}
