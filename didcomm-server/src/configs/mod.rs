use std::env;

use affinidi_tdk::secrets_resolver::secrets::Secret;
use app::configs::{AuditConfig, AuditLogFormat, Configs, TrustStorageBackend};
use async_trait::async_trait;
use serde_derive::{Deserialize, Serialize};

const DEFAULT_LISTEN_ADDRESS: &str = "0.0.0.0:3131";

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
pub struct AdminApiConfig {
    pub admin_dids: Vec<String>,
    pub audit_config: AuditConfig,
}

#[derive(Debug, Clone)]
pub struct DidcommServerConfigs {
    pub(crate) listen_address: String,
    pub(crate) profile_config: ProfileConfig,
    pub(crate) mediator_did: String,
    pub(crate) admin_api_config: AdminApiConfig,
    pub(crate) storage_backend: TrustStorageBackend,
}

pub(crate) fn parse_profile_config_from_str(
    did_and_secrets_as_str: &str,
) -> Result<ProfileConfig, Box<dyn std::error::Error>> {
    let profile_config: ProfileConfig = serde_json::from_str(did_and_secrets_as_str)?;
    Ok(profile_config)
}

#[async_trait]
impl Configs for DidcommServerConfigs {
    async fn load() -> Result<Self, Box<dyn std::error::Error>> {
        let storage_backend_str = env::var("TR_STORAGE_BACKEND")
            .unwrap_or("csv".to_string())
            .to_lowercase();
        let storage_backend = match storage_backend_str.as_str() {
            "dynamodb" | "ddb" => TrustStorageBackend::DynamoDb,
            _ => TrustStorageBackend::Csv,
        };

        let admin_dids_str = env::var("ADMIN_DIDS").unwrap_or_default();
        let admin_dids: Vec<String> = admin_dids_str
            .split(',')
            .map(|e| e.trim().to_string())
            .collect();

        let audit_log_format = env::var("AUDIT_LOG_FORMAT")
            .unwrap_or_else(|_| "text".to_string())
            .parse::<AuditLogFormat>()
            .unwrap_or(AuditLogFormat::Text);

        let audit_config = AuditConfig {
            log_format: audit_log_format,
        };

        let admin_api_config = AdminApiConfig {
            admin_dids,
            audit_config,
        };

        Ok(DidcommServerConfigs {
            listen_address: env::var("LISTEN_ADDRESS")
                .unwrap_or(DEFAULT_LISTEN_ADDRESS.to_string()),
            mediator_did: env::var("MEDIATOR_DID")?,
            profile_config: parse_profile_config_from_str(&env::var("PROFILE_CONFIG")?)?,
            admin_api_config,
            storage_backend,
        })
    }
}
