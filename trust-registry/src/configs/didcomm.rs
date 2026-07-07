use affinidi_tdk::{
    messaging::protocols::mediator::acls::AccessListModeType, secrets_resolver::secrets::Secret,
};
use serde_derive::{Deserialize, Serialize};
use std::fmt;
use tracing::warn;

use crate::didcomm::did_document::build_did_document;

use super::{
    Configs,
    loaders::{environment::*, load},
    secret_store,
};

/// Load the profile bundle from a configured secret-store backend, if any.
///
/// Returns `Ok(None)` when no backend is configured (deployment uses inline
/// `PROFILE_CONFIG`) or the backend holds no bundle yet, so the caller falls
/// back to `PROFILE_CONFIG`.
async fn load_profile_from_secret_store() -> Result<Option<String>, String> {
    let cfg = secret_store::secrets_config_from_env();
    if !secret_store::backend_selected(&cfg) {
        return Ok(None);
    }
    secret_store::read_profile(&cfg, &secret_store::data_dir()).await
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AuditLogFormat {
    #[default]
    Text,
    Json,
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
            _ => Err(format!("Invalid audit log format: {s}")),
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct AuditConfig {
    pub log_format: AuditLogFormat,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ProfileConfig {
    pub did: String,
    pub alias: String,
    pub secrets: Vec<Secret>,
}

#[derive(Debug, Clone, Default)]
pub struct AdminConfig {
    pub admin_dids: Vec<String>,
    pub audit_config: AuditConfig,
}

#[derive(Debug, Clone)]
pub struct DidDocumentRetryConfig {
    pub max_attempts: u32,
    pub initial_delay_secs: u64,
    pub max_delay_secs: u64,
}

impl Default for DidDocumentRetryConfig {
    fn default() -> Self {
        Self {
            max_attempts: 10,
            initial_delay_secs: 2,
            max_delay_secs: 30,
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct DidcommConfig {
    pub is_enabled: bool,
    pub acl_mode: AccessListModeType,
    pub profile_config: ProfileConfig,
    pub mediator_did: String,
    pub did_document: String,
    pub admin_config: AdminConfig,
    pub retry_config: DidDocumentRetryConfig,
}

pub fn parse_profile_from_secrets_str(
    did_and_secrets_as_str: &str,
) -> Result<ProfileConfig, Box<dyn std::error::Error + Send + Sync>> {
    let profile_config: ProfileConfig = serde_json::from_str(did_and_secrets_as_str)?;
    Ok(profile_config)
}

#[async_trait::async_trait]
impl Configs for DidcommConfig {
    async fn load() -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let enable_didcomm = env_or("ENABLE_DIDCOMM", "true");
        if enable_didcomm != "true" {
            return Ok(Default::default());
        }
        let acl_mode_raw = env_or("ACL_MODE", "ExplicitDeny");
        let acl_mode = if acl_mode_raw == "ExplicitAllow" {
            AccessListModeType::ExplicitAllow
        } else {
            AccessListModeType::ExplicitDeny
        };

        let admin_dids_str = optional_env("ADMIN_DIDS").unwrap_or_else(|| {
            warn!("Missing environment variable: ADMIN_DIDS. The admin list is empty");
            String::new()
        });
        let admin_dids: Vec<String> = admin_dids_str
            .split(',')
            .map(|e| e.trim().to_string())
            .collect();

        let log_format = env_or("AUDIT_LOG_FORMAT", "text")
            .parse::<AuditLogFormat>()
            .unwrap_or(AuditLogFormat::Text);

        let admin_config = AdminConfig {
            admin_dids,
            audit_config: AuditConfig { log_format },
        };

        let mediator_did = required_env("MEDIATOR_DID")?;

        // Prefer a configured secret-store backend (AWS/GCP/Azure/Vault/K8s/
        // keyring/…) for the profile bundle; fall back to the inline
        // PROFILE_CONFIG URI when no backend is configured or it is empty.
        let profile_configs_str = match load_profile_from_secret_store().await? {
            Some(bundle) => bundle,
            None => {
                let profile_configs_uri = required_env("PROFILE_CONFIG")?;
                load(&profile_configs_uri).await?
            }
        };
        let profile_config = parse_profile_from_secrets_str(&profile_configs_str)?;

        let did_document = if let Some(doc) = optional_env("DID_DOCUMENT") {
            load(&doc).await?
        } else {
            build_did_document(&profile_config, &mediator_did)
        };

        let retry_config = DidDocumentRetryConfig {
            max_attempts: env_or("DID_CHECK_MAX_ATTEMPTS", "10").parse().unwrap_or(10),
            initial_delay_secs: env_or("DID_CHECK_INITIAL_DELAY_SECS", "2")
                .parse()
                .unwrap_or(2),
            max_delay_secs: env_or("DID_CHECK_MAX_DELAY_SECS", "20")
                .parse()
                .unwrap_or(20),
        };

        Ok(DidcommConfig {
            is_enabled: true,
            acl_mode,
            mediator_did,
            profile_config,
            did_document,
            admin_config,
            retry_config,
        })
    }
}
