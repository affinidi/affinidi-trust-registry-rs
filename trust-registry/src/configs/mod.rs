pub mod didcomm;
pub mod loaders;
/// Pluggable secret stores for the registry's own identity bundle.
///
/// Compiled only when a `secrets-*` feature is on. Without one the registry has
/// no secret store, and the identity comes from `PROFILE_CONFIG` or from the
/// host that embedded it.
#[cfg(feature = "secrets")]
pub mod secret_store;
pub mod server;
pub mod storage;

#[cfg(feature = "vta")]
pub mod vta;

pub use didcomm::{AdminConfig, AuditConfig, AuditLogFormat, DidcommConfig, ProfileConfig};
pub use server::{DEFAULT_CAPABILITY_STATE_PATH, ServerConfig};
pub use storage::{
    DynamoDbStorageConfig, FileStorageConfig, FjallStorageConfig, RedisStorageConfig,
    StorageConfig, TrustStorageBackend,
};

/// Load a configuration section from the process environment.
///
/// This trait is the **only** place the registry reads environment variables.
/// A host embedding the registry builds [`TrustRegistryConfig`] directly instead
/// (see [`TrustRegistryConfig::embedded`]) and never touches it, so the host's
/// environment cannot silently reconfigure the registry.
#[async_trait::async_trait]
pub trait Configs: Sized {
    async fn load() -> Result<Self, Box<dyn std::error::Error + Send + Sync>>;
}

#[derive(Debug, Default)]
pub struct TrustRegistryConfig {
    pub server_config: ServerConfig,
    pub storage_config: StorageConfig,
    pub didcomm_config: DidcommConfig,
}

impl TrustRegistryConfig {
    /// A config for an embedded registry: REST-only, no DIDComm listener, and
    /// capability state written under `data_dir`.
    ///
    /// The starting point for a host that owns its own process. Every field is
    /// public, so adjust from here — enable DIDComm by replacing
    /// `didcomm_config`, pick a backend via `storage_config.storage_backend`,
    /// and so on.
    ///
    /// `listen_address` is left at its default but is irrelevant when the host
    /// mounts the registry's router into its own server rather than calling
    /// [`crate::server::serve`].
    pub fn embedded(data_dir: impl Into<std::path::PathBuf>) -> Self {
        let data_dir = data_dir.into();
        Self {
            server_config: ServerConfig {
                capability_state_path: Some(data_dir.join("capabilities.json")),
                ..Default::default()
            },
            storage_config: StorageConfig::default(),
            didcomm_config: DidcommConfig::disabled(),
        }
    }
}

#[async_trait::async_trait]
impl Configs for TrustRegistryConfig {
    async fn load() -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        Ok(Self {
            server_config: ServerConfig::load().await?,
            storage_config: StorageConfig::load().await?,
            didcomm_config: DidcommConfig::load().await?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serial_test::serial;

    /// The whole point of `embedded`: a host's environment must not reach into
    /// the registry's configuration. Set every variable `Configs::load` reads
    /// and assert none of them lands.
    #[test]
    #[serial]
    fn embedded_config_ignores_the_environment() {
        unsafe {
            std::env::set_var("LISTEN_ADDRESS", "10.0.0.1:9999");
            std::env::set_var("CORS_ALLOWED_ORIGINS", "https://evil.example");
            std::env::set_var("TR_CAPABILITY_STATE", "/tmp/hijacked.json");
            std::env::set_var("TR_STORAGE_BACKEND", "redis");
            std::env::set_var("ENABLE_DIDCOMM", "true");
        }

        let config = TrustRegistryConfig::embedded("/srv/host/registry");

        assert_eq!(config.server_config.listen_address, "0.0.0.0:3232");
        assert!(config.server_config.cors_allowed_origins.is_empty());
        assert_eq!(
            config.server_config.capability_state_path(),
            std::path::PathBuf::from("/srv/host/registry/capabilities.json")
        );
        assert_eq!(
            config.storage_config.storage_backend,
            TrustStorageBackend::default()
        );
        assert!(!config.didcomm_config.is_enabled);

        unsafe {
            for k in [
                "LISTEN_ADDRESS",
                "CORS_ALLOWED_ORIGINS",
                "TR_CAPABILITY_STATE",
                "TR_STORAGE_BACKEND",
                "ENABLE_DIDCOMM",
            ] {
                std::env::remove_var(k);
            }
        }
    }

    /// `is_enabled` and `transport_flags.didcomm` must agree, or `/health` and
    /// the startup transport summary advertise a transport nothing answers.
    #[test]
    fn disabled_didcomm_config_is_self_consistent() {
        let cfg = DidcommConfig::disabled();
        assert!(!cfg.is_enabled);
        assert!(!cfg.transport_flags.didcomm);
        assert!(!cfg.transport_flags.tsp);
        assert!(
            cfg.transport_flags.rest,
            "a REST-only registry still serves REST"
        );
        cfg.transport_flags
            .validate()
            .expect("REST-only is a valid transport set");
    }

    /// An unset path keeps the historical default, so existing deployments that
    /// relied on `TR_CAPABILITY_STATE` being absent are unaffected.
    #[test]
    fn capability_state_path_defaults_when_unset() {
        let cfg = ServerConfig::default();
        assert_eq!(cfg.capability_state_path, None);
        assert_eq!(
            cfg.capability_state_path(),
            std::path::PathBuf::from(DEFAULT_CAPABILITY_STATE_PATH)
        );
    }
}
