//! Pluggable secret-store backend for the Trust Registry's identity.
//!
//! The Trust Registry's identity — its DID plus the private keys in its
//! `PROFILE_CONFIG` bundle — can be provisioned into, and loaded from, any of the
//! backends the Affinidi mediator and did-hosting services use, via the published
//! [`vti_secrets`] crate: AWS Secrets Manager, GCP Secret Manager, Azure Key
//! Vault, HashiCorp Vault, Kubernetes Secret, OS keyring, config-inline, and a
//! plaintext file (dev only). The blob stored in the backend is the profile
//! bundle JSON verbatim (the same content `PROFILE_CONFIG` would hold inline).
//!
//! Backend selection follows `vti-secrets`' priority factory (AWS → GCP → Azure →
//! Vault → K8s → config-seed → keyring → plaintext), keyed by which
//! `TR_SECRETS_*` environment variables are set and which cargo `secrets-*`
//! features are enabled. This keeps the Trust Registry's offline/non-interactive
//! provisioning identical to `mediator-setup` and the did-hosting daemon.

use std::path::{Path, PathBuf};

use vti_secrets::{SecretsConfig, create_seed_store};

/// Default on-disk directory used by the file/plaintext backends and for any
/// backend that needs a scratch location.
const DEFAULT_DATA_DIR: &str = "./.trust-registry";

/// Build a [`SecretsConfig`] from `TR_SECRETS_*` environment variables.
///
/// Every field is optional; unset variables leave the `vti-secrets` default in
/// place. The chosen backend is whichever configured field wins the priority
/// order in [`create_seed_store`].
pub fn secrets_config_from_env() -> SecretsConfig {
    let mut cfg = SecretsConfig::default();
    let set = |name: &str| std::env::var(name).ok().filter(|v| !v.is_empty());

    cfg.seed = set("TR_SECRETS_SEED");
    cfg.aws_secret_name = set("TR_SECRETS_AWS_SECRET_NAME");
    cfg.aws_region = set("TR_SECRETS_AWS_REGION");
    cfg.gcp_project = set("TR_SECRETS_GCP_PROJECT");
    cfg.gcp_secret_name = set("TR_SECRETS_GCP_SECRET_NAME");
    cfg.azure_vault_url = set("TR_SECRETS_AZURE_VAULT_URL");
    cfg.azure_secret_name = set("TR_SECRETS_AZURE_SECRET_NAME");
    if let Some(v) = set("TR_SECRETS_KEYRING_SERVICE") {
        cfg.keyring_service = v;
    }
    cfg.vault_addr = set("TR_SECRETS_VAULT_ADDR");
    cfg.vault_secret_path = set("TR_SECRETS_VAULT_SECRET_PATH");
    cfg.vault_token = set("TR_SECRETS_VAULT_TOKEN");
    cfg.vault_namespace = set("TR_SECRETS_VAULT_NAMESPACE");
    cfg.k8s_secret_name = set("TR_SECRETS_K8S_SECRET_NAME");
    cfg.k8s_namespace = set("TR_SECRETS_K8S_NAMESPACE");
    cfg.allow_plaintext = std::env::var("TR_SECRETS_ALLOW_PLAINTEXT")
        .map(|v| v == "true")
        .unwrap_or(false);
    cfg
}

/// Whether the operator has explicitly configured a remote / keyring / config
/// backend (as opposed to the default inline `PROFILE_CONFIG`).
///
/// A configured backend is the signal that the Trust Registry should load its
/// identity from — or provision it into — the secret store. The implicit keyring
/// default is deliberately **not** counted here, so an unconfigured deployment
/// keeps using `PROFILE_CONFIG` unchanged.
pub fn backend_selected(cfg: &SecretsConfig) -> bool {
    cfg.seed.is_some()
        || cfg.aws_secret_name.is_some()
        || cfg.gcp_secret_name.is_some()
        || cfg.azure_secret_name.is_some()
        || cfg.vault_secret_path.is_some()
        || cfg.k8s_secret_name.is_some()
}

/// The on-disk data directory for file-backed backends (`TR_SECRETS_DATA_DIR`,
/// default `./.trust-registry`).
pub fn data_dir() -> PathBuf {
    std::env::var("TR_SECRETS_DATA_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from(DEFAULT_DATA_DIR))
}

/// Write the profile bundle JSON to the configured backend.
pub async fn write_profile(cfg: &SecretsConfig, dir: &Path, bundle: &str) -> Result<(), String> {
    let store = create_seed_store(cfg, dir).map_err(|e| format!("secret store init: {e}"))?;
    store
        .set(bundle.as_bytes())
        .await
        .map_err(|e| format!("secret store write: {e}"))
}

/// Read the profile bundle JSON from the configured backend, if present.
pub async fn read_profile(cfg: &SecretsConfig, dir: &Path) -> Result<Option<String>, String> {
    let store = create_seed_store(cfg, dir).map_err(|e| format!("secret store init: {e}"))?;
    let bytes = store
        .get()
        .await
        .map_err(|e| format!("secret store read: {e}"))?;
    match bytes {
        Some(bytes) => {
            Ok(Some(String::from_utf8(bytes).map_err(|e| {
                format!("secret store returned non-UTF8 bundle: {e}")
            })?))
        }
        None => Ok(None),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serial_test::serial;

    fn clear_env() {
        for k in [
            "TR_SECRETS_SEED",
            "TR_SECRETS_AWS_SECRET_NAME",
            "TR_SECRETS_GCP_SECRET_NAME",
            "TR_SECRETS_AZURE_SECRET_NAME",
            "TR_SECRETS_VAULT_SECRET_PATH",
            "TR_SECRETS_K8S_SECRET_NAME",
            "TR_SECRETS_KEYRING_SERVICE",
            "TR_SECRETS_ALLOW_PLAINTEXT",
        ] {
            unsafe { std::env::remove_var(k) };
        }
    }

    #[test]
    #[serial]
    fn unconfigured_env_selects_no_explicit_backend() {
        clear_env();
        let cfg = secrets_config_from_env();
        assert!(!backend_selected(&cfg));
    }

    #[test]
    #[serial]
    fn aws_secret_name_selects_backend() {
        clear_env();
        unsafe { std::env::set_var("TR_SECRETS_AWS_SECRET_NAME", "tr/profile") };
        let cfg = secrets_config_from_env();
        assert_eq!(cfg.aws_secret_name.as_deref(), Some("tr/profile"));
        assert!(backend_selected(&cfg));
        clear_env();
    }

    #[test]
    #[serial]
    fn vault_and_keyring_env_map_through() {
        clear_env();
        unsafe {
            std::env::set_var("TR_SECRETS_VAULT_SECRET_PATH", "secret/tr");
            std::env::set_var("TR_SECRETS_KEYRING_SERVICE", "trust-registry");
            std::env::set_var("TR_SECRETS_ALLOW_PLAINTEXT", "true");
        }
        let cfg = secrets_config_from_env();
        assert_eq!(cfg.vault_secret_path.as_deref(), Some("secret/tr"));
        assert_eq!(cfg.keyring_service, "trust-registry");
        assert!(cfg.allow_plaintext);
        assert!(backend_selected(&cfg));
        clear_env();
    }

    #[test]
    fn data_dir_defaults() {
        // Not serial: only asserts the default when the var is absent in most runs.
        let dir = data_dir();
        assert!(dir.as_os_str().len() > 0);
    }
}
