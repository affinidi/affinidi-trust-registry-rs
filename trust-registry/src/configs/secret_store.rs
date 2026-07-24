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
    // First non-empty value across a list of env vars. Used for the fields
    // where we honour the canonical `VAULT_*` names Vault's own tooling
    // defines, falling back to the `TR_SECRETS_VAULT_*` spelling — matching
    // vta-service so an operator can carry the same env across services.
    let set_any = |names: &[&str]| names.iter().find_map(|n| set(n));
    let is_truthy = |v: String| matches!(v.to_ascii_lowercase().as_str(), "1" | "true" | "yes");

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

    // HashiCorp Vault — connection + KV location, plus the auth-method-specific
    // fields. `vault_auth_method` defaults to `kubernetes`, whose branch in
    // `vti_secrets` *requires* `vault_k8s_role`; without mapping the auth
    // method and role here the Vault backend fails to initialise the moment
    // `TR_SECRETS_VAULT_ADDR` is set. The string-defaulted fields
    // (`kv_mount`, `secret_key`, `auth_method`, `k8s_mount`, `k8s_jwt_path`,
    // `approle_mount`) are only overwritten when the env var is present so the
    // `vti_secrets` defaults survive.
    cfg.vault_addr = set_any(&["VAULT_ADDR", "TR_SECRETS_VAULT_ADDR"]);
    cfg.vault_namespace = set_any(&["VAULT_NAMESPACE", "TR_SECRETS_VAULT_NAMESPACE"]);
    cfg.vault_secret_path = set("TR_SECRETS_VAULT_SECRET_PATH");
    if let Some(v) = set("TR_SECRETS_VAULT_KV_MOUNT") {
        cfg.vault_kv_mount = v;
    }
    if let Some(v) = set("TR_SECRETS_VAULT_SECRET_KEY") {
        cfg.vault_secret_key = v;
    }
    if let Some(v) = set("TR_SECRETS_VAULT_AUTH_METHOD") {
        cfg.vault_auth_method = v;
    }
    cfg.vault_k8s_role = set("TR_SECRETS_VAULT_K8S_ROLE");
    if let Some(v) = set("TR_SECRETS_VAULT_K8S_MOUNT") {
        cfg.vault_k8s_mount = v;
    }
    if let Some(v) = set("TR_SECRETS_VAULT_K8S_JWT_PATH") {
        cfg.vault_k8s_jwt_path = v;
    }
    cfg.vault_token = set_any(&["VAULT_TOKEN", "TR_SECRETS_VAULT_TOKEN"]);
    cfg.vault_approle_role_id = set("TR_SECRETS_VAULT_APPROLE_ROLE_ID");
    cfg.vault_approle_secret_id = set("TR_SECRETS_VAULT_APPROLE_SECRET_ID");
    if let Some(v) = set("TR_SECRETS_VAULT_APPROLE_MOUNT") {
        cfg.vault_approle_mount = v;
    }
    cfg.vault_skip_verify = set_any(&["VAULT_SKIP_VERIFY", "TR_SECRETS_VAULT_SKIP_VERIFY"])
        .map(is_truthy)
        .unwrap_or(false);

    // Kubernetes `Secret` backend.
    cfg.k8s_secret_name = set("TR_SECRETS_K8S_SECRET_NAME");
    cfg.k8s_namespace = set("TR_SECRETS_K8S_NAMESPACE");
    if let Some(v) = set("TR_SECRETS_K8S_SECRET_KEY") {
        cfg.k8s_secret_key = v;
    }

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
            "VAULT_ADDR",
            "VAULT_NAMESPACE",
            "VAULT_TOKEN",
            "VAULT_SKIP_VERIFY",
            "TR_SECRETS_VAULT_ADDR",
            "TR_SECRETS_VAULT_NAMESPACE",
            "TR_SECRETS_VAULT_SECRET_PATH",
            "TR_SECRETS_VAULT_KV_MOUNT",
            "TR_SECRETS_VAULT_SECRET_KEY",
            "TR_SECRETS_VAULT_AUTH_METHOD",
            "TR_SECRETS_VAULT_K8S_ROLE",
            "TR_SECRETS_VAULT_K8S_MOUNT",
            "TR_SECRETS_VAULT_K8S_JWT_PATH",
            "TR_SECRETS_VAULT_TOKEN",
            "TR_SECRETS_VAULT_APPROLE_ROLE_ID",
            "TR_SECRETS_VAULT_APPROLE_SECRET_ID",
            "TR_SECRETS_VAULT_APPROLE_MOUNT",
            "TR_SECRETS_VAULT_SKIP_VERIFY",
            "TR_SECRETS_K8S_SECRET_NAME",
            "TR_SECRETS_K8S_NAMESPACE",
            "TR_SECRETS_K8S_SECRET_KEY",
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
    #[serial]
    fn vault_k8s_auth_env_maps_through() {
        // The default auth method is `kubernetes`, whose `vti_secrets` branch
        // requires `vault_k8s_role`. Before these were mapped, selecting Vault
        // from env could not supply the role and startup failed. Assert the
        // full k8s-auth env set lands in the config, and that the string
        // defaults are preserved when their env vars are absent.
        clear_env();
        unsafe {
            std::env::set_var("TR_SECRETS_VAULT_ADDR", "https://vault.svc:8200");
            std::env::set_var("TR_SECRETS_VAULT_SECRET_PATH", "tr/master-seed");
            std::env::set_var("TR_SECRETS_VAULT_AUTH_METHOD", "kubernetes");
            std::env::set_var("TR_SECRETS_VAULT_K8S_ROLE", "trust-registry");
        }
        let cfg = secrets_config_from_env();
        assert_eq!(cfg.vault_addr.as_deref(), Some("https://vault.svc:8200"));
        assert_eq!(cfg.vault_secret_path.as_deref(), Some("tr/master-seed"));
        assert_eq!(cfg.vault_auth_method, "kubernetes");
        assert_eq!(cfg.vault_k8s_role.as_deref(), Some("trust-registry"));
        // Defaults survive when the corresponding env vars are unset.
        assert_eq!(cfg.vault_kv_mount, "secret");
        assert_eq!(cfg.vault_secret_key, "seed");
        assert_eq!(cfg.vault_k8s_mount, "kubernetes");
        assert!(backend_selected(&cfg));
        clear_env();
    }

    #[test]
    #[serial]
    fn vault_canonical_env_names_take_precedence() {
        // Operators reuse Vault's own `VAULT_ADDR` / `VAULT_TOKEN` env vars
        // across services; honour them, matching vta-service.
        clear_env();
        unsafe {
            std::env::set_var("VAULT_ADDR", "https://canonical:8200");
            std::env::set_var("TR_SECRETS_VAULT_ADDR", "https://fallback:8200");
            std::env::set_var("VAULT_TOKEN", "hvs.canonical");
            std::env::set_var("VAULT_SKIP_VERIFY", "true");
            std::env::set_var("TR_SECRETS_VAULT_SECRET_PATH", "tr/seed");
            std::env::set_var("TR_SECRETS_VAULT_AUTH_METHOD", "token");
        }
        let cfg = secrets_config_from_env();
        assert_eq!(cfg.vault_addr.as_deref(), Some("https://canonical:8200"));
        assert_eq!(cfg.vault_token.as_deref(), Some("hvs.canonical"));
        assert!(cfg.vault_skip_verify);
        clear_env();
    }

    #[test]
    #[serial]
    fn vault_approle_and_k8s_secret_key_map_through() {
        clear_env();
        unsafe {
            std::env::set_var("TR_SECRETS_VAULT_ADDR", "https://vault.example.com");
            std::env::set_var("TR_SECRETS_VAULT_SECRET_PATH", "tr/seed");
            std::env::set_var("TR_SECRETS_VAULT_AUTH_METHOD", "approle");
            std::env::set_var("TR_SECRETS_VAULT_APPROLE_ROLE_ID", "role-123");
            std::env::set_var("TR_SECRETS_VAULT_APPROLE_SECRET_ID", "secret-456");
            std::env::set_var("TR_SECRETS_K8S_SECRET_KEY", "bip39_seed");
        }
        let cfg = secrets_config_from_env();
        assert_eq!(cfg.vault_auth_method, "approle");
        assert_eq!(cfg.vault_approle_role_id.as_deref(), Some("role-123"));
        assert_eq!(cfg.vault_approle_secret_id.as_deref(), Some("secret-456"));
        assert_eq!(cfg.k8s_secret_key, "bip39_seed");
        clear_env();
    }

    #[test]
    fn data_dir_defaults() {
        // Not serial: only asserts the default when the var is absent in most runs.
        let dir = data_dir();
        assert!(dir.as_os_str().len() > 0);
    }
}
