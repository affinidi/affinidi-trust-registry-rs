//! Verifiable Trust Agent (VTA) as the Trust Registry's identity source.
//!
//! Feature-gated behind `vta`. When configured, the Trust Registry fetches its
//! DID and private keys from a VTA at startup via
//! [`vta_sdk::integration::startup`], instead of loading them from an inline
//! `PROFILE_CONFIG` or a secret-store bundle. The VTA performs remote key custody
//! (BIP-32 derivation); `startup` authenticates, pulls a [`DidSecretsBundle`],
//! and caches it so the Trust Registry survives the VTA being briefly offline.
//!
//! The offline cache is implemented as a [`SecretCache`] over the same pluggable
//! secret-store backends as the rest of the Trust Registry (see
//! [`crate::configs::secret_store`]): AWS/GCP/Azure/Vault/K8s/keyring/plaintext.
//!
//! Configuration (env):
//! - `TR_VTA_CREDENTIAL` — the VTA `CredentialBundle` JSON, or a loader URI
//!   (`file://`, `aws_secrets://`, …) resolving to it. Presence enables the VTA path.
//! - `TR_VTA_CONTEXT_ID` — the VTA context holding this service's DID + keys.
//! - `TR_VTA_URL` — optional VTA URL override (else taken from the credential).
//! - `TR_ALIAS` — profile alias (default `Trust Registry`).

use serde_json::json;
use vta_sdk::credentials::CredentialBundle;
use vta_sdk::did_key::secrets_from_bundle;
use vta_sdk::did_secrets::DidSecretsBundle;
use vta_sdk::integration::{SecretCache, VtaServiceConfig, startup};

use super::loaders::{environment::optional_env, load};
use super::secret_store;

type BoxError = Box<dyn std::error::Error + Send + Sync>;

/// Offline cache for the VTA secrets bundle, persisted through the Trust
/// Registry's configured secret-store backend (the same `TR_SECRETS_*` backends
/// used for the profile bundle). In VTA mode that backend holds the cached
/// bundle so the service can boot while the VTA is unreachable.
pub struct VtaSecretCache;

impl SecretCache for VtaSecretCache {
    async fn store(&self, bundle: &DidSecretsBundle) -> Result<(), BoxError> {
        // `DidSecretsBundle` has no encode()/decode(); serialise with serde_json.
        let json = serde_json::to_string(bundle).map_err(|e| Box::new(e) as BoxError)?;
        let cfg = secret_store::secrets_config_from_env();
        secret_store::write_profile(&cfg, &secret_store::data_dir(), &json)
            .await
            .map_err(BoxError::from)?;
        Ok(())
    }

    async fn load(&self) -> Result<Option<DidSecretsBundle>, BoxError> {
        let cfg = secret_store::secrets_config_from_env();
        match secret_store::read_profile(&cfg, &secret_store::data_dir())
            .await
            .map_err(BoxError::from)?
        {
            Some(json) => Ok(Some(
                serde_json::from_str(&json).map_err(|e| Box::new(e) as BoxError)?,
            )),
            None => Ok(None),
        }
    }
}

/// Build a [`VtaServiceConfig`] from the environment, or `None` when the VTA path
/// is not configured (`TR_VTA_CREDENTIAL` unset).
async fn vta_config_from_env() -> Result<Option<VtaServiceConfig>, String> {
    let Some(credential_uri) = optional_env("TR_VTA_CREDENTIAL") else {
        return Ok(None);
    };
    let context_id = optional_env("TR_VTA_CONTEXT_ID")
        .ok_or_else(|| "TR_VTA_CREDENTIAL is set but TR_VTA_CONTEXT_ID is missing".to_string())?;

    // Resolve the credential via the standard loaders so it can live in a file,
    // AWS Secrets Manager, etc.
    let credential_json = load(&credential_uri).await?;
    let credential: CredentialBundle = serde_json::from_str(&credential_json)
        .map_err(|e| format!("invalid TR_VTA_CREDENTIAL bundle: {e}"))?;

    let mut config = VtaServiceConfig::new(credential, context_id);
    if let Some(url) = optional_env("TR_VTA_URL") {
        config.auth.url_override = Some(url);
    }
    Ok(Some(config))
}

/// If a VTA is configured, authenticate and pull the Trust Registry's identity,
/// returning it as a `PROFILE_CONFIG`-shaped JSON string (`{alias, did,
/// secrets}`) so it flows through the same parsing path as the other sources.
///
/// Returns `Ok(None)` when no VTA is configured. Propagates an error when a VTA
/// is configured but neither the live fetch nor the offline cache yields a
/// bundle — the caller must not silently fall back to a different identity.
pub async fn startup_profile_json() -> Result<Option<String>, String> {
    let Some(config) = vta_config_from_env().await? else {
        return Ok(None);
    };

    let cache = VtaSecretCache;
    let result = startup(&config, &cache)
        .await
        .map_err(|e| format!("VTA startup failed: {e}"))?;

    let secrets = secrets_from_bundle(&result.bundle)
        .map_err(|e| format!("failed to decode VTA secrets bundle: {e}"))?;

    let alias = optional_env("TR_ALIAS").unwrap_or_else(|| "Trust Registry".to_string());
    let profile = json!({
        "alias": alias,
        "did": result.did,
        "secrets": secrets,
    });
    Ok(Some(profile.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serial_test::serial;

    fn clear_vta_env() {
        for k in ["TR_VTA_CREDENTIAL", "TR_VTA_CONTEXT_ID", "TR_VTA_URL"] {
            unsafe { std::env::remove_var(k) };
        }
    }

    #[tokio::test]
    #[serial]
    async fn no_vta_configured_returns_none() {
        clear_vta_env();
        assert!(vta_config_from_env().await.expect("ok").is_none());
        assert!(startup_profile_json().await.expect("ok").is_none());
    }

    #[tokio::test]
    #[serial]
    async fn credential_without_context_errors() {
        clear_vta_env();
        unsafe {
            std::env::set_var(
                "TR_VTA_CREDENTIAL",
                r#"string://{"did":"did:web:svc","privateKeyMultibase":"z0","vtaDid":"did:web:vta"}"#,
            );
        }
        assert!(vta_config_from_env().await.is_err());
        clear_vta_env();
    }

    #[tokio::test]
    #[serial]
    async fn valid_credential_builds_config() {
        clear_vta_env();
        unsafe {
            std::env::set_var(
                "TR_VTA_CREDENTIAL",
                r#"string://{"did":"did:web:svc","privateKeyMultibase":"z6Mkexample","vtaDid":"did:web:vta","vtaUrl":"https://vta.example"}"#,
            );
            std::env::set_var("TR_VTA_CONTEXT_ID", "ctx-1");
        }
        let cfg = vta_config_from_env().await.expect("ok").expect("some");
        assert_eq!(cfg.context.id, "ctx-1");
        assert_eq!(cfg.auth.credential.did, "did:web:svc");
        clear_vta_env();
    }
}
