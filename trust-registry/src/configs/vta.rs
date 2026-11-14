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
//! ## Mediator connection keys
//!
//! When the VTA path is enabled, the bundle it returns *is* the Trust Registry's
//! `ProfileConfig` (`{did, alias, secrets}`), and those same `secrets` are the
//! keys the DIDComm/TSP mediator connection authenticates with: the config
//! layer feeds this profile into
//! [`Listener::build_listener`](crate::didcomm::listener::Listener::build_listener),
//! which builds a `TDKProfile::new(alias, did, Some(mediator_did), secrets)` and
//! authenticates to the mediator with it. There is therefore no separate
//! "mediator key" provisioning step — sourcing the profile from the VTA sources
//! the mediator connection keys from the VTA in the same act.
//!
//! ## Configuration
//!
//! Read once by [`VtaConfig::from_env`] while the configuration loads, and
//! held in [`DidcommConfig::vta`](crate::configs::DidcommConfig::vta):
//! - `TR_VTA_CREDENTIAL` — the VTA `CredentialBundle` JSON, or a loader URI
//!   (`file://`, `aws_secrets://`, …) resolving to it. Presence enables the VTA path.
//! - `TR_VTA_CONTEXT_ID` — the VTA context holding this service's DID + keys.
//! - `TR_VTA_URL` — optional VTA URL override (else taken from the credential).
//! - `TR_ALIAS` — profile alias (default `Trust Registry`).
//!
//! ## Offline cache
//!
//! The cache lives in its own slot of the configured secret store, never in the
//! slot that holds a provisioned profile bundle: the backend's secret name (or
//! Vault path, Kubernetes `Secret` name, keyring service) with
//! [`VTA_CACHE_SUFFIX`] appended, and for the plaintext file backend the
//! [`VTA_CACHE_DIR`] subdirectory of `TR_SECRETS_DATA_DIR`. With no backend
//! configured the cache needs `TR_SECRETS_ALLOW_PLAINTEXT=true` (dev/test), as
//! a `--features vta` build has no keyring; without either, startup warns that
//! there is no offline cache.

use std::path::{Path, PathBuf};

use affinidi_did_common::scid::strip_scid_src;
use serde_json::json;
use tracing::warn;
use vta_sdk::credentials::CredentialBundle;
use vta_sdk::did_key::secrets_from_bundle;
use vta_sdk::did_secrets::DidSecretsBundle;
use vta_sdk::integration::{SecretCache, VtaServiceConfig, startup};
use vti_secrets::{SecretBackend, SecretsConfig, create_seed_store};

use super::loaders::{environment::non_empty_env, load_setting};
use super::secret_store;

use crate::BoxError;

/// Appended to the configured secret name (Vault path, `Secret` name, keyring
/// service) to make the VTA cache's own slot.
pub const VTA_CACHE_SUFFIX: &str = "-vta-cache";

/// Subdirectory of the data directory the plaintext-file cache is kept in.
pub const VTA_CACHE_DIR: &str = "vta-cache";

const DEFAULT_ALIAS: &str = "Trust Registry";

/// The VTA settings, resolved once while the configuration loads.
#[derive(Clone, Debug)]
pub struct VtaConfig {
    /// The credential the registry authenticates to the VTA with. Its `Debug`
    /// leaves the private key out.
    pub credential: CredentialBundle,
    /// The VTA context holding this service's DID and keys.
    pub context_id: String,
    /// Overrides the VTA URL inside the credential.
    pub url_override: Option<String>,
    /// The profile alias.
    pub alias: String,
}

impl VtaConfig {
    /// Read `TR_VTA_*` and `TR_ALIAS`, resolving the credential through the
    /// loaders. `None` when `TR_VTA_CREDENTIAL` is unset.
    pub async fn from_env() -> Result<Option<Self>, String> {
        let Some(credential_uri) = non_empty_env("TR_VTA_CREDENTIAL") else {
            return Ok(None);
        };
        let context_id = non_empty_env("TR_VTA_CONTEXT_ID").ok_or_else(|| {
            "TR_VTA_CREDENTIAL is set but TR_VTA_CONTEXT_ID is missing".to_string()
        })?;

        // Resolve the credential via the standard loaders so it can live in a
        // file, AWS Secrets Manager, etc.
        let credential_json = load_setting("TR_VTA_CREDENTIAL", &credential_uri).await?;
        let credential: CredentialBundle = serde_json::from_str(&credential_json)
            .map_err(|e| format!("TR_VTA_CREDENTIAL is not a VTA credential bundle: {e}"))?;

        Ok(Some(Self {
            credential,
            context_id,
            url_override: non_empty_env("TR_VTA_URL"),
            alias: non_empty_env("TR_ALIAS").unwrap_or_else(|| DEFAULT_ALIAS.to_string()),
        }))
    }

    fn service_config(&self) -> VtaServiceConfig {
        let mut config = VtaServiceConfig::new(self.credential.clone(), self.context_id.clone());
        config.auth.url_override = self.url_override.clone();
        config
    }
}

/// The cache's own slot in the store `cfg` selects: each backend's secret name
/// with [`VTA_CACHE_SUFFIX`] appended, and `data_dir`/[`VTA_CACHE_DIR`] for
/// the file backends.
pub fn vta_cache_slot(cfg: &SecretsConfig, data_dir: &Path) -> (SecretsConfig, PathBuf) {
    let mut cache = cfg.clone();
    for name in [
        &mut cache.aws_secret_name,
        &mut cache.gcp_secret_name,
        &mut cache.azure_secret_name,
        &mut cache.vault_secret_path,
        &mut cache.k8s_secret_name,
    ]
    .into_iter()
    .flatten()
    {
        name.push_str(VTA_CACHE_SUFFIX);
    }
    cache.keyring_service.push_str(VTA_CACHE_SUFFIX);
    (cache, data_dir.join(VTA_CACHE_DIR))
}

/// Offline cache for the VTA secrets bundle, persisted through the Trust
/// Registry's configured secret-store backend in a slot of its own (see
/// [`vta_cache_slot`]), so the service can boot while the VTA is unreachable.
pub struct VtaSecretCache {
    /// The configured store: where a provisioned profile bundle lives, and
    /// where releases before the cache had its own slot wrote the cache.
    store: SecretsConfig,
    data_dir: PathBuf,
}

impl VtaSecretCache {
    pub fn new(store: SecretsConfig, data_dir: PathBuf) -> Self {
        Self { store, data_dir }
    }

    /// `TR_SECRETS_SEED` is read-only and holds the profile itself, so it has
    /// no slot for a cache.
    fn read_only(&self) -> bool {
        secret_store::selected_backend(&self.store) == Some(SecretBackend::ConfigSeed)
    }

    fn slot(&self) -> (SecretsConfig, PathBuf) {
        vta_cache_slot(&self.store, &self.data_dir)
    }

    /// Whether the cache store can be built; `Err` says what to set.
    pub fn check(&self) -> Result<(), String> {
        if self.read_only() {
            return Err(
                "the selected secret store (TR_SECRETS_SEED) is read-only and cannot hold \
                 the VTA offline cache"
                    .to_string(),
            );
        }
        let (cfg, dir) = self.slot();
        create_seed_store(&cfg, &dir).map(|_| ()).map_err(|e| {
            format!(
                "{e}. Configure a secret-store backend (TR_SECRETS_BACKEND and its \
                 TR_SECRETS_* settings) or, for development only, set \
                 TR_SECRETS_ALLOW_PLAINTEXT=true to cache under TR_SECRETS_DATA_DIR"
            )
        })
    }
}

impl SecretCache for VtaSecretCache {
    async fn store(&self, bundle: &DidSecretsBundle) -> Result<(), BoxError> {
        if self.read_only() {
            return Err("the TR_SECRETS_SEED store is read-only; no VTA cache written".into());
        }
        // `DidSecretsBundle` has no encode()/decode(); serialise with serde_json.
        let json = serde_json::to_string(bundle).map_err(|e| Box::new(e) as BoxError)?;
        let (cfg, dir) = self.slot();
        secret_store::write_profile(&cfg, &dir, &json)
            .await
            .map_err(BoxError::from)
    }

    async fn load(&self) -> Result<Option<DidSecretsBundle>, BoxError> {
        if self.read_only() {
            return Ok(None);
        }
        let (cfg, dir) = self.slot();
        match secret_store::read_profile(&cfg, &dir).await {
            Ok(Some(json)) => {
                return Ok(Some(
                    serde_json::from_str(&json).map_err(|e| Box::new(e) as BoxError)?,
                ));
            }
            Ok(None) => {}
            // The legacy slot below may still hold a usable cache, and with
            // the VTA unreachable it is the only way to boot; so a failed read
            // here is reported, not returned.
            Err(e) => warn!(
                "could not read the VTA offline cache from its own slot ({e}); trying the \
                 profile bundle's slot, where releases before it kept the cache"
            ),
        }
        // Releases before the cache had its own slot wrote it where the
        // profile bundle lives. Read a cache found there, so an upgrade while
        // the VTA is down still boots; anything else there (a provisioned
        // profile) is left alone and never overwritten.
        match secret_store::read_profile(&self.store, &self.data_dir).await {
            Ok(Some(json)) => match serde_json::from_str::<DidSecretsBundle>(&json) {
                Ok(bundle) => {
                    warn!(
                        "using the VTA offline cache found in the profile bundle's slot, which \
                         is no longer refreshed: the next successful VTA fetch writes the cache \
                         to its own slot"
                    );
                    Ok(Some(bundle))
                }
                Err(_) => Ok(None),
            },
            Ok(None) | Err(_) => Ok(None),
        }
    }
}

/// Authenticate to the configured VTA and pull the Trust Registry's identity,
/// returning it as a `PROFILE_CONFIG`-shaped JSON string (`{alias, did,
/// secrets}`) so it flows through the same parsing path as the other sources.
///
/// `cache` is the offline cache, built from the secret-store settings loaded
/// with the rest of the configuration. Propagates an error when neither the
/// live fetch nor the offline cache yields a bundle — the caller must not
/// silently fall back to a different identity.
pub async fn startup_profile_json(
    vta: &VtaConfig,
    cache: &VtaSecretCache,
) -> Result<String, String> {
    if let Err(e) = cache.check() {
        warn!(
            "VTA offline cache unavailable, so the registry cannot start while the VTA is \
             unreachable: {e}"
        );
    }
    let result = startup(&vta.service_config(), cache)
        .await
        .map_err(|e| format!("VTA startup failed: {e}"))?;

    let secrets = secrets_from_bundle(&result.bundle)
        .map_err(|e| format!("failed to decode VTA secrets bundle: {e}"))?;

    let profile = json!({
        "alias": vta.alias,
        "did": result.did,
        "secrets": secrets,
    });
    Ok(profile.to_string())
}

/// Why a rotation did not happen.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RotateError {
    pub reason: String,
    /// Whether the same request may succeed later: a failure reaching the
    /// VTA or resolving the DID, not one of the registry's own setup.
    pub transient: bool,
}

impl RotateError {
    fn permanent(reason: String) -> Self {
        Self {
            reason,
            transient: false,
        }
    }

    fn transient(reason: String) -> Self {
        Self {
            reason,
            transient: true,
        }
    }
}

impl std::fmt::Display for RotateError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.reason)
    }
}

/// Rotate the Trust Registry's VTA-managed `did:webvh` keys.
///
/// Builds a [`vta_sdk::client::VtaClient`] from the credential loaded with the
/// configuration (`vta`, `None` when no VTA is configured) and calls the VTA's
/// canonical `webvh/dids/rotate-keys/1.0` task, which keys on the DID itself —
/// no context id or SCID needed. Returns `(did, new_scid, new_version_id)` on
/// success.
///
/// `did` must be a `did:webvh`, or a `did:scid:vh:1` (VTI-KEY-160), whose log
/// is a did:webvh log and is rotated as one; rejecting anything else here
/// keeps the failure local instead of surfacing as a VTA-side protocol error.
/// The returned DID is `did` as the registry presents it: for a did:scid, its
/// bare DID, which a rotation does not change.
pub async fn rotate_did(
    vta: Option<&VtaConfig>,
    did: &str,
    pre_rotation_count: Option<u32>,
    label: Option<String>,
) -> Result<(String, String, String), RotateError> {
    use vta_sdk::client::VtaClient;
    use vta_sdk::protocols::did_management::update::RotateDidWebvhKeysBody;

    let vta = vta.ok_or_else(|| {
        RotateError::permanent("VTA is not configured (TR_VTA_CREDENTIAL unset)".to_string())
    })?;
    let webvh_did = webvh_log_did(did).await?;

    let client = VtaClient::from_credential(&vta.credential, vta.url_override.as_deref())
        .await
        .map_err(|e| RotateError::transient(format!("VTA authentication failed: {e}")))?;

    let body = RotateDidWebvhKeysBody {
        pre_rotation_count,
        label,
    };
    let result = client
        .rotate_did_webvh_keys_by_did(&webvh_did, body)
        .await
        .map_err(|e| RotateError::transient(format!("VTA did:webvh key rotation failed: {e}")))?;

    let did = if did.starts_with("did:scid:") {
        strip_scid_src(did).into_owned()
    } else {
        result.did
    };
    Ok((did, result.new_scid, result.new_version_id))
}

/// The did:webvh DID of `did`'s log: `did` itself for a did:webvh, and for a
/// `did:scid:vh:1` the did:webvh its own resolved document lists in
/// `alsoKnownAs` (VTI-KEY-161), which is the log the VTA rotates.
///
/// A bare did:scid resolves only through a source the resolver already holds,
/// which a fresh one does not; configure the registry's DID as its DID URL
/// (`did:scid:vh:1:<scid>?src=…`) for this to find the log.
async fn webvh_log_did(did: &str) -> Result<String, RotateError> {
    if did
        .strip_prefix("did:webvh:")
        .and_then(|rest| rest.split(':').next())
        .is_some_and(|scid| !scid.is_empty())
    {
        return Ok(did.to_string());
    }
    let Some(scid) = did
        .strip_prefix("did:scid:vh:1:")
        .map(|rest| rest.split(['?', '#']).next().unwrap_or(rest))
        .filter(|s| !s.is_empty())
    else {
        return Err(RotateError::permanent(format!(
            "DID {did} is not a did:webvh or did:scid:vh:1; cannot rotate its keys"
        )));
    };

    use affinidi_tdk::did_resolver::{DIDCacheClient, config::DIDCacheConfigBuilder};
    let resolver = DIDCacheClient::new(DIDCacheConfigBuilder::default().build())
        .await
        .map_err(|e| {
            RotateError::transient(format!(
                "cannot build a DID resolver to find {did}'s log: {e}"
            ))
        })?;
    let resolved = resolver.resolve(did).await.map_err(|e| {
        RotateError::transient(format!(
            "cannot resolve {did} to find its did:webvh log: {e}"
        ))
    })?;
    let prefix = format!("did:webvh:{scid}:");
    resolved
        .doc
        .also_known_as
        .iter()
        .find(|alias| alias.starts_with(&prefix))
        .cloned()
        .ok_or_else(|| {
            RotateError::permanent(format!("{did}'s document names no did:webvh log to rotate"))
        })
}

#[cfg(test)]
// `std::env::{set_var, remove_var}` are unsafe since edition 2024.
#[allow(unsafe_code)]
mod tests {
    use super::*;
    use serial_test::serial;

    fn clear_vta_env() {
        for k in [
            "TR_VTA_CREDENTIAL",
            "TR_VTA_CONTEXT_ID",
            "TR_VTA_URL",
            "TR_ALIAS",
        ] {
            unsafe { std::env::remove_var(k) };
        }
    }

    #[tokio::test]
    #[serial]
    async fn no_vta_configured_returns_none() {
        clear_vta_env();
        assert!(VtaConfig::from_env().await.expect("ok").is_none());
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
        let err = VtaConfig::from_env().await.expect_err("no context");
        assert!(err.contains("TR_VTA_CONTEXT_ID"), "{err}");
        clear_vta_env();
    }

    #[tokio::test]
    #[serial]
    async fn a_mistyped_credential_scheme_names_the_variable() {
        clear_vta_env();
        unsafe {
            std::env::set_var("TR_VTA_CREDENTIAL", "flie:///etc/tr/vta.json");
            std::env::set_var("TR_VTA_CONTEXT_ID", "ctx-1");
        }
        let err = VtaConfig::from_env().await.expect_err("bad scheme");
        assert!(err.starts_with("TR_VTA_CREDENTIAL: "), "{err}");
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
            std::env::set_var("TR_VTA_URL", "https://override.example");
        }
        let vta = VtaConfig::from_env().await.expect("ok").expect("some");
        assert_eq!(vta.alias, DEFAULT_ALIAS);
        let cfg = vta.service_config();
        assert_eq!(cfg.context.id, "ctx-1");
        assert_eq!(cfg.auth.credential.did, "did:web:svc");
        assert_eq!(
            cfg.auth.url_override.as_deref(),
            Some("https://override.example")
        );
        // The private key stays out of a config dump.
        assert!(!format!("{vta:?}").contains("z6Mkexample"));
        clear_vta_env();
    }

    /// Rotation takes its credential from the configuration, not from the
    /// environment at request time.
    #[tokio::test]
    #[serial]
    async fn rotation_without_a_configured_vta_is_refused() {
        clear_vta_env();
        unsafe {
            std::env::set_var(
                "TR_VTA_CREDENTIAL",
                r#"string://{"did":"did:web:svc","privateKeyMultibase":"z0","vtaDid":"did:web:vta"}"#,
            );
        }
        let err = rotate_did(None, "did:webvh:Qm:example.com", None, None)
            .await
            .expect_err("no VTA");
        assert!(err.reason.contains("not configured"), "{err}");
        assert!(!err.transient, "a missing VTA is not fixed by retrying");
        clear_vta_env();
    }

    fn plaintext_store() -> SecretsConfig {
        let mut cfg = SecretsConfig::default();
        cfg.backend = Some(SecretBackend::Plaintext);
        cfg.allow_plaintext = true;
        cfg
    }

    fn bundle() -> DidSecretsBundle {
        DidSecretsBundle {
            did: "did:webvh:QmCache:example.com".to_string(),
            secrets: Vec::new(),
        }
    }

    /// With the documented development cache (plaintext under the data dir)
    /// a stored bundle loads back, and it is written to its own slot rather
    /// than over the profile bundle.
    #[tokio::test]
    async fn the_cache_round_trips_in_its_own_slot() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = plaintext_store();
        let profile = r#"{"alias":"TR","did":"did:example:tr","secrets":[]}"#;
        secret_store::write_profile(&store, dir.path(), profile)
            .await
            .expect("profile written");

        let cache = VtaSecretCache::new(store.clone(), dir.path().to_path_buf());
        cache.check().expect("cache store available");
        cache.store(&bundle()).await.expect("stored");
        let loaded = cache.load().await.expect("loads").expect("cached");
        assert_eq!(loaded.did, bundle().did);

        assert_eq!(
            secret_store::read_profile(&store, dir.path())
                .await
                .expect("read")
                .as_deref(),
            Some(profile),
            "the profile bundle's slot is untouched"
        );
    }

    /// A cache written by an earlier release into the profile's slot is still
    /// found; a profile bundle there is not mistaken for a cache.
    #[tokio::test]
    async fn the_cache_reads_a_legacy_cache_but_not_a_profile() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = plaintext_store();
        let cache = VtaSecretCache::new(store.clone(), dir.path().to_path_buf());
        assert!(cache.load().await.expect("empty").is_none());

        let profile = r#"{"alias":"TR","did":"did:example:tr","secrets":[{"id":"k"}]}"#;
        secret_store::write_profile(&store, dir.path(), profile)
            .await
            .expect("written");
        assert!(cache.load().await.expect("not a cache").is_none());

        let legacy = serde_json::to_string(&bundle()).expect("json");
        secret_store::write_profile(&store, dir.path(), &legacy)
            .await
            .expect("written");
        let loaded = cache.load().await.expect("loads").expect("legacy cache");
        assert_eq!(loaded.did, bundle().did);
    }

    /// A cache slot that cannot be read is no reason to skip the legacy slot:
    /// with the VTA down, the legacy cache may be the only way to boot.
    #[tokio::test]
    async fn an_unreadable_cache_slot_falls_back_to_the_legacy_slot() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = plaintext_store();
        let cache = VtaSecretCache::new(store.clone(), dir.path().to_path_buf());
        cache.store(&bundle()).await.expect("stored");
        // Corrupt every file in the cache's own slot.
        let slot_dir = dir.path().join(VTA_CACHE_DIR);
        for entry in std::fs::read_dir(&slot_dir).expect("cache slot exists") {
            let path = entry.expect("entry").path();
            if path.is_file() {
                std::fs::write(&path, [0xff, 0xfe, 0xfd]).expect("corrupted");
            }
        }
        assert!(
            secret_store::read_profile(&vta_cache_slot(&store, dir.path()).0, &slot_dir)
                .await
                .is_err(),
            "the cache slot is unreadable"
        );

        let legacy = serde_json::to_string(&bundle()).expect("json");
        secret_store::write_profile(&store, dir.path(), &legacy)
            .await
            .expect("written");
        let loaded = cache
            .load()
            .await
            .expect("an unreadable slot is not fatal")
            .expect("legacy cache");
        assert_eq!(loaded.did, bundle().did);
    }

    /// Without a backend or the plaintext opt-in, the cache cannot be kept,
    /// and the check says which variables to set.
    #[cfg(not(feature = "secrets-keyring"))]
    #[test]
    fn an_unavailable_cache_names_what_to_set() {
        let dir = tempfile::tempdir().expect("tempdir");
        let cache = VtaSecretCache::new(SecretsConfig::default(), dir.path().to_path_buf());
        let err = cache.check().expect_err("no store");
        assert!(err.contains("TR_SECRETS_ALLOW_PLAINTEXT"), "{err}");
    }

    #[test]
    fn the_cache_slot_differs_from_the_profile_slot() {
        let mut cfg = SecretsConfig::default();
        cfg.aws_secret_name = Some("tr/profile".to_string());
        cfg.vault_secret_path = Some("tr/seed".to_string());
        let (cache, dir) = vta_cache_slot(&cfg, Path::new("/srv/tr"));
        assert_eq!(
            cache.aws_secret_name.as_deref(),
            Some("tr/profile-vta-cache")
        );
        assert_eq!(
            cache.vault_secret_path.as_deref(),
            Some("tr/seed-vta-cache")
        );
        assert_eq!(cache.gcp_secret_name, None);
        assert_ne!(cache.keyring_service, cfg.keyring_service);
        assert_eq!(dir, Path::new("/srv/tr").join(VTA_CACHE_DIR));
    }
}
