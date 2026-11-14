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
//! ## Which backend
//!
//! `TR_SECRETS_BACKEND` names the backend outright and is passed to
//! `vti-secrets` as [`SecretsConfig::backend`]. Without it the backend is the
//! one whose selector variable is set — `TR_SECRETS_AWS_SECRET_NAME`,
//! `TR_SECRETS_GCP_SECRET_NAME`, `TR_SECRETS_AZURE_VAULT_URL`, the Vault
//! address, `TR_SECRETS_K8S_SECRET_NAME` or `TR_SECRETS_SEED` — and setting
//! more than one of them is an error rather than a silent pick by priority.
//! [`selected_backend`] applies exactly the rule [`create_seed_store`] does, so
//! the registry and `vti-secrets` cannot disagree about whether, and which, a
//! backend is in use.
//!
//! Half-configured backends are refused with the missing variable's name:
//! Azure needs its vault URL and secret name, Vault its address and secret
//! path, GCP its project and secret name. The canonical `VAULT_*` variables
//! Vault's own tooling reads are honoured only once Vault is requested
//! (`TR_SECRETS_VAULT_SECRET_PATH` or `TR_SECRETS_BACKEND=vault`), so a host
//! exporting `VAULT_ADDR` for unrelated tooling does not redirect or break the
//! registry.

use std::path::{Path, PathBuf};

use vti_secrets::{SecretBackend, SecretsConfig, create_seed_store};

use super::loaders::environment::{env_flag, non_empty_env};

/// Default on-disk directory used by the file/plaintext backends and for any
/// backend that needs a scratch location.
pub const DEFAULT_DATA_DIR: &str = "./.trust-registry";

/// The `TR_SECRETS_BACKEND` names, as `vti-secrets` spells them.
const BACKEND_NAMES: &[(&str, SecretBackend)] = &[
    ("aws", SecretBackend::Aws),
    ("gcp", SecretBackend::Gcp),
    ("azure", SecretBackend::Azure),
    ("vault", SecretBackend::Vault),
    ("kubernetes", SecretBackend::Kubernetes),
    ("config_seed", SecretBackend::ConfigSeed),
    ("keyring", SecretBackend::Keyring),
    ("plaintext", SecretBackend::Plaintext),
];

/// The `TR_SECRETS_BACKEND` value naming `backend`, for logs and errors.
pub fn backend_name(backend: SecretBackend) -> &'static str {
    BACKEND_NAMES
        .iter()
        .find(|(_, b)| *b == backend)
        .map_or("other", |(name, _)| name)
}

/// Parse `TR_SECRETS_BACKEND`. `encrypted_file` is not offered: it needs a
/// key-encryption-key table that has no environment form.
pub fn parse_secret_backend(raw: &str) -> Result<SecretBackend, String> {
    let wanted = raw.trim().to_ascii_lowercase();
    BACKEND_NAMES
        .iter()
        .find(|(name, _)| *name == wanted)
        .map(|(_, backend)| *backend)
        .ok_or_else(|| {
            let names: Vec<&str> = BACKEND_NAMES.iter().map(|(name, _)| *name).collect();
            format!(
                "TR_SECRETS_BACKEND must be one of {} (got '{}')",
                names.join(", "),
                raw.trim()
            )
        })
}

/// `VAULT_SKIP_VERIFY` and its `TR_SECRETS_` spelling follow Vault's own
/// convention (`1`/`true`/`yes`); anything unrecognised is an error.
fn vault_bool(name: &str, raw: &str) -> Result<bool, String> {
    match raw.trim().to_ascii_lowercase().as_str() {
        "1" | "true" | "yes" => Ok(true),
        "0" | "false" | "no" => Ok(false),
        _ => Err(format!(
            "{name} must be one of true/false, 1/0, yes/no (got '{}')",
            raw.trim()
        )),
    }
}

/// Build a [`SecretsConfig`] from `TR_SECRETS_*` environment variables.
///
/// Unset variables leave the `vti-secrets` default in place. A half-configured
/// backend, more than one implicitly selected backend, or an unparseable value
/// is an error naming the variable to fix (see the module docs).
pub fn secrets_config_from_env() -> Result<SecretsConfig, String> {
    let mut cfg = SecretsConfig::default();
    let set = non_empty_env;
    // First non-empty value across a list of env vars, with the name it came
    // from.
    let set_any = |names: &[&'static str]| names.iter().find_map(|n| set(n).map(|v| (*n, v)));

    cfg.backend = set("TR_SECRETS_BACKEND")
        .map(|raw| parse_secret_backend(&raw))
        .transpose()?;
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

    // HashiCorp Vault. Requested by its secret path or the explicit selector;
    // only then are the canonical `VAULT_*` names (which take precedence over
    // the `TR_SECRETS_VAULT_*` spelling, matching vta-service) consulted.
    let vault_path = set("TR_SECRETS_VAULT_SECRET_PATH");
    let vault_requested = vault_path.is_some() || cfg.backend == Some(SecretBackend::Vault);
    if vault_requested {
        cfg.vault_addr = set_any(&["VAULT_ADDR", "TR_SECRETS_VAULT_ADDR"]).map(|(_, v)| v);
        cfg.vault_namespace =
            set_any(&["VAULT_NAMESPACE", "TR_SECRETS_VAULT_NAMESPACE"]).map(|(_, v)| v);
        cfg.vault_token = set_any(&["VAULT_TOKEN", "TR_SECRETS_VAULT_TOKEN"]).map(|(_, v)| v);
        cfg.vault_skip_verify = set_any(&["VAULT_SKIP_VERIFY", "TR_SECRETS_VAULT_SKIP_VERIFY"])
            .map(|(name, v)| vault_bool(name, &v))
            .transpose()?
            .unwrap_or(false);
    } else if set("TR_SECRETS_VAULT_ADDR").is_some() {
        return Err(
            "TR_SECRETS_VAULT_ADDR is set but TR_SECRETS_VAULT_SECRET_PATH is not; set both \
             to use Vault, or neither"
                .to_string(),
        );
    }
    cfg.vault_secret_path = vault_path;
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
    cfg.vault_approle_role_id = set("TR_SECRETS_VAULT_APPROLE_ROLE_ID");
    cfg.vault_approle_secret_id = set("TR_SECRETS_VAULT_APPROLE_SECRET_ID");
    if let Some(v) = set("TR_SECRETS_VAULT_APPROLE_MOUNT") {
        cfg.vault_approle_mount = v;
    }

    // Kubernetes `Secret` backend.
    cfg.k8s_secret_name = set("TR_SECRETS_K8S_SECRET_NAME");
    cfg.k8s_namespace = set("TR_SECRETS_K8S_NAMESPACE");
    if let Some(v) = set("TR_SECRETS_K8S_SECRET_KEY") {
        cfg.k8s_secret_key = v;
    }

    cfg.allow_plaintext = env_flag("TR_SECRETS_ALLOW_PLAINTEXT", false)?;

    validate(&cfg)?;
    Ok(cfg)
}

/// The backends whose selector field is set, in `vti-secrets`' priority order.
fn implicitly_selected(cfg: &SecretsConfig) -> Vec<(SecretBackend, &'static str)> {
    [
        (
            cfg.aws_secret_name.is_some(),
            SecretBackend::Aws,
            "TR_SECRETS_AWS_SECRET_NAME",
        ),
        (
            cfg.gcp_secret_name.is_some(),
            SecretBackend::Gcp,
            "TR_SECRETS_GCP_SECRET_NAME",
        ),
        (
            cfg.azure_vault_url.is_some(),
            SecretBackend::Azure,
            "TR_SECRETS_AZURE_VAULT_URL",
        ),
        (
            cfg.vault_addr.is_some(),
            SecretBackend::Vault,
            "TR_SECRETS_VAULT_ADDR",
        ),
        (
            cfg.k8s_secret_name.is_some(),
            SecretBackend::Kubernetes,
            "TR_SECRETS_K8S_SECRET_NAME",
        ),
        (
            cfg.seed.is_some(),
            SecretBackend::ConfigSeed,
            "TR_SECRETS_SEED",
        ),
    ]
    .into_iter()
    .filter(|(set, _, _)| *set)
    .map(|(_, backend, var)| (backend, var))
    .collect()
}

/// Refuse a configuration `create_seed_store` would resolve to a backend the
/// operator did not ask for, or reject with a message naming config-file keys.
fn validate(cfg: &SecretsConfig) -> Result<(), String> {
    let requires = |missing: bool, var: &str, because: &str| {
        if missing {
            Err(format!("{var} is required when {because}"))
        } else {
            Ok(())
        }
    };
    // Pairs that only work together.
    requires(
        cfg.azure_secret_name.is_some() && cfg.azure_vault_url.is_none(),
        "TR_SECRETS_AZURE_VAULT_URL",
        "TR_SECRETS_AZURE_SECRET_NAME is set",
    )?;
    requires(
        cfg.azure_vault_url.is_some() && cfg.azure_secret_name.is_none(),
        "TR_SECRETS_AZURE_SECRET_NAME",
        "TR_SECRETS_AZURE_VAULT_URL is set",
    )?;
    requires(
        cfg.vault_secret_path.is_some() && cfg.vault_addr.is_none(),
        "TR_SECRETS_VAULT_ADDR (or VAULT_ADDR)",
        "TR_SECRETS_VAULT_SECRET_PATH is set",
    )?;
    requires(
        cfg.vault_addr.is_some() && cfg.vault_secret_path.is_none(),
        "TR_SECRETS_VAULT_SECRET_PATH",
        "Vault is selected",
    )?;
    requires(
        cfg.gcp_secret_name.is_some() && cfg.gcp_project.is_none(),
        "TR_SECRETS_GCP_PROJECT",
        "TR_SECRETS_GCP_SECRET_NAME is set",
    )?;

    match cfg.backend {
        Some(explicit) => {
            let field = match explicit {
                SecretBackend::Aws => {
                    Some((cfg.aws_secret_name.is_none(), "TR_SECRETS_AWS_SECRET_NAME"))
                }
                SecretBackend::Gcp => {
                    Some((cfg.gcp_secret_name.is_none(), "TR_SECRETS_GCP_SECRET_NAME"))
                }
                SecretBackend::Azure => {
                    Some((cfg.azure_vault_url.is_none(), "TR_SECRETS_AZURE_VAULT_URL"))
                }
                SecretBackend::Vault => Some((
                    cfg.vault_secret_path.is_none(),
                    "TR_SECRETS_VAULT_SECRET_PATH",
                )),
                SecretBackend::Kubernetes => {
                    Some((cfg.k8s_secret_name.is_none(), "TR_SECRETS_K8S_SECRET_NAME"))
                }
                SecretBackend::ConfigSeed => Some((cfg.seed.is_none(), "TR_SECRETS_SEED")),
                SecretBackend::Plaintext => {
                    Some((!cfg.allow_plaintext, "TR_SECRETS_ALLOW_PLAINTEXT=true"))
                }
                _ => None,
            };
            if let Some((true, var)) = field {
                return Err(format!(
                    "{var} is required when TR_SECRETS_BACKEND={}",
                    backend_name(explicit)
                ));
            }
        }
        None => {
            let selected = implicitly_selected(cfg);
            if selected.len() > 1 {
                let vars: Vec<&str> = selected.iter().map(|(_, var)| *var).collect();
                return Err(format!(
                    "more than one secret-store backend is configured ({}); unset all but \
                     one, or name the one to use with TR_SECRETS_BACKEND",
                    vars.join(", ")
                ));
            }
        }
    }
    Ok(())
}

/// The backend `cfg` requests, by the same rule [`create_seed_store`] applies:
/// the explicit `TR_SECRETS_BACKEND`, else the backend whose selector field is
/// set. `None` when the operator configured none.
///
/// The implicit keyring / plaintext fallbacks `create_seed_store` reaches when
/// nothing is configured are deliberately **not** reported here, so an
/// unconfigured deployment keeps using `PROFILE_CONFIG` unchanged.
pub fn selected_backend(cfg: &SecretsConfig) -> Option<SecretBackend> {
    cfg.backend.or_else(|| {
        implicitly_selected(cfg)
            .first()
            .map(|(backend, _)| *backend)
    })
}

/// Whether the operator has explicitly configured a backend (as opposed to the
/// default inline `PROFILE_CONFIG`). See [`selected_backend`].
pub fn backend_selected(cfg: &SecretsConfig) -> bool {
    selected_backend(cfg).is_some()
}

/// The on-disk data directory for file-backed backends (`TR_SECRETS_DATA_DIR`,
/// default `./.trust-registry`). Read only while the configuration loads.
pub fn data_dir() -> PathBuf {
    non_empty_env("TR_SECRETS_DATA_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(DEFAULT_DATA_DIR))
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

    pub(crate) const SECRETS_VARS: &[&str] = &[
        "TR_SECRETS_BACKEND",
        "TR_SECRETS_SEED",
        "TR_SECRETS_AWS_SECRET_NAME",
        "TR_SECRETS_AWS_REGION",
        "TR_SECRETS_GCP_SECRET_NAME",
        "TR_SECRETS_GCP_PROJECT",
        "TR_SECRETS_AZURE_SECRET_NAME",
        "TR_SECRETS_AZURE_VAULT_URL",
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
        "TR_SECRETS_DATA_DIR",
    ];

    pub(crate) fn clear_env() {
        for k in SECRETS_VARS {
            unsafe { std::env::remove_var(k) };
        }
    }

    fn set(pairs: &[(&str, &str)]) {
        for (k, v) in pairs {
            unsafe { std::env::set_var(k, v) };
        }
    }

    #[test]
    #[serial]
    fn unconfigured_env_selects_no_explicit_backend() {
        clear_env();
        let cfg = secrets_config_from_env().expect("valid");
        assert!(!backend_selected(&cfg));
    }

    #[test]
    #[serial]
    fn aws_secret_name_selects_backend() {
        clear_env();
        set(&[("TR_SECRETS_AWS_SECRET_NAME", "tr/profile")]);
        let cfg = secrets_config_from_env().expect("valid");
        assert_eq!(cfg.aws_secret_name.as_deref(), Some("tr/profile"));
        assert_eq!(selected_backend(&cfg), Some(SecretBackend::Aws));
        clear_env();
    }

    #[test]
    #[serial]
    fn vault_and_keyring_env_map_through() {
        clear_env();
        set(&[
            ("TR_SECRETS_VAULT_ADDR", "https://vault.svc:8200"),
            ("TR_SECRETS_VAULT_SECRET_PATH", "secret/tr"),
            ("TR_SECRETS_KEYRING_SERVICE", "trust-registry"),
            ("TR_SECRETS_ALLOW_PLAINTEXT", "true"),
        ]);
        let cfg = secrets_config_from_env().expect("valid");
        assert_eq!(cfg.vault_secret_path.as_deref(), Some("secret/tr"));
        assert_eq!(cfg.keyring_service, "trust-registry");
        assert!(cfg.allow_plaintext);
        assert_eq!(selected_backend(&cfg), Some(SecretBackend::Vault));
        clear_env();
    }

    #[test]
    #[serial]
    fn vault_k8s_auth_env_maps_through() {
        // The default auth method is `kubernetes`, whose `vti_secrets` branch
        // requires `vault_k8s_role`. Assert the full k8s-auth env set lands in
        // the config, and that the string defaults are preserved when their
        // env vars are absent.
        clear_env();
        set(&[
            ("TR_SECRETS_VAULT_ADDR", "https://vault.svc:8200"),
            ("TR_SECRETS_VAULT_SECRET_PATH", "tr/master-seed"),
            ("TR_SECRETS_VAULT_AUTH_METHOD", "kubernetes"),
            ("TR_SECRETS_VAULT_K8S_ROLE", "trust-registry"),
        ]);
        let cfg = secrets_config_from_env().expect("valid");
        assert_eq!(cfg.vault_addr.as_deref(), Some("https://vault.svc:8200"));
        assert_eq!(cfg.vault_secret_path.as_deref(), Some("tr/master-seed"));
        assert_eq!(cfg.vault_auth_method, "kubernetes");
        assert_eq!(cfg.vault_k8s_role.as_deref(), Some("trust-registry"));
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
        // across services; honour them once Vault is requested.
        clear_env();
        set(&[
            ("VAULT_ADDR", "https://canonical:8200"),
            ("TR_SECRETS_VAULT_ADDR", "https://fallback:8200"),
            ("VAULT_TOKEN", "hvs.canonical"),
            ("VAULT_SKIP_VERIFY", "true"),
            ("TR_SECRETS_VAULT_SECRET_PATH", "tr/seed"),
            ("TR_SECRETS_VAULT_AUTH_METHOD", "token"),
        ]);
        let cfg = secrets_config_from_env().expect("valid");
        assert_eq!(cfg.vault_addr.as_deref(), Some("https://canonical:8200"));
        assert_eq!(cfg.vault_token.as_deref(), Some("hvs.canonical"));
        assert!(cfg.vault_skip_verify);
        clear_env();
    }

    /// A host exporting `VAULT_ADDR` for unrelated tooling must not select
    /// Vault for a registry configured for another backend, or for none.
    #[test]
    #[serial]
    fn ambient_vault_addr_does_not_select_vault() {
        clear_env();
        set(&[
            ("VAULT_ADDR", "https://unrelated:8200"),
            ("VAULT_TOKEN", "hvs.unrelated"),
        ]);
        let cfg = secrets_config_from_env().expect("valid");
        assert_eq!(cfg.vault_addr, None);
        assert_eq!(cfg.vault_token, None);
        assert!(!backend_selected(&cfg));

        set(&[("TR_SECRETS_K8S_SECRET_NAME", "tr-profile")]);
        let cfg = secrets_config_from_env().expect("valid");
        assert_eq!(cfg.vault_addr, None);
        assert_eq!(selected_backend(&cfg), Some(SecretBackend::Kubernetes));
        clear_env();
    }

    #[test]
    #[serial]
    fn vault_approle_and_k8s_secret_key_map_through() {
        clear_env();
        set(&[
            ("TR_SECRETS_VAULT_ADDR", "https://vault.example.com"),
            ("TR_SECRETS_VAULT_SECRET_PATH", "tr/seed"),
            ("TR_SECRETS_VAULT_AUTH_METHOD", "approle"),
            ("TR_SECRETS_VAULT_APPROLE_ROLE_ID", "role-123"),
            ("TR_SECRETS_VAULT_APPROLE_SECRET_ID", "secret-456"),
            ("TR_SECRETS_K8S_SECRET_KEY", "bip39_seed"),
        ]);
        let cfg = secrets_config_from_env().expect("valid");
        assert_eq!(cfg.vault_auth_method, "approle");
        assert_eq!(cfg.vault_approle_role_id.as_deref(), Some("role-123"));
        assert_eq!(cfg.vault_approle_secret_id.as_deref(), Some("secret-456"));
        assert_eq!(cfg.k8s_secret_key, "bip39_seed");
        clear_env();
    }

    /// Each half-configured backend is refused naming the missing variable,
    /// where it used to fall through to another store.
    #[test]
    #[serial]
    fn half_configured_backends_name_the_missing_variable() {
        for (pairs, missing) in [
            (
                &[("TR_SECRETS_AZURE_SECRET_NAME", "tr")][..],
                "TR_SECRETS_AZURE_VAULT_URL",
            ),
            (
                &[("TR_SECRETS_AZURE_VAULT_URL", "https://v.vault.azure.net")][..],
                "TR_SECRETS_AZURE_SECRET_NAME",
            ),
            (
                &[("TR_SECRETS_VAULT_SECRET_PATH", "tr/seed")][..],
                "TR_SECRETS_VAULT_ADDR",
            ),
            (
                &[("TR_SECRETS_VAULT_ADDR", "https://vault:8200")][..],
                "TR_SECRETS_VAULT_SECRET_PATH",
            ),
            (
                &[("TR_SECRETS_GCP_SECRET_NAME", "tr")][..],
                "TR_SECRETS_GCP_PROJECT",
            ),
            (
                &[("TR_SECRETS_BACKEND", "aws")][..],
                "TR_SECRETS_AWS_SECRET_NAME",
            ),
            (
                &[("TR_SECRETS_BACKEND", "plaintext")][..],
                "TR_SECRETS_ALLOW_PLAINTEXT",
            ),
        ] {
            clear_env();
            set(pairs);
            let err = secrets_config_from_env().expect_err(missing);
            assert!(err.contains(missing), "{pairs:?}: {err}");
        }
        clear_env();
    }

    #[test]
    #[serial]
    fn two_implicit_backends_are_an_error_unless_one_is_named() {
        clear_env();
        set(&[
            ("TR_SECRETS_AWS_SECRET_NAME", "tr/profile"),
            ("TR_SECRETS_K8S_SECRET_NAME", "tr-profile"),
        ]);
        let err = secrets_config_from_env().expect_err("ambiguous");
        assert!(err.contains("TR_SECRETS_BACKEND"), "{err}");

        set(&[("TR_SECRETS_BACKEND", "kubernetes")]);
        let cfg = secrets_config_from_env().expect("named");
        assert_eq!(cfg.backend, Some(SecretBackend::Kubernetes));
        assert_eq!(selected_backend(&cfg), Some(SecretBackend::Kubernetes));
        clear_env();
    }

    #[test]
    #[serial]
    fn backend_selector_is_parsed_strictly() {
        clear_env();
        set(&[("TR_SECRETS_BACKEND", "Keyring")]);
        let cfg = secrets_config_from_env().expect("valid");
        assert_eq!(selected_backend(&cfg), Some(SecretBackend::Keyring));

        set(&[("TR_SECRETS_BACKEND", "hashicorp")]);
        let err = secrets_config_from_env().expect_err("unknown");
        assert!(err.contains("TR_SECRETS_BACKEND"), "{err}");
        assert!(err.contains("hashicorp"), "{err}");
        clear_env();
    }

    #[test]
    #[serial]
    fn booleans_are_strict() {
        clear_env();
        set(&[("TR_SECRETS_ALLOW_PLAINTEXT", "yes")]);
        let err = secrets_config_from_env().expect_err("not true/false");
        assert!(err.contains("TR_SECRETS_ALLOW_PLAINTEXT"), "{err}");
        clear_env();
        set(&[
            ("TR_SECRETS_VAULT_ADDR", "https://vault:8200"),
            ("TR_SECRETS_VAULT_SECRET_PATH", "tr/seed"),
            ("TR_SECRETS_VAULT_SKIP_VERIFY", "maybe"),
        ]);
        let err = secrets_config_from_env().expect_err("not a boolean");
        assert!(err.contains("TR_SECRETS_VAULT_SKIP_VERIFY"), "{err}");
        clear_env();
    }

    /// `selected_backend` and `create_seed_store` agree: what the registry
    /// thinks is configured is what `vti-secrets` builds, and an unconfigured
    /// environment on a build without the keyring reaches the plaintext arm,
    /// which refuses without `TR_SECRETS_ALLOW_PLAINTEXT`.
    #[cfg(not(feature = "secrets-keyring"))]
    #[tokio::test]
    #[serial]
    async fn selection_agrees_with_vti_secrets() {
        clear_env();
        let dir = tempfile::tempdir().expect("tempdir");
        let cfg = secrets_config_from_env().expect("valid");
        assert!(!backend_selected(&cfg));
        assert!(create_seed_store(&cfg, dir.path()).is_err());

        set(&[
            ("TR_SECRETS_BACKEND", "plaintext"),
            ("TR_SECRETS_ALLOW_PLAINTEXT", "true"),
        ]);
        let cfg = secrets_config_from_env().expect("valid");
        assert_eq!(selected_backend(&cfg), Some(SecretBackend::Plaintext));
        write_profile(&cfg, dir.path(), r#"{"did":"did:example:1"}"#)
            .await
            .expect("written");
        assert_eq!(
            read_profile(&cfg, dir.path()).await.expect("read"),
            Some(r#"{"did":"did:example:1"}"#.to_string())
        );
        clear_env();
    }

    #[test]
    #[serial]
    fn data_dir_defaults_and_overrides() {
        clear_env();
        assert_eq!(data_dir(), PathBuf::from(DEFAULT_DATA_DIR));
        set(&[("TR_SECRETS_DATA_DIR", "/srv/tr")]);
        assert_eq!(data_dir(), PathBuf::from("/srv/tr"));
        clear_env();
    }
}
