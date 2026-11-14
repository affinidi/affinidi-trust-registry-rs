use affinidi_did_common::scid::{same_reference, strip_scid_src};
use affinidi_tdk::{
    messaging::protocols::mediator::acls::AccessListModeType, secrets_resolver::secrets::Secret,
};
use serde_derive::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt;
use tracing::warn;

use crate::didcomm::did_document::{TransportFlags, build_did_document, validate_public_url};

use super::{
    Configs,
    loaders::{environment::*, load_setting},
};

/// The secret-store settings, read once while the configuration loads.
#[cfg(feature = "secrets")]
struct SecretStoreSettings {
    config: vti_secrets::SecretsConfig,
    data_dir: std::path::PathBuf,
}

#[cfg(feature = "secrets")]
impl SecretStoreSettings {
    fn from_env() -> Result<Self, String> {
        use super::secret_store;

        let config = secret_store::secrets_config_from_env()?;
        if let Some(backend) = secret_store::selected_backend(&config) {
            tracing::info!(
                backend = secret_store::backend_name(backend),
                "secret store selected"
            );
        }
        Ok(Self {
            config,
            data_dir: secret_store::data_dir(),
        })
    }
}

/// Load the profile bundle from a configured secret-store backend, if any.
///
/// Returns `Ok(None)` when no backend is configured (deployment uses inline
/// `PROFILE_CONFIG`) or the backend holds no bundle yet, so the caller falls
/// back to `PROFILE_CONFIG`.
#[cfg(feature = "secrets")]
async fn load_profile_from_secret_store(
    settings: &SecretStoreSettings,
) -> Result<Option<String>, String> {
    use super::secret_store;

    if !secret_store::backend_selected(&settings.config) {
        return Ok(None);
    }
    secret_store::read_profile(&settings.config, &settings.data_dir)
        .await
        .map_err(|e| format!("the configured secret store (TR_SECRETS_*): {e}"))
}

/// Where the profile bundle came from, for error messages.
#[derive(Debug, Clone, Copy)]
enum ProfileSource {
    #[cfg(feature = "vta")]
    Vta,
    #[cfg(feature = "secrets")]
    SecretStore,
    ProfileConfig,
}

impl fmt::Display for ProfileSource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            #[cfg(feature = "vta")]
            Self::Vta => write!(f, "the profile built from the VTA (TR_VTA_CREDENTIAL)"),
            #[cfg(feature = "secrets")]
            Self::SecretStore => write!(f, "the profile bundle in the secret store (TR_SECRETS_*)"),
            Self::ProfileConfig => write!(f, "PROFILE_CONFIG"),
        }
    }
}

/// The registry's identity bundle and where it came from. Precedence: a
/// configured VTA (remote key custody), then a configured secret-store backend,
/// then the `PROFILE_CONFIG` loader URI.
async fn load_profile_bundle(
    #[cfg(feature = "vta")] vta: Option<&super::vta::VtaConfig>,
    #[cfg(feature = "secrets")] secrets: &SecretStoreSettings,
) -> Result<(String, ProfileSource), String> {
    #[cfg(feature = "vta")]
    if let Some(vta) = vta {
        let cache =
            super::vta::VtaSecretCache::new(secrets.config.clone(), secrets.data_dir.clone());
        let bundle = super::vta::startup_profile_json(vta, &cache).await?;
        return Ok((bundle, ProfileSource::Vta));
    }
    #[cfg(feature = "secrets")]
    if let Some(bundle) = load_profile_from_secret_store(secrets).await? {
        return Ok((bundle, ProfileSource::SecretStore));
    }
    let profile_configs_uri = didcomm_required_env("PROFILE_CONFIG")?;
    let bundle = load_setting("PROFILE_CONFIG", &profile_configs_uri).await?;
    Ok((bundle, ProfileSource::ProfileConfig))
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AuditLogFormat {
    Text,
    /// The default: values are escaped by construction.
    #[default]
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
    /// DIDs that may send record-mutating Trust Tasks.
    pub admin_dids: Vec<String>,
    /// Authorities, beyond its own DID, each admin DID may write records under.
    /// An admin not listed here may only write under its own DID.
    pub admin_authorities: HashMap<String, Vec<String>>,
    pub audit_config: AuditConfig,
}

/// Parse `ADMIN_AUTHORITIES`: a JSON object mapping an admin DID to the
/// authority DIDs it may write records under in addition to its own.
///
/// An empty or absent value means no admin writes beyond its own DID. A
/// malformed value is an error rather than being read as empty, so a typo
/// cannot silently change who may write what.
/// DIDs whose private keys have been published (in this repository's
/// history, as the test client's former sample identity), so a proof made
/// with them shows nothing about who sent it.
pub const PUBLISHED_SAMPLE_ADMIN_DIDS: &[&str] = &[
    "did:peer:2.Vz6Mkpun7xEJWBqwtaiHSqfjLe1ejqQ4PAUEas1gjH7VVNxjs.EzQ3shoprXELvJw9ou4VbfrFRx5FZQsP9EB1LMUJaPacDKtiZ8",
];

/// Refuse an admin list that names a DID whose private keys are public
/// ([`PUBLISHED_SAMPLE_ADMIN_DIDS`]): anyone could make its proofs.
pub fn check_admin_dids_not_published(admin_dids: &[String]) -> Result<(), String> {
    match admin_dids
        .iter()
        .find(|did| PUBLISHED_SAMPLE_ADMIN_DIDS.contains(&did.as_str()))
    {
        Some(did) => Err(format!(
            "ADMIN_DIDS lists {did}, the test client's former sample identity, whose private \
             keys are published in this repository. Remove it; the test client now generates \
             its own identity on first run."
        )),
        None => Ok(()),
    }
}

pub fn parse_admin_authorities(
    raw: Option<&str>,
    admin_dids: &[String],
) -> Result<HashMap<String, Vec<String>>, String> {
    let Some(raw) = raw.map(str::trim).filter(|raw| !raw.is_empty()) else {
        return Ok(HashMap::new());
    };
    let admin_authorities: HashMap<String, Vec<String>> = serde_json::from_str(raw).map_err(|e| {
        format!(
            "ADMIN_AUTHORITIES must be a JSON object mapping an admin DID to a list of authority DIDs: {e}"
        )
    })?;
    // Keyed and compared by DID, as `admin_dids` is.
    let admin_authorities: HashMap<String, Vec<String>> = admin_authorities
        .into_iter()
        .map(|(admin, authorities)| {
            (
                strip_scid_src(&admin).into_owned(),
                authorities
                    .iter()
                    .map(|a| strip_scid_src(a).into_owned())
                    .collect(),
            )
        })
        .collect();
    if let Some(unknown) = admin_authorities
        .keys()
        .find(|admin| !admin_dids.iter().any(|d| same_reference(d, admin)))
    {
        return Err(format!(
            "ADMIN_AUTHORITIES names {unknown}, which is not in ADMIN_DIDS"
        ));
    }
    Ok(admin_authorities)
}

#[derive(Debug, Clone)]
pub struct DidDocumentRetryConfig {
    pub max_attempts: u32,
    pub initial_delay_secs: u64,
    pub max_delay_secs: u64,
}

/// Default for `DID_CHECK_MAX_ATTEMPTS`.
pub const DEFAULT_DID_CHECK_MAX_ATTEMPTS: u32 = 10;
/// Default for `DID_CHECK_INITIAL_DELAY_SECS`.
pub const DEFAULT_DID_CHECK_INITIAL_DELAY_SECS: u64 = 2;
/// Default for `DID_CHECK_MAX_DELAY_SECS`.
pub const DEFAULT_DID_CHECK_MAX_DELAY_SECS: u64 = 20;

/// The same defaults the `DID_CHECK_*` variables take when unset.
impl Default for DidDocumentRetryConfig {
    fn default() -> Self {
        Self {
            max_attempts: DEFAULT_DID_CHECK_MAX_ATTEMPTS,
            initial_delay_secs: DEFAULT_DID_CHECK_INITIAL_DELAY_SECS,
            max_delay_secs: DEFAULT_DID_CHECK_MAX_DELAY_SECS,
        }
    }
}

impl DidDocumentRetryConfig {
    /// Read `DID_CHECK_MAX_ATTEMPTS`, `DID_CHECK_INITIAL_DELAY_SECS` and
    /// `DID_CHECK_MAX_DELAY_SECS`. Each must be a positive whole number, and
    /// the maximum delay at least the initial one.
    pub fn from_env() -> Result<Self, String> {
        let max_attempts = positive_env(
            "DID_CHECK_MAX_ATTEMPTS",
            u64::from(DEFAULT_DID_CHECK_MAX_ATTEMPTS),
        )?;
        let max_attempts = u32::try_from(max_attempts).map_err(|_| {
            format!("DID_CHECK_MAX_ATTEMPTS is out of range (got '{max_attempts}')")
        })?;
        let initial_delay_secs = positive_env(
            "DID_CHECK_INITIAL_DELAY_SECS",
            DEFAULT_DID_CHECK_INITIAL_DELAY_SECS,
        )?;
        let max_delay_secs =
            positive_env("DID_CHECK_MAX_DELAY_SECS", DEFAULT_DID_CHECK_MAX_DELAY_SECS)?;
        if max_delay_secs < initial_delay_secs {
            return Err(format!(
                "DID_CHECK_MAX_DELAY_SECS ({max_delay_secs}) must not be less than \
                 DID_CHECK_INITIAL_DELAY_SECS ({initial_delay_secs})"
            ));
        }
        Ok(Self {
            max_attempts,
            initial_delay_secs,
            max_delay_secs,
        })
    }
}

#[derive(Debug, Clone, Default)]
pub struct DidcommConfig {
    pub is_enabled: bool,
    /// Which transports this process serves and advertises. Carried here even
    /// when DIDComm itself is disabled, so the server can gate the TSP receive
    /// loop and report the effective transport set at startup.
    pub transport_flags: TransportFlags,
    pub acl_mode: AccessListModeType,
    pub profile_config: ProfileConfig,
    pub mediator_did: String,
    pub did_document: String,
    pub admin_config: AdminConfig,
    pub retry_config: DidDocumentRetryConfig,
    /// Base directory of the TSP messaging store; the profile alias names a
    /// subdirectory of it. `None` means `./.trust-registry/messaging`,
    /// relative to the working directory.
    pub messaging_store_path: Option<std::path::PathBuf>,
    /// Bounds on the TSP relationship store.
    #[cfg(feature = "tsp")]
    pub relationship_limits: crate::messaging::relationship_store::RelationshipLimits,
    /// The VTA the identity came from, and which `did/rotate` rotates
    /// through. `None` when the identity is not VTA-managed.
    #[cfg(feature = "vta")]
    pub vta: Option<std::sync::Arc<super::vta::VtaConfig>>,
}

/// The default base of the TSP messaging store.
pub const DEFAULT_MESSAGING_STORE_PATH: &str = "./.trust-registry/messaging";

impl DidcommConfig {
    /// The messaging store base, applying the default when unset.
    pub fn messaging_store_path(&self) -> std::path::PathBuf {
        self.messaging_store_path
            .clone()
            .unwrap_or_else(|| std::path::PathBuf::from(DEFAULT_MESSAGING_STORE_PATH))
    }
}

/// `TR_MESSAGING_STORE_PATH`, else `messaging` under `TR_SECRETS_DATA_DIR`,
/// else `None` (the default).
fn messaging_store_path_from_env() -> Option<std::path::PathBuf> {
    non_empty_env("TR_MESSAGING_STORE_PATH")
        .map(std::path::PathBuf::from)
        .or_else(|| {
            non_empty_env("TR_SECRETS_DATA_DIR")
                .map(|dir| std::path::PathBuf::from(dir).join("messaging"))
        })
}

impl DidcommConfig {
    /// A REST-only configuration: no listener, no mediator, no DID document.
    ///
    /// Prefer this over `DidcommConfig::default()` when building a config
    /// programmatically. The derived default leaves `transport_flags.didcomm`
    /// at its own default of `true` while `is_enabled` is `false`, so the two
    /// halves disagree — `/health` and the startup transport summary would
    /// report DIDComm as served while nothing answers it. This constructor
    /// keeps them consistent.
    ///
    /// It matches what [`Configs::load`] produces when `ENABLE_DIDCOMM=false`.
    pub fn disabled() -> Self {
        Self {
            is_enabled: false,
            transport_flags: TransportFlags {
                rest: true,
                didcomm: false,
                tsp: false,
            },
            ..Default::default()
        }
    }
}

pub fn parse_profile_from_secrets_str(
    did_and_secrets_as_str: &str,
) -> Result<ProfileConfig, Box<dyn std::error::Error + Send + Sync>> {
    let profile_config: ProfileConfig = serde_json::from_str(did_and_secrets_as_str)?;
    Ok(profile_config)
}

/// A variable the DIDComm path needs. Empty counts as unset (an `.env` line
/// `MEDIATOR_DID=` is how a REST-only setup used to leave it), and the error
/// names the switch that turns the requirement off.
fn didcomm_required_env(name: &str) -> Result<String, String> {
    didcomm_required(name, optional_env(name))
}

fn didcomm_required(name: &str, value: Option<String>) -> Result<String, String> {
    value.filter(|v| !v.trim().is_empty()).ok_or_else(|| {
        format!(
            "{name} is unset or empty, and DIDComm is enabled (ENABLE_DIDCOMM defaults to \
             true). Set {name}, or set ENABLE_DIDCOMM=false to run the registry over REST only"
        )
    })
}

/// Parse `ADMIN_DIDS`: comma-separated, surrounding space trimmed, empty
/// entries (a trailing or doubled comma) dropped. A did:scid admin is listed
/// by its DID; a `?src=` locator says where to fetch it, not who it is
/// (VTI-KEY-160).
pub fn parse_admin_dids(raw: Option<&str>) -> Vec<String> {
    raw.unwrap_or_default()
        .split(',')
        .map(str::trim)
        .filter(|e| !e.is_empty())
        .map(|e| strip_scid_src(e).into_owned())
        .collect()
}

/// Parse `AUDIT_LOG_FORMAT`: unset or blank is `json`; anything but `json` or
/// `text` is an error rather than a silent `json`.
pub fn parse_audit_log_format(raw: Option<&str>) -> Result<AuditLogFormat, String> {
    match raw.map(str::trim).filter(|v| !v.is_empty()) {
        None => Ok(AuditLogFormat::default()),
        Some(raw) => raw
            .parse()
            .map_err(|_| format!("AUDIT_LOG_FORMAT must be 'json' or 'text' (got '{raw}')")),
    }
}

/// Parse `DID_DOCUMENT`'s loaded content, which must be a JSON document.
fn check_did_document(content: &str) -> Result<(), String> {
    serde_json::from_str::<serde_json::Value>(content)
        .map(|_| ())
        .map_err(|e| format!("DID_DOCUMENT is not a JSON document: {e}"))
}

/// Parse `ACL_MODE`: `ExplicitDeny` (public: anyone may send to the registry
/// through its mediator) or `ExplicitAllow` (private: only allow-listed DIDs
/// may). Unset or empty means `ExplicitDeny`, as before. The two names match
/// case-insensitively after trimming; anything else is an error, so a typo in
/// a private registry's configuration cannot start it in public mode.
pub(crate) fn parse_acl_mode(raw: Option<&str>) -> Result<AccessListModeType, String> {
    let Some(raw) = raw.map(str::trim).filter(|v| !v.is_empty()) else {
        return Ok(AccessListModeType::ExplicitDeny);
    };
    if raw.eq_ignore_ascii_case("ExplicitDeny") {
        Ok(AccessListModeType::ExplicitDeny)
    } else if raw.eq_ignore_ascii_case("ExplicitAllow") {
        Ok(AccessListModeType::ExplicitAllow)
    } else {
        Err(format!(
            "ACL_MODE must be 'ExplicitDeny' (public) or 'ExplicitAllow' (private) (got '{raw}')"
        ))
    }
}

/// Read [`TransportFlags`] from the environment and reject incoherent
/// combinations.
///
/// Defaults: `ENABLE_REST=true`, `ENABLE_DIDCOMM=true`, `ENABLE_TSP=false`.
///
/// Lives here rather than next to `TransportFlags` so that every environment
/// read in the crate sits under `configs`. The struct itself is plain public
/// data with a `Default`, so an embedding host constructs it directly and the
/// environment never reaches it. `TransportFlags::validate` still runs on both
/// paths, so a host cannot build an incoherent set either.
pub fn transport_flags_from_env() -> Result<TransportFlags, String> {
    let flags = TransportFlags {
        rest: env_flag("ENABLE_REST", true)?,
        didcomm: env_flag("ENABLE_DIDCOMM", true)?,
        tsp: env_flag("ENABLE_TSP", false)?,
    };
    flags.validate()?;
    Ok(flags)
}

#[async_trait::async_trait]
impl Configs for DidcommConfig {
    async fn load() -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        // Parsed before the DIDComm short-circuit so an invalid or empty
        // transport set is rejected even for a REST-only deployment.
        let transport_flags = transport_flags_from_env()?;
        if !transport_flags.didcomm {
            // No mediator profile is loaded on this path, so no DID document is
            // built either: a REST-only registry is reached by URL, not by DID.
            warn!(
                "DIDComm is disabled; no DID document will be published. \
                 Consumers must reach this registry by URL."
            );
            return Ok(DidcommConfig {
                is_enabled: false,
                transport_flags,
                ..Default::default()
            });
        }
        let acl_mode = parse_acl_mode(optional_env("ACL_MODE").as_deref())?;

        let admin_dids = parse_admin_dids(optional_env("ADMIN_DIDS").as_deref());
        if admin_dids.is_empty() {
            warn!("ADMIN_DIDS is unset or empty: no DID may send record-mutating Trust Tasks");
        }
        check_admin_dids_not_published(&admin_dids)?;

        let log_format = parse_audit_log_format(optional_env("AUDIT_LOG_FORMAT").as_deref())?;

        let admin_authorities =
            parse_admin_authorities(optional_env("ADMIN_AUTHORITIES").as_deref(), &admin_dids)?;

        let admin_config = AdminConfig {
            admin_dids,
            admin_authorities,
            audit_config: AuditConfig { log_format },
        };

        let mediator_did = didcomm_required_env("MEDIATOR_DID")?;

        #[cfg(feature = "secrets")]
        let secret_store = SecretStoreSettings::from_env()?;
        #[cfg(feature = "vta")]
        let vta = super::vta::VtaConfig::from_env()
            .await?
            .map(std::sync::Arc::new);

        let (profile_configs_str, profile_source) = load_profile_bundle(
            #[cfg(feature = "vta")]
            vta.as_deref(),
            #[cfg(feature = "secrets")]
            &secret_store,
        )
        .await?;
        let profile_config = parse_profile_from_secrets_str(&profile_configs_str)
            .map_err(|e| format!("{profile_source} is not a valid profile bundle: {e}"))?;

        // Externally reachable base URL for the REST/TRQP surface. Absent =>
        // no `TRQPRest` service entry, so the registry never advertises a
        // transport a peer cannot reach. LISTEN_ADDRESS is deliberately not a
        // fallback: it is a bind address, frequently `0.0.0.0`.
        let public_url = optional_env("TR_PUBLIC_URL")
            .map(|u| u.trim().to_string())
            .filter(|u| !u.is_empty());
        if let Some(url) = public_url.as_deref() {
            // Fail at startup rather than publish an endpoint consumers reject.
            validate_public_url(url)?;
        }
        if transport_flags.rest && public_url.is_none() {
            warn!(
                "ENABLE_REST=true but TR_PUBLIC_URL is unset: REST is served but not \
                 advertised in the DID document. Set TR_PUBLIC_URL to make it discoverable."
            );
        }

        let did_document = if let Some(doc) = non_empty_env("DID_DOCUMENT") {
            let content = load_setting("DID_DOCUMENT", &doc).await?;
            check_did_document(&content)?;
            content
        } else {
            build_did_document(
                &profile_config,
                &mediator_did,
                public_url.as_deref(),
                transport_flags,
            )
            .map_err(|e| format!("cannot build the DID document from the profile: {e}"))?
        };

        let retry_config = DidDocumentRetryConfig::from_env()?;

        Ok(DidcommConfig {
            is_enabled: true,
            transport_flags,
            acl_mode,
            mediator_did,
            profile_config,
            did_document,
            admin_config,
            retry_config,
            messaging_store_path: messaging_store_path_from_env(),
            // A malformed bound stops startup rather than running unbounded.
            #[cfg(feature = "tsp")]
            relationship_limits:
                crate::messaging::relationship_store::RelationshipLimits::from_env()?,
            #[cfg(feature = "vta")]
            vta,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::{
        PUBLISHED_SAMPLE_ADMIN_DIDS, check_admin_dids_not_published, didcomm_required,
        parse_admin_authorities,
    };

    /// `MEDIATOR_DID=` is how a REST-only setup left `.env`: it must read as
    /// unset, with an error that names `ENABLE_DIDCOMM=false`.
    #[test]
    fn an_empty_didcomm_variable_is_unset_and_the_error_names_the_switch() {
        for value in [None, Some(String::new()), Some("  ".to_string())] {
            let err = didcomm_required("MEDIATOR_DID", value).unwrap_err();
            assert!(err.contains("ENABLE_DIDCOMM=false"), "{err}");
        }
        assert_eq!(
            didcomm_required("MEDIATOR_DID", Some("did:example:m".into())).unwrap(),
            "did:example:m"
        );
    }

    #[test]
    fn an_admin_list_naming_a_published_sample_identity_is_refused() {
        let listed = vec![
            ADMIN.to_string(),
            PUBLISHED_SAMPLE_ADMIN_DIDS[0].to_string(),
        ];
        let err = check_admin_dids_not_published(&listed).unwrap_err();
        assert!(err.contains(PUBLISHED_SAMPLE_ADMIN_DIDS[0]));
        assert!(check_admin_dids_not_published(&admins()).is_ok());
        assert!(check_admin_dids_not_published(&[]).is_ok());
    }

    /// The sample test-client identity is no longer shipped anywhere a
    /// deployment could pick it up.
    #[test]
    fn the_env_example_names_no_published_sample_identity() {
        let example = include_str!("../../../.env.example");
        for did in PUBLISHED_SAMPLE_ADMIN_DIDS {
            assert!(!example.contains(did));
        }
    }

    const ADMIN: &str = "did:example:admin";

    fn admins() -> Vec<String> {
        vec![ADMIN.to_string()]
    }

    #[test]
    fn absent_or_empty_admin_authorities_grant_nothing_extra() {
        assert!(parse_admin_authorities(None, &admins()).unwrap().is_empty());
        assert!(
            parse_admin_authorities(Some("  "), &admins())
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn admin_authorities_map_an_admin_to_its_extra_authorities() {
        let parsed = parse_admin_authorities(
            Some(r#"{"did:example:admin": ["did:example:a", "did:example:b"]}"#),
            &admins(),
        )
        .unwrap();
        assert_eq!(parsed[ADMIN], vec!["did:example:a", "did:example:b"]);
    }

    /// A did:scid admin and its authorities are keyed by DID: the `?src=`
    /// locator they may be written with is not part of who they are.
    #[test]
    fn a_did_scid_admin_and_authority_are_keyed_by_did() {
        let parsed = parse_admin_authorities(
            Some(
                r#"{"did:scid:vh:1:QmAdmin?src=a.example": ["did:scid:vh:1:QmAuth?src=b.example"]}"#,
            ),
            &["did:scid:vh:1:QmAdmin".to_string()],
        )
        .unwrap();
        assert_eq!(
            parsed["did:scid:vh:1:QmAdmin"],
            vec!["did:scid:vh:1:QmAuth"]
        );
    }

    #[test]
    fn malformed_admin_authorities_are_an_error() {
        assert!(
            parse_admin_authorities(Some("did:example:admin=did:example:a"), &admins()).is_err()
        );
    }

    #[test]
    fn admin_authorities_for_a_non_admin_are_an_error() {
        assert!(
            parse_admin_authorities(
                Some(r#"{"did:example:stranger": ["did:example:a"]}"#),
                &admins()
            )
            .is_err()
        );
    }
}

#[cfg(test)]
mod acl_mode_tests {
    use super::parse_acl_mode;
    use affinidi_tdk::messaging::protocols::mediator::acls::AccessListModeType;

    #[test]
    fn acl_mode_defaults_to_explicit_deny_when_unset_or_empty() {
        assert_eq!(parse_acl_mode(None), Ok(AccessListModeType::ExplicitDeny));
        assert_eq!(
            parse_acl_mode(Some("  ")),
            Ok(AccessListModeType::ExplicitDeny)
        );
    }

    #[test]
    fn acl_mode_accepts_either_name_in_any_case_with_surrounding_space() {
        for raw in ["ExplicitAllow", "explicitallow", " EXPLICITALLOW "] {
            assert_eq!(
                parse_acl_mode(Some(raw)),
                Ok(AccessListModeType::ExplicitAllow),
                "{raw:?}"
            );
        }
        for raw in ["ExplicitDeny", "explicitdeny\t"] {
            assert_eq!(
                parse_acl_mode(Some(raw)),
                Ok(AccessListModeType::ExplicitDeny),
                "{raw:?}"
            );
        }
    }

    /// A value that is neither name must stop startup rather than select the
    /// public mode.
    #[test]
    fn acl_mode_rejects_any_other_value() {
        for raw in ["private", "Explicit_Allow", "ExplicitAllowed", "allow"] {
            let err = parse_acl_mode(Some(raw)).expect_err(raw);
            assert!(err.contains("ACL_MODE"), "{err}");
            assert!(err.contains(raw), "{err}");
        }
    }
}

#[cfg(test)]
mod strictness_tests {
    use super::*;
    use serial_test::serial;

    #[test]
    fn admin_dids_drop_empty_entries() {
        assert!(parse_admin_dids(None).is_empty());
        assert!(parse_admin_dids(Some("")).is_empty());
        assert!(parse_admin_dids(Some(" , ,")).is_empty());
        assert_eq!(
            parse_admin_dids(Some("did:example:a,,did:example:b, ")),
            vec!["did:example:a", "did:example:b"]
        );
    }

    /// A typo used to select `json` silently.
    #[test]
    fn audit_log_format_rejects_unknown_values() {
        assert_eq!(parse_audit_log_format(None), Ok(AuditLogFormat::Json));
        assert_eq!(parse_audit_log_format(Some(" ")), Ok(AuditLogFormat::Json));
        assert_eq!(
            parse_audit_log_format(Some("TEXT")),
            Ok(AuditLogFormat::Text)
        );
        let err = parse_audit_log_format(Some("txt")).unwrap_err();
        assert!(err.contains("AUDIT_LOG_FORMAT"), "{err}");
        assert!(err.contains("txt"), "{err}");
    }

    #[test]
    fn did_document_must_be_json() {
        assert!(check_did_document(r#"{"id":"did:example:1"}"#).is_ok());
        let err = check_did_document("aws_secret://tr/doc").unwrap_err();
        assert!(err.contains("DID_DOCUMENT"), "{err}");
    }

    const RETRY_VARS: [&str; 3] = [
        "DID_CHECK_MAX_ATTEMPTS",
        "DID_CHECK_INITIAL_DELAY_SECS",
        "DID_CHECK_MAX_DELAY_SECS",
    ];

    fn clear_retry_env() {
        for k in RETRY_VARS {
            unsafe { std::env::remove_var(k) };
        }
    }

    /// The environment defaults and `Default` used to disagree (20 and 30).
    #[test]
    #[serial]
    fn retry_defaults_agree() {
        clear_retry_env();
        let loaded = DidDocumentRetryConfig::from_env().expect("defaults");
        let default = DidDocumentRetryConfig::default();
        assert_eq!(loaded.max_attempts, default.max_attempts);
        assert_eq!(loaded.initial_delay_secs, default.initial_delay_secs);
        assert_eq!(loaded.max_delay_secs, default.max_delay_secs);
    }

    /// Bad values used to fall back to the defaults without a word.
    #[test]
    #[serial]
    fn bad_retry_values_name_the_variable() {
        for name in RETRY_VARS {
            for raw in ["0", "ten", "-3"] {
                clear_retry_env();
                unsafe { std::env::set_var(name, raw) };
                let err = DidDocumentRetryConfig::from_env().expect_err(raw);
                assert!(err.contains(name), "{name}={raw}: {err}");
            }
        }
        clear_retry_env();
        unsafe {
            std::env::set_var("DID_CHECK_INITIAL_DELAY_SECS", "40");
            std::env::set_var("DID_CHECK_MAX_DELAY_SECS", "10");
        }
        let err = DidDocumentRetryConfig::from_env().expect_err("inverted");
        assert!(err.contains("DID_CHECK_MAX_DELAY_SECS"), "{err}");
        clear_retry_env();
    }

    #[test]
    #[serial]
    fn messaging_store_path_follows_its_variable_then_the_data_dir() {
        unsafe {
            std::env::remove_var("TR_MESSAGING_STORE_PATH");
            std::env::remove_var("TR_SECRETS_DATA_DIR");
        }
        assert_eq!(messaging_store_path_from_env(), None);
        assert_eq!(
            DidcommConfig::default().messaging_store_path(),
            std::path::PathBuf::from(DEFAULT_MESSAGING_STORE_PATH)
        );
        unsafe { std::env::set_var("TR_SECRETS_DATA_DIR", "/srv/tr") };
        assert_eq!(
            messaging_store_path_from_env(),
            Some(std::path::PathBuf::from("/srv/tr/messaging"))
        );
        unsafe { std::env::set_var("TR_MESSAGING_STORE_PATH", "/srv/msg") };
        assert_eq!(
            messaging_store_path_from_env(),
            Some(std::path::PathBuf::from("/srv/msg"))
        );
        unsafe {
            std::env::remove_var("TR_MESSAGING_STORE_PATH");
            std::env::remove_var("TR_SECRETS_DATA_DIR");
        }
    }

    /// A profile that does not parse, or whose loader scheme is mistyped,
    /// names the setting it came from.
    #[tokio::test]
    #[serial]
    async fn an_unparseable_profile_config_is_named() {
        for (k, v) in [
            ("ENABLE_DIDCOMM", "true"),
            ("MEDIATOR_DID", "did:example:mediator"),
            ("PROFILE_CONFIG", "string://{not json"),
        ] {
            unsafe { std::env::set_var(k, v) };
        }
        for k in ["TR_VTA_CREDENTIAL", "ADMIN_DIDS", "ADMIN_AUTHORITIES"] {
            unsafe { std::env::remove_var(k) };
        }
        let err = DidcommConfig::load().await.expect_err("bad profile");
        assert!(err.to_string().contains("PROFILE_CONFIG"), "{err}");

        unsafe { std::env::set_var("PROFILE_CONFIG", "aws_secret://tr/profile") };
        let err = DidcommConfig::load().await.expect_err("bad scheme");
        assert!(
            err.to_string()
                .starts_with("PROFILE_CONFIG: unsupported loader scheme"),
            "{err}"
        );
        for k in ["ENABLE_DIDCOMM", "MEDIATOR_DID", "PROFILE_CONFIG"] {
            unsafe { std::env::remove_var(k) };
        }
    }
}
