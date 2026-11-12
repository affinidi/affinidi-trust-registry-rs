use affinidi_tdk::{
    did_common::{DID, PeerCreateKey, PeerKeyPurpose, PeerService, PeerServiceEndpoint},
    secrets_resolver::secrets::Secret,
};
use serde::{Deserialize, Serialize};
use serde_json;
use std::{
    collections::HashMap,
    env, fs,
    io::Write,
    path::{Path, PathBuf},
};

/// The alias the demo runs its admin operations as.
pub const ADMIN_ALIAS: &str = "SampleTRAdmin";

/// Where the test client keeps its identity unless `SERVICE_CONFIG_PATH`
/// says otherwise. Not tracked by git: each checkout makes its own.
pub const DEFAULT_CONFIG_PATH: &str = "./conf/user_config.json";

#[derive(Default, Debug, Clone, Serialize, Deserialize)]
pub struct ServiceConfig {
    pub alias: String,
    pub secrets: Vec<Secret>,
}

pub fn load_file(
    path: &Path,
) -> Result<HashMap<String, ServiceConfig>, Box<dyn std::error::Error>> {
    let file_content = fs::read_to_string(path)?;

    let service_configs: HashMap<String, ServiceConfig> =
        serde_json::from_str::<HashMap<String, ServiceConfig>>(&file_content)?;

    Ok(service_configs)
}

/// What [`load_user_config`] found.
pub enum UserConfig {
    /// An existing identity file.
    Loaded(HashMap<String, ServiceConfig>),
    /// No identity file existed, so a new admin identity was generated and
    /// saved here. Its DID must be added to the registry's `ADMIN_DIDS`
    /// before it can manage records.
    Generated { did: String, path: PathBuf },
}

pub fn config_path() -> PathBuf {
    env::var("SERVICE_CONFIG_PATH")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from(DEFAULT_CONFIG_PATH))
}

/// Load the test client's identity from [`config_path`], or, when no file is
/// there, generate a fresh `did:peer` admin routed through `mediator_did`
/// and save it there (owner-only).
pub fn load_user_config(mediator_did: &str) -> Result<UserConfig, Box<dyn std::error::Error>> {
    let path = config_path();
    if path.exists() {
        return Ok(UserConfig::Loaded(load_file(&path)?));
    }
    let (did, secrets) = generate_admin(mediator_did)?;
    let mut configs = HashMap::new();
    configs.insert(
        did.clone(),
        ServiceConfig {
            alias: ADMIN_ALIAS.to_string(),
            secrets,
        },
    );
    write_new_private(&path, &serde_json::to_string_pretty(&configs)?)?;
    Ok(UserConfig::Generated { did, path })
}

/// A new `did:peer:2` with an Ed25519 signing key (`#key-1`) and an X25519
/// key-agreement key (`#key-2`), its DIDComm service pointing at
/// `mediator_did`.
pub fn generate_admin(
    mediator_did: &str,
) -> Result<(String, Vec<Secret>), Box<dyn std::error::Error>> {
    let mut signing = Secret::generate_ed25519(None, None);
    let mut agreement = Secret::generate_x25519(None, None)?;
    let keys = vec![
        PeerCreateKey::from_multibase(
            PeerKeyPurpose::Verification,
            signing.get_public_keymultibase()?,
        ),
        PeerCreateKey::from_multibase(
            PeerKeyPurpose::Encryption,
            agreement.get_public_keymultibase()?,
        ),
    ];
    let services = vec![PeerService {
        id: None,
        type_: "dm".into(),
        endpoint: PeerServiceEndpoint::Uri(mediator_did.to_string()),
    }];
    let (did, _) = DID::generate_peer(&keys, Some(&services))?;
    let did = did.to_string();
    signing.id = format!("{did}#key-1");
    agreement.id = format!("{did}#key-2");
    Ok((did, vec![signing, agreement]))
}

/// Create `path` (and its directory) with owner-only permissions; never
/// replaces an existing file.
fn write_new_private(path: &Path, contents: &str) -> std::io::Result<()> {
    if let Some(dir) = path.parent().filter(|d| !d.as_os_str().is_empty()) {
        fs::create_dir_all(dir)?;
    }
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path)?;
    file.write_all(contents.as_bytes())?;
    file.write_all(b"\n")
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]
    use super::*;

    #[test]
    fn a_generated_admin_round_trips_through_its_file() {
        let dir = env::temp_dir().join(format!(
            "test-client-config-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or_default()
        ));
        let path = dir.join("conf").join("user_config.json");

        let (did, secrets) = generate_admin("did:example:mediator").unwrap();
        assert!(did.starts_with("did:peer:2."));
        assert_eq!(secrets.len(), 2);
        assert!(secrets.iter().all(|s| s.id.starts_with(&did)));

        let mut configs = HashMap::new();
        configs.insert(
            did.clone(),
            ServiceConfig {
                alias: ADMIN_ALIAS.to_string(),
                secrets,
            },
        );
        write_new_private(&path, &serde_json::to_string(&configs).unwrap()).unwrap();
        // Never replaced.
        assert!(write_new_private(&path, "{}").is_err());

        let loaded = load_file(&path).unwrap();
        assert_eq!(loaded[&did].alias, ADMIN_ALIAS);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(&path).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
        fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn each_generated_admin_is_new() {
        let (a, _) = generate_admin("did:example:mediator").unwrap();
        let (b, _) = generate_admin("did:example:mediator").unwrap();
        assert_ne!(a, b);
    }
}
