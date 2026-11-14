#![cfg(feature = "dev-tools")]
// The `Args` doc comments are clap's `--help` text, written for a terminal
// (`<NAME>`, bare URLs), not rustdoc markup.
#![allow(rustdoc::invalid_html_tags, rustdoc::bare_urls)]
//! `setup-trust-registry`: write a Trust Registry's `.env`, and with
//! `--mediator-did` give it a DIDComm identity.
//!
//! Re-running is safe by default: a value already in `.env` for the
//! registry's identity (`PROFILE_CONFIG`, `MEDIATOR_DID`, `ADMIN_DIDS`,
//! `ACL_MODE`, `ADMIN_AUTHORITIES`), a bundle already in the configured
//! secret store, or a DID / key file already in the working directory is
//! never replaced without `--force`, and `--force` backs each one up
//! (owner-only) first. Every check and every fallible step that does not
//! write runs before the first write.

use affinidi_tdk::{
    TDK,
    common::{config::TDKConfig, profiles::TDKProfile},
    did_common::{
        DID as DIDCommon, PeerCreateKey, PeerKeyPurpose, PeerService, PeerServiceEndpoint,
    },
    messaging::profiles::ATMProfile,
    secrets_resolver::secrets::{Secret, SecretMaterial},
};

use clap::{ArgAction, Parser};
use crossterm::{
    event::{self, Event},
    terminal,
};
use didwebvh_rs::{
    DIDWebVHState, create::add_scid_also_known_as, parameters::Parameters, url::WebVHURL,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    error::Error,
    fs,
    io::Read,
    path::{Path, PathBuf},
    sync::Arc,
};
use trust_registry::configs::didcomm::transport_flags_from_env;
use trust_registry::didcomm::did_document::{build_did_document_value, validate_public_url};
use url::Url;

#[path = "env_file.rs"]
mod env_file;
use env_file::{backup_file, backup_path, create_private, insert_env_vars, is_blank_value};

type BoxError = Box<dyn Error>;

/// The `.env` this tool writes, and the example it starts from.
const ENV_PATH: &str = "./.env";
const ENV_EXAMPLE_PATH: &str = "./.env.example";
/// The DID document and did:webvh log written for `web` / `webvh` / `scid`.
const DID_JSON_PATH: &str = "did.json";
const DID_JSONL_PATH: &str = "did.jsonl";
/// The did:webvh update key and pre-rotation key, owner-only.
const UPDATE_KEYS_PATH: &str = "did-update-keys.json";
/// Where a generated profile goes when `--profile` names a non-file location.
const LOCAL_PROFILE_PATH: &str = "./trust-registry-profile.json";

/// `.env` keys that hold or bind the registry's identity. A run never
/// replaces a non-empty one without `--force`.
const PROTECTED_KEYS: [&str; 5] = [
    "PROFILE_CONFIG",
    "MEDIATOR_DID",
    "ADMIN_DIDS",
    "ACL_MODE",
    "ADMIN_AUTHORITIES",
];

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ProfileConfig {
    alias: String,
    did: String,
    secrets: Vec<Secret>,
}

#[derive(Parser, Debug)]
#[command(
    version,
    about = "Affinidi Trust Registry Setup Tool",
    long_about = "Writes the Trust Registry's .env (storage, audit log, transports) and, with \
                  --mediator-did, gives it a DIDComm identity in one of three modes:\n\n  \
                  new DID        --did-method <peer|web|webvh|scid>\n  \
                  existing DID   --tr-did <DID> --tr-did-secret-file <PATH>\n  \
                  existing profile  --profile <URI>   (without --did-method)\n\n\
                  Without --mediator-did, DIDComm is disabled (ENABLE_DIDCOMM=false) and the \
                  registry serves REST only.\n\n\
                  Values already in .env for the registry's identity, a bundle already in the \
                  secret store, and existing did.json / did.jsonl / did-update-keys.json / \
                  profile files are never replaced without --force, which backs them up first."
)]
struct Args {
    /// Mediator DID the Trust Registry connects through (e.g.
    /// did:web:mediator.example.com). Enables DIDComm and requires one of the
    /// three identity modes.
    #[arg(long, short = 'd')]
    mediator_did: Option<String>,

    /// Generate a new Trust Registry DID with this method (new-DID mode).
    ///
    /// `scid` writes a did:webvh log and presents its did:scid:vh:1 DID, which
    /// the same log verifies but which does not change if the log moves.
    #[arg(long, short = 'm', value_parser = ["peer", "web", "webvh", "scid"],
          conflicts_with = "tr_did")]
    did_method: Option<String>,

    /// URL the DID is derived from and its document hosted under, e.g.
    /// https://example.com or https://example.com/tr (required for web, webvh
    /// and scid). Give this base URL, not the path of did.json / did.jsonl.
    #[arg(long, short = 'w', required_if_eq_any([("did_method", "web"), ("did_method", "webvh"), ("did_method", "scid")]))]
    didweb_url: Option<String>,

    /// Do not list the did:scid:vh:1 form of a new did:webvh in its
    /// `alsoKnownAs`. Listed by default, so peers can recognise the Trust
    /// Registry under either form; not allowed with `--did-method scid`, whose
    /// identity is that form.
    #[arg(long, action = ArgAction::SetTrue)]
    no_scid_alias: bool,

    /// Profile location, as a PROFILE_CONFIG loader URI:
    /// 'file:///path/to/profile.json', 'aws_secrets://<NAME>' or
    /// 'aws_parameter_store://<NAME>'. An inline JSON value or
    /// 'string://<JSON>' is refused: it would put the private keys on the
    /// command line (use --tr-did-secret-file, or save it to a file).
    ///
    /// With --did-method: where the generated profile is to live. A file://
    /// location is written (owner-only); any other location gets the profile
    /// in ./trust-registry-profile.json for you to upload, and .env points at
    /// the location.
    ///
    /// Without --did-method (existing-profile mode): the profile is loaded
    /// from here and validated, no key is generated, and .env points at it.
    #[arg(long, short = 'p', conflicts_with = "tr_did")]
    profile: Option<String>,

    /// Storage backend for trust records.
    #[arg(long, short = 's', value_parser = ["csv", "ddb", "redis", "fjall"], default_value = "csv")]
    storage_backend: String,

    /// Path to the CSV file of trust records (csv backend). Written as
    /// FILE_STORAGE_PATH.
    #[arg(long, short = 'f', default_value = "./sample-data/data.csv")]
    file_storage_path: String,

    /// DynamoDB table name (required with the ddb backend). Written as
    /// DDB_TABLE_NAME.
    #[arg(long, short = 't', required_if_eq("storage_backend", "ddb"))]
    ddb_table_name: Option<String>,

    /// Redis URL (redis backend). Written as REDIS_URL.
    #[arg(long, short = 'u', default_value = "redis://localhost:6379")]
    redis_url: String,

    /// Directory of the fjall database (fjall backend). Written as
    /// TR_FJALL_PATH.
    #[arg(long, default_value = "./trust_records.fjall")]
    fjall_path: String,

    /// Admin DIDs that can manage Trust Registry records (comma-separated).
    /// Written as ADMIN_DIDS; left out of .env when not given.
    #[arg(long, short = 'a')]
    admin_dids: Option<String>,

    /// Admin DIDs (comma-separated, each also in --admin-dids) that may act on
    /// the registry itself: rotate its DID and enable or disable capabilities
    /// that have no authority. Written to ADMIN_AUTHORITIES as an entry for
    /// the registry's DID. Without it no admin can rotate the registry's DID.
    #[arg(long)]
    operator_dids: Option<String>,

    /// Existing Trust Registry DID (existing-DID mode, with
    /// --tr-did-secret-file).
    #[arg(long, short = 'r', requires = "tr_did_secret_file")]
    tr_did: Option<String>,

    /// File holding the existing DID's secrets as a JSON array (with
    /// --tr-did). `-` reads them from stdin. Read from a file rather than the
    /// command line so the keys stay out of shell history and the process
    /// list.
    #[arg(long, short = 'e', value_name = "PATH", requires = "tr_did")]
    tr_did_secret_file: Option<PathBuf>,

    /// Also create a test Trust Registry DID and a test client DID, open
    /// mediator accounts for both, and write them with their keys to
    /// ./.env.test. For development and CI only; never needed in production.
    #[arg(long, action = ArgAction::SetTrue)]
    with_test_identities: bool,

    /// Build ./.env.test for the CI pipeline, from the tracked .env.pipeline
    /// template (otherwise from testing/.env.test.example). Implies
    /// --with-test-identities. `--test-in-pipeline` and
    /// `--test-in-pipeline=true` are the same.
    #[arg(long, short = 'l', num_args = 0..=1, default_value_t = false,
          default_missing_value = "true", action = ArgAction::Set)]
    test_in_pipeline: bool,

    /// Audit log output format. Written as AUDIT_LOG_FORMAT.
    #[arg(long, short = 'o', value_parser = ["json", "text"], default_value = "json")]
    audit_log_format: String,

    /// Mediator ACL mode for the registry's DID: ExplicitDeny (public: anyone
    /// may send to it) or ExplicitAllow (private: only allow-listed DIDs may).
    /// Written as ACL_MODE; when not given, .env keeps what it has (the
    /// registry's default is ExplicitDeny).
    #[arg(long, short = 'x', value_parser = ["ExplicitDeny", "ExplicitAllow"])]
    acl_mode: Option<String>,

    /// Run without interactive prompts (CI / container provisioning). Skips the
    /// "press any key after hosting the DID document" pause for web, webvh and
    /// scid.
    #[arg(long, action = ArgAction::SetTrue)]
    non_interactive: bool,

    /// Replace identity values already in .env, an existing secret-store
    /// bundle, and existing did.json / did.jsonl / did-update-keys.json /
    /// profile files. Each is backed up first, owner-only: files as
    /// <name>.backup-<UTC timestamp>, the secret-store bundle as
    /// ./secret-store-profile.backup-<UTC timestamp>.json.
    #[arg(long, action = ArgAction::SetTrue)]
    force: bool,
}

/// How this run gets the registry's DIDComm identity.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Mode {
    /// No mediator: DIDComm off, no identity.
    NoDidcomm,
    /// `--tr-did` + `--tr-did-secret-file`.
    ExistingDid { did: String, secret_file: PathBuf },
    /// `--did-method`, optionally saving the profile to `--profile`.
    NewDid {
        method: String,
        save_to: Option<String>,
    },
    /// `--profile` without `--did-method`.
    ExistingProfile { location: String },
}

fn nonblank(v: &Option<String>) -> Option<&str> {
    v.as_deref().map(str::trim).filter(|s| !s.is_empty())
}

fn select_mode(args: &Args) -> Result<Mode, String> {
    let Some(_) = nonblank(&args.mediator_did) else {
        let mut stray = Vec::new();
        if args.did_method.is_some() {
            stray.push("--did-method");
        }
        if args.tr_did.is_some() {
            stray.push("--tr-did");
        }
        if args.profile.is_some() {
            stray.push("--profile");
        }
        if args.with_test_identities || args.test_in_pipeline {
            stray.push("--with-test-identities / --test-in-pipeline");
        }
        if args.admin_dids.is_some() || args.operator_dids.is_some() {
            stray.push("--admin-dids / --operator-dids");
        }
        if args.acl_mode.is_some() {
            stray.push("--acl-mode");
        }
        if !stray.is_empty() {
            return Err(format!(
                "{} configure DIDComm and need --mediator-did",
                stray.join(", ")
            ));
        }
        return Ok(Mode::NoDidcomm);
    };
    if let Some(location) = &args.profile {
        check_profile_locator(location)?;
    }
    match (
        &args.tr_did,
        &args.tr_did_secret_file,
        &args.did_method,
        &args.profile,
    ) {
        (Some(did), Some(file), None, None) => Ok(Mode::ExistingDid {
            did: did.trim().to_string(),
            secret_file: file.clone(),
        }),
        (None, None, Some(method), save_to) => Ok(Mode::NewDid {
            method: method.clone(),
            save_to: save_to.clone(),
        }),
        (None, None, None, Some(location)) => Ok(Mode::ExistingProfile {
            location: location.clone(),
        }),
        (None, None, None, None) => Err(
            "--mediator-did needs the registry's identity. Choose one:\n  \
             --did-method <peer|web|webvh|scid>              generate a new DID\n  \
             --tr-did <DID> --tr-did-secret-file <PATH>      use an existing DID\n  \
             --profile <URI>                                 use an existing profile"
                .into(),
        ),
        // clap's `requires` / `conflicts_with` refuse the other combinations.
        _ => Err(
            "--tr-did and --tr-did-secret-file go together, and with neither \
                  --did-method nor --profile"
                .into(),
        ),
    }
}

/// The `--profile` schemes accepted: locators, which name where a profile is
/// and never contain its keys.
const PROFILE_LOCATOR_SCHEMES: [&str; 3] = ["file://", "aws_secrets://", "aws_parameter_store://"];

fn is_profile_locator(location: &str) -> bool {
    PROFILE_LOCATOR_SCHEMES
        .iter()
        .any(|scheme| location.trim().starts_with(scheme))
}

/// Refuse a `--profile` that is not a locator. An inline JSON value or
/// `string://<JSON>` is the profile itself, private keys included, on the
/// command line, where shell history and the process list keep it. The error
/// does not repeat the value.
fn check_profile_locator(location: &str) -> Result<(), String> {
    if is_profile_locator(location) {
        Ok(())
    } else {
        Err(
            "--profile takes a location (file://, aws_secrets:// or aws_parameter_store://), \
             not the profile itself: an inline JSON or string:// value puts private keys on the \
             command line. Save it to an owner-only file and pass file:///path/to/profile.json, \
             or pass its DID and keys with --tr-did and --tr-did-secret-file."
                .into(),
        )
    }
}

/// `location` for output: a locator as given, anything else redacted, since
/// it may be a profile with its private keys.
fn shown_location(location: &str) -> String {
    if is_profile_locator(location) {
        location.trim().to_string()
    } else {
        "<redacted: not a profile locator>".to_string()
    }
}

/// `value` without one pair of surrounding quotes.
fn unquote(value: &str) -> &str {
    let v = value.trim();
    for q in ['\'', '"'] {
        if let Some(inner) = v.strip_prefix(q).and_then(|s| s.strip_suffix(q)) {
            return inner;
        }
    }
    v
}

/// What a run intends for one protected `.env` key.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Intent {
    /// Leave the line alone.
    Keep,
    /// Write this value (`None`: a value not known until the identity is
    /// generated, which is new by construction).
    Set(Option<String>),
    /// Drop the line (the profile moves to the secret store).
    Remove,
}

/// The protected values this run would replace in an existing `.env`, each
/// as a line for the operator.
fn env_conflicts(
    existing: &BTreeMap<String, String>,
    intents: &BTreeMap<&str, Intent>,
) -> Vec<String> {
    let mut conflicts = Vec::new();
    for (key, intent) in intents {
        let Some(current) = existing.get(*key).filter(|v| !is_blank_value(v)) else {
            continue;
        };
        let replaced = match intent {
            Intent::Keep => false,
            Intent::Set(None) | Intent::Remove => true,
            Intent::Set(Some(new)) => unquote(new) != unquote(current),
        };
        if replaced {
            conflicts.push(format!(
                "{ENV_PATH} already sets {key}; this run would {}",
                if *intent == Intent::Remove {
                    "remove it (the profile moves to the secret store)"
                } else {
                    "replace it"
                }
            ));
        }
    }
    conflicts
}

/// A REST-only run would set ENABLE_DIDCOMM=false under an identity the
/// existing `.env` still configures.
fn disables_existing_identity(existing: &BTreeMap<String, String>) -> bool {
    let has = |k: &str| existing.get(k).is_some_and(|v| !is_blank_value(v));
    let didcomm_off = existing
        .get("ENABLE_DIDCOMM")
        .is_some_and(|v| unquote(v).eq_ignore_ascii_case("false"));
    (has("PROFILE_CONFIG") || has("MEDIATOR_DID")) && !didcomm_off
}

/// Read the existing DID's secrets from `path`, or from stdin for `-`.
fn read_secret_file(path: &Path) -> Result<String, BoxError> {
    if path == Path::new("-") {
        let mut buf = String::new();
        std::io::stdin().read_to_string(&mut buf)?;
        Ok(buf)
    } else {
        fs::read_to_string(path)
            .map_err(|e| format!("Failed to read {}: {e}", path.display()).into())
    }
}

/// What may be shown of a profile bundle: its DID and key ids, never the
/// key material.
fn profile_summary(did: &str, secrets: &[Secret]) -> String {
    let mut out = format!("  DID: {did}");
    for secret in secrets {
        out.push_str(&format!("\n  key: {}", secret.id));
    }
    out
}

/// Write a generated profile bundle to `path`, owner-only, refusing to
/// replace an existing file.
fn write_profile_file(path: &Path, bundle: &str) -> std::io::Result<()> {
    create_private(path, format!("{bundle}\n").as_bytes())
}

/// Create `path` with `contents` (a public document, so default permissions),
/// refusing to replace an existing file.
fn create_public(path: &Path, contents: &[u8]) -> std::io::Result<()> {
    use std::io::Write as _;
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)?;
    file.write_all(contents)?;
    file.sync_all()
}

/// Where to save a generated profile for `--profile <location>`: the path of
/// a `file://` location, else a local file the operator uploads to it.
fn profile_output_path(location: &str) -> PathBuf {
    match location.strip_prefix("file://") {
        Some(path) if !path.is_empty() => PathBuf::from(path),
        _ => PathBuf::from(LOCAL_PROFILE_PATH),
    }
}

/// Check that `secrets` can be published as `did`'s document, so a profile
/// the registry could not serve is refused here rather than at its startup.
fn check_publishable(did: &str, secrets: &[Secret]) -> Result<(), String> {
    trust_registry::didcomm::did_document::build_verification_methods_for(did, secrets)
        .map(|_| ())
        .map_err(|e| format!("the profile's keys cannot be published: {e}"))
}

/// Open a mediator account for `did` and, if it is private, make it public
/// (explicit-deny) so the test client can reach the test registry.
pub async fn set_acl(
    alias: &str,
    did: &str,
    mediator_did: &str,
    secrets: Vec<Secret>,
) -> Result<(), String> {
    let profile = TDKProfile::new(alias, did, Some(mediator_did), secrets);

    let config = TDKConfig::builder()
        .with_load_environment(false)
        .build()
        .map_err(|e| format!("TDK configuration: {e}"))?;
    let tdk = TDK::new(config, None)
        .await
        .map_err(|e| format!("TDK start: {e}"))?;
    tdk.add_profile(&profile).await;
    let atm = Arc::new(
        tdk.atm
            .clone()
            .ok_or("the TDK started without its messaging component")?,
    );

    let atm_profile = ATMProfile::from_tdk_profile(&atm, &profile)
        .await
        .map_err(|e| {
            format!(
                "creating the messaging profile for {did}: {e}. This might indicate an issue \
                 with DID resolution or service endpoint configuration"
            )
        })?;

    let profile = atm.profile_add(&atm_profile, true).await.map_err(|e| {
        format!(
            "connecting {did} to the mediator: {e}. Possible causes: the mediator is not \
             running or unreachable, the DID document's service endpoints are wrong, network \
             connectivity, or an authentication/key mismatch"
        )
    })?;
    // Open the registry to senders (explicit-deny) if its mediator account is
    // private, through the mediator's Trust Tasks.
    trust_registry::mediator_acl::open_if_private(&atm, &profile)
        .await
        .map_err(|e| {
            format!(
                "setting the mediator access-list mode for {did}: {e}. The mediator must \
                 serve the messaging/account Trust Tasks"
            )
        })
}

/// `secret`'s key under `id`, in the JWK form a profile bundle carries.
fn jwk_secret(id: &str, secret: &Secret) -> Result<Secret, String> {
    let SecretMaterial::JWK(jwk) = &secret.secret_material else {
        return Err(format!("{id}: a generated key has no JWK form"));
    };
    serde_json::from_value(json!({
        "id": id,
        "type": "JsonWebKey2020",
        "privateKeyJwk": jwk
    }))
    .map_err(|e| format!("{id}: {e}"))
}

/// An Ed25519 signing key and an X25519 key-agreement key.
///
/// Curve25519 because a mediator holds those keys by default (`mediator-setup`
/// adds P-256 only when asked), so a P-256 DID cannot authenticate to one, and
/// Ed25519 is the only key the messaging SDK signs Trust Tasks with: a mediator
/// enforcing Trust Task verification refuses the registry's unsigned
/// `messaging/account/update` from a P-256-only DID.
fn create_keys() -> Result<(Secret, Secret), String> {
    let verification_key = Secret::generate_ed25519(None, None);
    let encryption_key =
        Secret::generate_x25519(None, None).map_err(|e| format!("X25519 key: {e}"))?;
    Ok((verification_key, encryption_key))
}

/// A did:peer routed through `mediator_did`, with the key pair
/// [`create_keys`] explains: Ed25519 to sign, X25519 to agree keys.
pub fn create_did(mediator_did: &str) -> Result<(String, Vec<Secret>), String> {
    let (mut verification_key, mut encryption_key) = create_keys()?;
    let v_multibase = verification_key
        .get_public_keymultibase()
        .map_err(|e| format!("verification key multibase: {e}"))?;
    let e_multibase = encryption_key
        .get_public_keymultibase()
        .map_err(|e| format!("encryption key multibase: {e}"))?;

    let keys = vec![
        PeerCreateKey::from_multibase(PeerKeyPurpose::Verification, v_multibase),
        PeerCreateKey::from_multibase(PeerKeyPurpose::Encryption, e_multibase),
    ];

    let services = Some(vec![PeerService {
        id: None,
        type_: "dm".into(),
        endpoint: PeerServiceEndpoint::Uri(mediator_did.to_string()),
    }]);

    let (did_peer, _) = DIDCommon::generate_peer(&keys, services.as_deref())
        .map_err(|e| format!("did:peer creation: {e}"))?;
    let did_peer_str = did_peer.to_string();

    verification_key.id = [did_peer_str.as_str(), "#key-1"].concat();
    encryption_key.id = [did_peer_str.as_str(), "#key-2"].concat();

    Ok((did_peer_str, vec![verification_key, encryption_key]))
}

/// The did:webvh update key that signed the first log entry and the
/// pre-rotation key whose hash it committed. Without them no further entry
/// (key rotation, new endpoints, deactivation) can ever be made.
#[derive(Serialize)]
struct UpdateKeys {
    /// The DID the keys control (the did:webvh, also for `scid`).
    did: String,
    /// Signed log entry 1; listed in its `updateKeys`.
    #[serde(rename = "updateKey")]
    update_key: Secret,
    /// Committed in entry 1's `nextKeyHashes`: entry 2 must list this key in
    /// its `updateKeys`, be signed by it, and commit the hash of a new next key.
    #[serde(rename = "nextUpdateKey")]
    next_update_key: Secret,
}

/// A generated did:web / did:webvh / did:scid, held in memory until the
/// write phase.
struct WebDid {
    did: String,
    secrets: Vec<Secret>,
    did_json: String,
    did_jsonl: Option<String>,
    update_keys: Option<UpdateKeys>,
}

/// The `did:key` form of `secret`'s public key, as its id.
fn did_key_id(secret: &Secret) -> Result<String, String> {
    let mb = secret
        .get_public_keymultibase()
        .map_err(|e| format!("update key multibase: {e}"))?;
    Ok(format!("did:key:{mb}#{mb}"))
}

/// `async` because `didwebvh-rs` made `create_log_entry` async (it may
/// resolve a witness/watcher list).
async fn create_web_did(
    mediator_did: &str,
    web_url: &str,
    did_method: &str,
    scid_alias: bool,
) -> Result<WebDid, BoxError> {
    // A did:scid is presented from a did:webvh log; the alias is what says so
    // to a resolver of the did:webvh (VTI-KEY-166).
    let webvh_log = did_method == "webvh" || did_method == "scid";
    if did_method == "scid" && !scid_alias {
        return Err("--no-scid-alias cannot be used with --did-method scid".into());
    }

    let parsed_url = Url::parse(web_url)?;
    let did_url_raw = WebVHURL::parse_url(&parsed_url)?;
    let mut tr_did = if did_method == "web" {
        did_url_raw.to_string().replace("webvh:{SCID}", "web")
    } else {
        did_url_raw.to_string()
    };

    let (verification_key, encryption_key) = create_keys()?;

    // The document comes from the registry's own builder, so the published
    // document and one the registry would build for itself are the same:
    // each key under its own id, relationships by key type, and the service
    // entries gated on the same `TransportFlags` the server reads. This run
    // writes ENABLE_DIDCOMM=true, so DIDComm is on whatever the shell says.
    let mut flags = transport_flags_from_env()?;
    flags.didcomm = true;
    flags.validate()?;
    let public_url = std::env::var("TR_PUBLIC_URL")
        .ok()
        .map(|u| u.trim().to_string())
        .filter(|u| !u.is_empty());
    if let Some(url) = public_url.as_deref() {
        validate_public_url(url)?;
    } else if flags.rest {
        println!(
            "  ! ENABLE_REST=true but TR_PUBLIC_URL is unset — REST will be served but not \
             advertised in the DID document."
        );
    }
    let doc_keys = [
        jwk_secret(&format!("{tr_did}#key-1"), &verification_key)?,
        jwk_secret(&format!("{tr_did}#key-2"), &encryption_key)?,
    ];
    let mut document = build_did_document_value(
        &tr_did,
        &doc_keys,
        mediator_did,
        public_url.as_deref(),
        flags,
    )?;

    let mut did_jsonl = None;
    let mut update_keys = None;
    if webvh_log {
        let mut update_secret = Secret::generate_ed25519(None, None);
        update_secret.id = did_key_id(&update_secret)?;
        let mut next_update_secret = Secret::generate_ed25519(None, None);
        next_update_secret.id = did_key_id(&next_update_secret)?;

        let parameters = Parameters::new()
            .with_key_pre_rotation(true)
            .with_update_keys(vec![update_secret.get_public_keymultibase()?])
            .with_next_key_hashes(vec![next_update_secret.get_public_keymultibase_hash()?])
            .with_portable(true)
            .build();

        if scid_alias {
            // Written against the `{SCID}` placeholder, which the log entry
            // fills in, as `didwebvh_rs::create::create_did` does.
            add_scid_also_known_as(&mut document, &tr_did)?;
        }

        let mut didwebvh = DIDWebVHState::default();
        let log_entry = didwebvh
            .create_log_entry(None, &document, &parameters, &update_secret)
            .await?;
        tr_did = log_entry
            .get_state()
            .get("id")
            .and_then(Value::as_str)
            .ok_or("the did:webvh log entry has no id")?
            .to_string();
        did_jsonl = Some(format!(
            "{}\n",
            serde_json::to_string(&log_entry.log_entry)?
        ));
        document = log_entry.get_did_document()?;
        update_keys = Some(UpdateKeys {
            did: tr_did.clone(),
            update_key: update_secret,
            next_update_key: next_update_secret,
        });
    }

    // A did:scid Trust Registry is known by its bare DID, and its keys are
    // under it in its own document (VTI-KEY-161). Its profile DID is the DID
    // URL with `?src=`, so what it sends carries the locator a peer needs to
    // resolve it (VTI-KEY-163).
    let key_did = if did_method == "scid" {
        let scid_url = DIDWebVHState::convert_webvh_id_to_scid_id(&tr_did);
        let bare = scid_url
            .split_once('?')
            .map(|(did, _)| did.to_string())
            .ok_or_else(|| format!("{tr_did} has no did:scid form"))?;
        println!("  did:webvh log: {tr_did}");
        tr_did = scid_url;
        bare
    } else {
        tr_did.clone()
    };

    let secrets = vec![
        jwk_secret(&format!("{key_did}#key-1"), &verification_key)?,
        jwk_secret(&format!("{key_did}#key-2"), &encryption_key)?,
    ];

    Ok(WebDid {
        did: tr_did,
        secrets,
        did_json: serde_json::to_string_pretty(&document)?,
        did_jsonl,
        update_keys,
    })
}

/// Restores the terminal on every exit path, error included.
struct RawModeGuard;

impl RawModeGuard {
    fn enable() -> std::io::Result<Self> {
        terminal::enable_raw_mode()?;
        Ok(Self)
    }
}

impl Drop for RawModeGuard {
    fn drop(&mut self) {
        let _ = terminal::disable_raw_mode();
    }
}

fn wait_for_key() -> Result<(), BoxError> {
    let _guard = RawModeGuard::enable()?;
    loop {
        if let Event::Key(key_event) = event::read()?
            && key_event.kind == event::KeyEventKind::Press
        {
            return Ok(());
        }
    }
}

/// Create the test registry and test client DIDs, open their mediator
/// accounts, and write them to `.env.test`. Any failure is returned.
async fn setup_test_identities(mediator_did: &str, in_pipeline: bool) -> Result<(), BoxError> {
    println!("Generating test DIDs (--with-test-identities)...");

    let test_tr_did = create_did(mediator_did)?;
    let test_client_did = create_did(mediator_did)?;
    let test_tr_profile_configs = json!({
        "did": test_tr_did.0,
        "alias": "Test Trust Registry",
        "secrets": test_tr_did.1
    });

    println!("Configuring mediator accounts for the test DIDs...");
    for (did, secrets) in [&test_tr_did, &test_client_did] {
        set_acl(did, did, mediator_did, secrets.clone())
            .await
            .map_err(|e| format!("test identity {did}: {e}"))?;
    }
    println!("✓ Configured test DIDs on the mediator.");

    let client_secrets = serde_json::to_string(&serde_json::to_string(&test_client_did.1)?)?;
    let mut vars = BTreeMap::new();
    vars.insert("TRUST_REGISTRY_DID".to_string(), test_tr_did.0.clone());
    vars.insert("CLIENT_DID".to_string(), test_client_did.0.clone());
    vars.insert("ADMIN_DIDS".to_string(), test_client_did.0.clone());
    vars.insert("CLIENT_SECRETS".to_string(), client_secrets);
    vars.insert(
        "PROFILE_CONFIG".to_string(),
        format!("'{}'", serde_json::to_string(&test_tr_profile_configs)?),
    );
    // `.env.pipeline` is a tracked template: the generated keys go to the
    // untracked `.env.test`, built from it.
    let template = if in_pipeline {
        "./.env.pipeline"
    } else {
        vars.insert("MEDIATOR_DID".to_string(), mediator_did.to_string());
        "./testing/.env.test.example"
    };
    insert_env_vars("./.env.test", vars, &[], Some(template))?;
    println!("✓ Wrote the test identities to .env.test (from {template}).");
    Ok(())
}

/// The registry identity this run produced, before anything is written.
struct Identity {
    did: String,
    bundle: String,
    /// The `PROFILE_CONFIG` value when the profile stays in `.env`.
    env_value: String,
    /// A generated profile to write to this file.
    profile_file: Option<PathBuf>,
    web: Option<WebDid>,
}

fn bundle_of(did: &str, secrets: &[Secret]) -> Result<String, BoxError> {
    Ok(serde_json::to_string(&ProfileConfig {
        alias: "Trust Registry".to_string(),
        did: did.to_string(),
        secrets: secrets.to_vec(),
    })?)
}

/// Build the identity for `mode` in memory. Writes nothing.
async fn prepare_identity(
    mode: &Mode,
    args: &Args,
    mediator_did: &str,
) -> Result<Option<Identity>, BoxError> {
    match mode {
        Mode::NoDidcomm => Ok(None),
        Mode::ExistingDid { did, secret_file } => {
            println!("Mode: existing Trust Registry DID {did}");
            let raw = read_secret_file(secret_file)?;
            let secrets: Vec<Secret> = serde_json::from_str(&raw)
                .map_err(|e| format!("Failed to parse --tr-did-secret-file as JSON: {e}"))?;
            check_publishable(did, &secrets)?;
            let bundle = bundle_of(did, &secrets)?;
            Ok(Some(Identity {
                did: did.clone(),
                env_value: format!("'{bundle}'"),
                bundle,
                profile_file: None,
                web: None,
            }))
        }
        Mode::ExistingProfile { location } => {
            let shown = shown_location(location);
            println!("Mode: existing profile at {shown}");
            let bundle = trust_registry::configs::loaders::load(location)
                .await
                .map_err(|e| format!("could not load the profile from {shown}: {e}"))?;
            let profile = trust_registry::configs::didcomm::parse_profile_from_secrets_str(&bundle)
                .map_err(|e| format!("{shown} does not hold a profile bundle: {e}"))?;
            check_publishable(&profile.did, &profile.secrets)?;
            println!("✓ Profile loaded and validated (no key generated):");
            println!("{}", profile_summary(&profile.did, &profile.secrets));
            Ok(Some(Identity {
                did: profile.did,
                bundle,
                env_value: location.clone(),
                profile_file: None,
                web: None,
            }))
        }
        Mode::NewDid { method, save_to } => {
            println!("Mode: generating a new Trust Registry DID (did:{method})");
            let (did, secrets, web) = match method.as_str() {
                "peer" => {
                    let (did, secrets) = create_did(mediator_did)?;
                    (did, secrets, None)
                }
                "web" | "webvh" | "scid" => {
                    let web_url = args
                        .didweb_url
                        .as_deref()
                        .ok_or_else(|| format!("--didweb-url is required for did:{method}"))?;
                    let web =
                        create_web_did(mediator_did, web_url, method, !args.no_scid_alias).await?;
                    (web.did.clone(), web.secrets.clone(), Some(web))
                }
                other => return Err(format!("Unsupported DID method: {other}").into()),
            };
            println!("✓ Trust Registry DID created: {did}");
            let bundle = bundle_of(&did, &secrets)?;
            let (env_value, profile_file) = match save_to {
                None => (format!("'{bundle}'"), None),
                Some(location) => (location.clone(), Some(profile_output_path(location))),
            };
            Ok(Some(Identity {
                did,
                bundle,
                env_value,
                profile_file,
                web,
            }))
        }
    }
}

/// Files this run would create, for the conflict check.
fn files_to_create(mode: &Mode) -> Vec<PathBuf> {
    let mut files = Vec::new();
    if let Mode::NewDid { method, save_to } = mode {
        if method != "peer" {
            files.push(PathBuf::from(DID_JSON_PATH));
        }
        if method == "webvh" || method == "scid" {
            files.push(PathBuf::from(DID_JSONL_PATH));
            files.push(PathBuf::from(UPDATE_KEYS_PATH));
        }
        if let Some(location) = save_to {
            files.push(profile_output_path(location));
        }
    }
    files
}

fn utc_stamp() -> String {
    chrono::Utc::now().format("%Y%m%dT%H%M%SZ").to_string()
}

#[tokio::main]
async fn main() {
    if let Err(e) = run(Args::parse()).await {
        eprintln!();
        eprintln!("✗ {e}");
        std::process::exit(1);
    }
}

async fn run(args: Args) -> Result<(), BoxError> {
    println!();
    println!("🚀 Setting up Affinidi Trust Registry");
    println!();

    let mode = select_mode(&args)?;
    let mediator_did = nonblank(&args.mediator_did).unwrap_or_default().to_string();
    let enable_didcomm = mode != Mode::NoDidcomm;
    let with_test_identities = args.with_test_identities || args.test_in_pipeline;
    let admin_dids = nonblank(&args.admin_dids).map(str::to_string);

    let operator_dids: Vec<String> = args
        .operator_dids
        .as_deref()
        .unwrap_or("")
        .split(',')
        .map(|d| d.trim().to_string())
        .filter(|d| !d.is_empty())
        .collect();
    if let Some(stranger) = operator_dids.iter().find(|d| {
        !admin_dids
            .as_deref()
            .unwrap_or("")
            .split(',')
            .any(|a| a.trim() == d.as_str())
    }) {
        return Err(
            format!("--operator-dids names {stranger}, which is not in --admin-dids").into(),
        );
    }

    // ---- Pre-flight: everything that can refuse, before anything is written.
    let store_cfg = trust_registry::configs::secret_store::secrets_config_from_env()?;
    let store_backend = trust_registry::configs::secret_store::selected_backend(&store_cfg)
        .filter(|_| enable_didcomm);
    let use_store = store_backend.is_some();
    if store_backend == Some(vti_secrets::SecretBackend::ConfigSeed) {
        return Err(
            "TR_SECRETS_SEED selects a read-only store: it must already hold the \
                    hex-encoded profile bundle JSON. Unset it, or select a writable backend, \
                    to provision the profile."
                .into(),
        );
    }
    let store_name = store_backend.map_or(
        "configured",
        trust_registry::configs::secret_store::backend_name,
    );
    let store_dir = trust_registry::configs::secret_store::data_dir();

    let existing_env = env_file::read_env_vars(Path::new(ENV_PATH))?;
    let mut intents: BTreeMap<&str, Intent> =
        PROTECTED_KEYS.iter().map(|k| (*k, Intent::Keep)).collect();
    if let Some(m) = nonblank(&args.mediator_did) {
        intents.insert("MEDIATOR_DID", Intent::Set(Some(m.to_string())));
    }
    if let Some(a) = &admin_dids {
        intents.insert("ADMIN_DIDS", Intent::Set(Some(a.clone())));
    }
    if let Some(acl) = &args.acl_mode {
        intents.insert("ACL_MODE", Intent::Set(Some(acl.clone())));
    }
    if !operator_dids.is_empty() {
        intents.insert("ADMIN_AUTHORITIES", Intent::Set(None));
    }
    let profile_intent = match &mode {
        Mode::NoDidcomm => Intent::Keep,
        _ if use_store => Intent::Remove,
        Mode::ExistingProfile { location } => Intent::Set(Some(location.clone())),
        Mode::NewDid {
            save_to: Some(location),
            ..
        } => Intent::Set(Some(location.clone())),
        _ => Intent::Set(None),
    };
    intents.insert("PROFILE_CONFIG", profile_intent);

    let mut conflicts = Vec::new();
    if let Some(existing) = &existing_env {
        conflicts.extend(env_conflicts(existing, &intents));
        if !enable_didcomm && disables_existing_identity(existing) {
            conflicts.push(format!(
                "{ENV_PATH} configures a DIDComm identity (PROFILE_CONFIG / MEDIATOR_DID); \
                 without --mediator-did this run would set ENABLE_DIDCOMM=false"
            ));
        }
    }
    let files = files_to_create(&mode);
    for file in &files {
        if file.exists() {
            conflicts.push(format!("{} already exists", file.display()));
        }
    }
    let existing_bundle = if use_store {
        trust_registry::configs::secret_store::read_profile(&store_cfg, &store_dir)
            .await
            .map_err(|e| format!("could not read the configured secret store: {e}"))?
            .filter(|b| !b.trim().is_empty())
    } else {
        None
    };
    if existing_bundle.is_some() {
        conflicts.push("the configured secret store already holds a profile bundle".to_string());
    }
    if !conflicts.is_empty() && !args.force {
        return Err(format!(
            "refusing to replace the existing Trust Registry configuration:\n  - {}\n\n\
             Nothing was changed. Re-run with --force to replace these (each is backed up \
             first, owner-only), or use the existing identity: --profile <URI> or --tr-did.",
            conflicts.join("\n  - ")
        )
        .into());
    }

    // ---- Build the identity in memory (did:web may prompt later, after
    // the document is written).
    if enable_didcomm {
        println!("Trust Registry DIDComm configuration");
        println!("Mediator DID: {mediator_did}");
        println!();
    } else {
        println!("No --mediator-did: DIDComm disabled (ENABLE_DIDCOMM=false), REST only.");
    }
    let identity = prepare_identity(&mode, &args, &mediator_did).await?;

    // Test identities touch the mediator, which can fail: do it before the
    // registry's own configuration is written.
    if with_test_identities {
        setup_test_identities(&mediator_did, args.test_in_pipeline).await?;
    }

    // ---- Write phase. Back up what --force replaces, then write.
    let stamp = utc_stamp();
    if args.force && !conflicts.is_empty() {
        if Path::new(ENV_PATH).exists() {
            let backup = backup_file(Path::new(ENV_PATH), &stamp)?;
            println!("✓ Backed up {ENV_PATH} to {}", backup.display());
        }
        for file in files.iter().filter(|f| f.exists()) {
            let backup = backup_path(file, &stamp);
            fs::rename(file, &backup)
                .map_err(|e| format!("could not back up {}: {e}", file.display()))?;
            println!("✓ Moved {} to {}", file.display(), backup.display());
        }
        if let Some(bundle) = &existing_bundle {
            let backup = PathBuf::from(format!("./secret-store-profile.backup-{stamp}.json"));
            create_private(&backup, bundle.as_bytes())
                .map_err(|e| format!("could not back up the secret-store bundle: {e}"))?;
            println!(
                "✓ Backed up the secret store's profile bundle to {} (owner-only)",
                backup.display()
            );
        }
    }

    if let Some(identity) = &identity {
        if let Some(web) = &identity.web {
            create_public(Path::new(DID_JSON_PATH), web.did_json.as_bytes())?;
            if let Some(log) = &web.did_jsonl {
                create_public(Path::new(DID_JSONL_PATH), log.as_bytes())?;
            }
            if let Some(keys) = &web.update_keys {
                create_private(
                    Path::new(UPDATE_KEYS_PATH),
                    format!("{}\n", serde_json::to_string_pretty(keys)?).as_bytes(),
                )?;
                println!(
                    "✓ did:webvh update key and pre-rotation key written to {UPDATE_KEYS_PATH} \
                     (owner-only). They are the only way to update this DID (rotate keys, \
                     change endpoints, deactivate): keep the file offline and safe."
                );
            }
            println!(
                "✓ DID document written to {DID_JSON_PATH}{}",
                if web.did_jsonl.is_some() {
                    format!(" and the did:webvh log to {DID_JSONL_PATH}")
                } else {
                    String::new()
                }
            );
        }
        if let Some(path) = &identity.profile_file {
            write_profile_file(path, &identity.bundle).map_err(|e| {
                format!(
                    "Failed to write the generated profile to {}: {e}",
                    path.display()
                )
            })?;
            println!(
                "✓ Profile (with its private keys) written to {}",
                path.display()
            );
            if let Mode::NewDid {
                save_to: Some(location),
                ..
            } = &mode
                && path != Path::new(location.trim_start_matches("file://"))
            {
                println!(
                    "  Store it at {}, then delete the local file.",
                    shown_location(location)
                );
            }
        }
    }

    // A secret-store backend (TR_SECRETS_*) holds the bundle in place of
    // PROFILE_CONFIG; a plaintext copy in .env would defeat the store. Only a
    // bundle that parsed as a profile is ever written there.
    let mut set: BTreeMap<String, String> = BTreeMap::new();
    let mut remove: Vec<&str> = Vec::new();
    if let Some(identity) = &identity {
        if use_store {
            trust_registry::configs::secret_store::write_profile(
                &store_cfg,
                &store_dir,
                &identity.bundle,
            )
            .await
            .map_err(|e| format!("Failed to write the profile to the secret store: {e}"))?;
            println!("✓ Profile bundle provisioned into the {store_name} secret-store backend");
            remove.push("PROFILE_CONFIG");
        } else {
            set.insert("PROFILE_CONFIG".into(), identity.env_value.clone());
        }
    }

    set.insert("ENABLE_DIDCOMM".into(), enable_didcomm.to_string());
    if enable_didcomm {
        set.insert("MEDIATOR_DID".into(), mediator_did.clone());
    }
    if let Some(a) = &admin_dids {
        set.insert("ADMIN_DIDS".into(), a.clone());
    }
    if let Some(acl) = &args.acl_mode {
        set.insert("ACL_MODE".into(), acl.clone());
    }
    match (operator_dids.is_empty(), &identity) {
        (false, Some(identity)) => {
            let authorities: serde_json::Map<String, Value> = operator_dids
                .iter()
                .map(|operator| (operator.clone(), json!([identity.did])))
                .collect();
            set.insert(
                "ADMIN_AUTHORITIES".into(),
                format!("'{}'", serde_json::to_string(&authorities)?),
            );
            println!(
                "✓ ADMIN_AUTHORITIES lets {} act on the registry itself (DID rotation, \
                 capabilities without an authority).",
                operator_dids.join(", ")
            );
        }
        (false, None) => {}
        (true, _) if admin_dids.is_some() => println!(
            "Note: no admin may rotate the registry's DID or enable a capability without an \
             authority until ADMIN_AUTHORITIES lists the registry's DID for it. Pass \
             --operator-dids <admin DID> to write that entry."
        ),
        (true, _) => {}
    }

    // Storage.
    set.insert("TR_STORAGE_BACKEND".into(), args.storage_backend.clone());
    match args.storage_backend.as_str() {
        "csv" => {
            set.insert("FILE_STORAGE_PATH".into(), args.file_storage_path.clone());
        }
        "ddb" => {
            let table = nonblank(&args.ddb_table_name)
                .ok_or("--ddb-table-name is required with the ddb backend")?;
            set.insert("DDB_TABLE_NAME".into(), table.to_string());
        }
        "redis" => {
            set.insert("REDIS_URL".into(), args.redis_url.clone());
        }
        "fjall" => {
            set.insert("TR_FJALL_PATH".into(), args.fjall_path.clone());
        }
        _ => {}
    }
    set.insert("AUDIT_LOG_FORMAT".into(), args.audit_log_format.clone());

    // Never write an empty value; drop protected keys this run leaves blank,
    // and on a first run the example's placeholders for keys it did not set.
    set.retain(|_, v| !is_blank_value(v));
    for key in PROTECTED_KEYS {
        if set.contains_key(key) || remove.contains(&key) {
            continue;
        }
        let drop = match &existing_env {
            Some(existing) => existing.get(key).is_some_and(|v| is_blank_value(v)),
            None => key != "ACL_MODE",
        };
        if drop {
            remove.push(key);
        }
    }

    println!();
    println!("Environment configuration:");
    for (key, value) in &set {
        let shown = match key.as_str() {
            // A locator as given; an inline profile (keys) never.
            "PROFILE_CONFIG" if is_profile_locator(value) => value.clone(),
            "PROFILE_CONFIG" => "<redacted: written to .env>".to_string(),
            "REDIS_URL" => trust_registry::configs::storage::redact_url_credentials(value),
            _ => value.clone(),
        };
        println!("  {key}={shown}");
    }

    insert_env_vars(ENV_PATH, set, &remove, Some(ENV_EXAMPLE_PATH))?;
    println!("✓ {ENV_PATH} updated (comments and other lines kept)");

    if identity.as_ref().is_some_and(|i| i.web.is_some()) {
        let url = args.didweb_url.as_deref().unwrap_or_default();
        println!();
        println!("IMPORTANT: host the DID document before starting the Trust Registry.");
        println!("It must be publicly reachable under {url}.");
        if args.non_interactive {
            println!("Non-interactive mode: not waiting.");
        } else {
            println!("Press any key once it is hosted...");
            wait_for_key()?;
        }
    }

    println!();
    println!("Start the Trust Registry with:");
    println!("RUST_LOG=info cargo run --bin trust-registry");
    println!();
    Ok(())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]
    use super::*;

    fn parse(extra: &[&str]) -> Result<Args, clap::Error> {
        let mut argv = vec!["setup-trust-registry"];
        argv.extend_from_slice(extra);
        Args::try_parse_from(argv)
    }

    #[test]
    fn the_profile_summary_shows_ids_but_no_key_material() {
        let (did, secrets) = create_did("did:example:mediator").unwrap();
        let bundle = bundle_of(&did, &secrets).unwrap();
        let private_d: Vec<String> = serde_json::from_str::<Value>(&bundle).unwrap()["secrets"]
            .as_array()
            .unwrap()
            .iter()
            .map(|s| s["privateKeyJwk"]["d"].as_str().unwrap().to_string())
            .collect();
        assert_eq!(private_d.len(), 2);

        let summary = profile_summary(&did, &secrets);
        assert!(summary.contains(&did));
        assert!(summary.contains("#key-1") && summary.contains("#key-2"));
        for d in private_d {
            assert!(!summary.contains(&d));
        }
        assert!(!summary.contains("privateKeyJwk"));
    }

    #[test]
    fn a_generated_profile_goes_to_the_file_location_or_a_local_file() {
        assert_eq!(
            profile_output_path("file:///etc/tr/profile.json"),
            PathBuf::from("/etc/tr/profile.json")
        );
        assert_eq!(
            profile_output_path("aws_secrets://tr-profile"),
            PathBuf::from("./trust-registry-profile.json")
        );
    }

    #[test]
    fn a_profile_file_is_never_overwritten_and_is_owner_only() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("profile.json");
        write_profile_file(&path, "{}").unwrap();
        assert!(write_profile_file(&path, "{\"other\":1}").is_err());
        assert_eq!(fs::read_to_string(&path).unwrap(), "{}\n");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(&path).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
    }

    #[test]
    fn the_existing_secret_is_read_from_a_file_not_the_command_line() {
        let args = parse(&[
            "--mediator-did",
            "did:example:m",
            "--tr-did",
            "did:example:tr",
            "--tr-did-secret-file",
            "/run/secrets/tr.json",
        ])
        .unwrap();
        assert_eq!(
            select_mode(&args).unwrap(),
            Mode::ExistingDid {
                did: "did:example:tr".into(),
                secret_file: PathBuf::from("/run/secrets/tr.json")
            }
        );
        assert!(parse(&["--tr-did-secret", "[]"]).is_err());
    }

    /// #220: `--profile` alone is the existing-profile mode; it used to be
    /// unreachable behind `--did-method`'s default and generated a new DID.
    #[test]
    fn profile_without_did_method_is_the_existing_profile_mode() {
        let args = parse(&[
            "-d",
            "did:example:m",
            "--profile",
            "file:///etc/tr/profile.json",
        ])
        .unwrap();
        assert_eq!(
            select_mode(&args).unwrap(),
            Mode::ExistingProfile {
                location: "file:///etc/tr/profile.json".into()
            }
        );
        let args = parse(&["-d", "did:example:m", "-m", "peer", "-p", "file:///x.json"]).unwrap();
        assert_eq!(
            select_mode(&args).unwrap(),
            Mode::NewDid {
                method: "peer".into(),
                save_to: Some("file:///x.json".into())
            }
        );
    }

    /// `--profile` takes a locator only. An inline profile (JSON or
    /// `string://`) carries private keys, so it is refused in both modes, and
    /// the refusal does not echo it.
    #[test]
    fn an_inline_profile_is_refused_without_echoing_it() {
        let inline = r#"{"alias":"TR","did":"did:example:tr","secrets":[{"privateKeyJwk":{"d":"SECRET-D"}}]}"#;
        let string_uri = format!("string://{inline}");
        for value in [inline, string_uri.as_str()] {
            for extra in [&[][..], &["-m", "peer"][..]] {
                let mut argv = vec!["-d", "did:example:m", "--profile", value];
                argv.extend_from_slice(extra);
                let err = select_mode(&parse(&argv).unwrap()).unwrap_err();
                assert!(err.contains("--profile takes a location"), "{err}");
                assert!(!err.contains("SECRET-D"), "the refusal echoes the profile");
            }
        }
        for locator in [
            "file:///etc/tr/profile.json",
            "aws_secrets://tr",
            "aws_parameter_store://tr",
        ] {
            assert!(select_mode(&parse(&["-d", "did:example:m", "-p", locator]).unwrap()).is_ok());
            assert_eq!(shown_location(locator), locator);
        }
        // Defence in depth: anything that is not a locator is never shown.
        assert!(!shown_location(inline).contains("SECRET-D"));
        assert!(!shown_location(&string_uri).contains("SECRET-D"));
    }

    /// No default method: a mediator without a mode is an error naming the
    /// three, not a silently generated did:peer.
    #[test]
    fn a_mediator_without_a_mode_is_refused() {
        let args = parse(&["-d", "did:example:m"]).unwrap();
        assert!(args.did_method.is_none());
        let err = select_mode(&args).unwrap_err();
        assert!(
            err.contains("--did-method") && err.contains("--profile"),
            "{err}"
        );
    }

    #[test]
    fn half_an_existing_did_or_mixed_modes_are_refused() {
        assert!(parse(&["-d", "did:example:m", "--tr-did", "did:example:tr"]).is_err());
        assert!(parse(&["-d", "did:example:m", "--tr-did-secret-file", "s.json"]).is_err());
        assert!(
            parse(&[
                "-d",
                "did:example:m",
                "-m",
                "peer",
                "--tr-did",
                "did:x",
                "-e",
                "s.json"
            ])
            .is_err()
        );
    }

    #[test]
    fn didcomm_flags_without_a_mediator_are_refused() {
        for extra in [
            &["-m", "peer"][..],
            &["--with-test-identities"],
            &["--admin-dids", "did:example:a"],
            &["--acl-mode", "ExplicitAllow"],
        ] {
            let args = parse(extra).unwrap();
            assert!(select_mode(&args).is_err(), "{extra:?}");
        }
        assert_eq!(select_mode(&parse(&[]).unwrap()).unwrap(), Mode::NoDidcomm);
    }

    /// CI passes `--test-in-pipeline=true`; a bare switch works too.
    #[test]
    fn test_in_pipeline_is_a_switch_that_accepts_true() {
        assert!(
            parse(&["--test-in-pipeline=true"])
                .unwrap()
                .test_in_pipeline
        );
        assert!(parse(&["--test-in-pipeline"]).unwrap().test_in_pipeline);
        assert!(!parse(&[]).unwrap().test_in_pipeline);
        assert!(!parse(&[]).unwrap().with_test_identities);
    }

    #[test]
    fn flag_values_are_checked() {
        assert!(parse(&["-s", "fjall"]).is_ok());
        assert!(parse(&["-s", "sqlite"]).is_err());
        assert!(parse(&["-o", "xml"]).is_err());
        assert!(parse(&["-s", "ddb"]).is_err(), "ddb needs a table name");
        assert!(parse(&["-s", "ddb", "-t", "records"]).is_ok());
        assert!(parse(&[]).unwrap().acl_mode.is_none());
    }

    fn env(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    /// #191: a re-run must not replace an identity already in `.env`.
    #[test]
    fn a_rerun_that_would_replace_the_identity_is_a_conflict() {
        let existing = env(&[
            ("PROFILE_CONFIG", "'{\"did\":\"did:example:old\"}'"),
            ("MEDIATOR_DID", "\"did:example:m\""),
            ("ADMIN_DIDS", ""),
            ("ACL_MODE", "ExplicitDeny # Options: ..."),
        ]);
        let mut intents: BTreeMap<&str, Intent> =
            PROTECTED_KEYS.iter().map(|k| (*k, Intent::Keep)).collect();
        assert!(env_conflicts(&existing, &intents).is_empty());

        // Same mediator, quoted differently: not a change.
        intents.insert("MEDIATOR_DID", Intent::Set(Some("did:example:m".into())));
        // Filling an empty value is not a replacement.
        intents.insert("ADMIN_DIDS", Intent::Set(Some("did:example:a".into())));
        assert!(env_conflicts(&existing, &intents).is_empty());

        intents.insert("PROFILE_CONFIG", Intent::Set(None));
        intents.insert(
            "MEDIATOR_DID",
            Intent::Set(Some("did:example:other".into())),
        );
        let conflicts = env_conflicts(&existing, &intents);
        assert_eq!(conflicts.len(), 2, "{conflicts:?}");

        intents.insert("PROFILE_CONFIG", Intent::Remove);
        assert!(
            env_conflicts(&existing, &intents)
                .iter()
                .any(|c| c.contains("PROFILE_CONFIG") && c.contains("secret store"))
        );
    }

    /// #191/#230: the README quick start (no mediator) over a DIDComm `.env`
    /// would switch DIDComm off under a configured identity.
    #[test]
    fn a_rest_only_rerun_over_a_didcomm_identity_is_a_conflict() {
        assert!(disables_existing_identity(&env(&[(
            "PROFILE_CONFIG",
            "'{}'"
        )])));
        assert!(!disables_existing_identity(&env(&[
            ("PROFILE_CONFIG", "'{}'"),
            ("ENABLE_DIDCOMM", "false")
        ])));
        assert!(!disables_existing_identity(&env(&[
            ("PROFILE_CONFIG", ""),
            ("MEDIATOR_DID", "")
        ])));
    }

    #[test]
    fn did_files_are_planned_per_method() {
        let new = |m: &str| Mode::NewDid {
            method: m.into(),
            save_to: None,
        };
        assert!(files_to_create(&new("peer")).is_empty());
        assert_eq!(files_to_create(&new("web")), [PathBuf::from("did.json")]);
        assert_eq!(
            files_to_create(&new("scid")),
            [
                PathBuf::from("did.json"),
                PathBuf::from("did.jsonl"),
                PathBuf::from("did-update-keys.json")
            ]
        );
    }

    /// #204: the published document is the registry's own builder's, with the
    /// profile's key ids and relationships by key type.
    #[tokio::test]
    async fn a_did_web_document_names_the_profiles_keys() {
        let web = create_web_did(
            "did:example:mediator",
            "https://tr.example.com",
            "web",
            true,
        )
        .await
        .unwrap();
        assert_eq!(web.did, "did:web:tr.example.com");
        let doc: Value = serde_json::from_str(&web.did_json).unwrap();
        let ids: Vec<String> = web.secrets.iter().map(|s| s.id.clone()).collect();
        assert_eq!(
            ids,
            [
                "did:web:tr.example.com#key-1",
                "did:web:tr.example.com#key-2"
            ]
        );
        assert_eq!(doc["authentication"], json!([ids[0]]));
        assert_eq!(doc["keyAgreement"], json!([ids[1]]));
        assert_eq!(doc["verificationMethod"][0]["type"], "Multikey");
        // The same document the runtime builder makes from the profile.
        let runtime = build_did_document_value(
            &web.did,
            &web.secrets,
            "did:example:mediator",
            std::env::var("TR_PUBLIC_URL").ok().as_deref(),
            {
                let mut f = transport_flags_from_env().unwrap();
                f.didcomm = true;
                f
            },
        )
        .unwrap();
        assert_eq!(doc, runtime);
        assert!(web.update_keys.is_none());
    }

    /// #221: a did:webvh's update and pre-rotation keys are kept, and the
    /// committed hash is the next key's.
    #[tokio::test]
    async fn a_did_webvh_keeps_its_update_and_next_keys() {
        let web = create_web_did(
            "did:example:mediator",
            "https://tr.example.com",
            "webvh",
            true,
        )
        .await
        .unwrap();
        let keys = web.update_keys.as_ref().expect("update keys kept");
        assert_eq!(keys.did, web.did);
        let log: Value = serde_json::from_str(web.did_jsonl.as_ref().unwrap()).unwrap();
        assert_eq!(
            log["parameters"]["updateKeys"][0],
            keys.update_key.get_public_keymultibase().unwrap()
        );
        assert_eq!(
            log["parameters"]["nextKeyHashes"][0],
            keys.next_update_key.get_public_keymultibase_hash().unwrap()
        );
        let saved = serde_json::to_value(keys).unwrap();
        assert!(saved["updateKey"]["privateKeyJwk"]["d"].is_string());
        assert!(saved["nextUpdateKey"]["privateKeyJwk"]["d"].is_string());
    }
}
