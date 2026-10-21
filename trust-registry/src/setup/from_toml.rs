//! Phase 2 of `trust-registry setup`: provision the registry at a running VTA.
//!
//! `trust-registry setup --from <file>` reads a [`SetupFile`], authenticates to
//! the VTA as the phase-1 setup key, and asks it to provision the registry from
//! the `trust-registry` DID template. What it writes:
//!
//! - `credential_out`: the `TR_VTA_CREDENTIAL` bundle for the VTA-minted
//!   long-term admin (0600, never overwritten).
//! - `env_out` (optional): the environment the registry needs to run as what
//!   was just provisioned.
//!
//! and, on stdout, a terse `key=value` block for an automated caller to parse.

use std::collections::BTreeMap;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use serde::Deserialize;
use serde_json::Value;
use tokio::sync::mpsc;
use vta_sdk::credentials::CredentialBundle;
use vta_sdk::provision_client::diagnostics::Protocol;
use vta_sdk::provision_client::{
    EphemeralSetupKey, ProvisionAsk, ProvisionResultV2, VtaEvent, VtaIntent, VtaReply,
    run_connection_test, run_provision_flight,
};

use super::{DEFAULT_CONTEXT, TEMPLATE_NAME, TrustRegistryMessages};
use crate::didcomm::did_document::{
    DIDCOMM_SERVICE_FRAGMENT, REST_SERVICE_FRAGMENT, TRUST_REGISTRY_SERVICE_FRAGMENT,
    TSP_SERVICE_FRAGMENT, TransportFlags, build_services, validate_public_url,
};

/// The `trust-registry` template's service slots, by the fragment of the entry
/// [`build_services`] puts in each. Every slot defaults to `null` and is pruned,
/// which is how the published document advertises only what the registry
/// serves.
const SERVICE_SLOTS: [(&str, &str); 4] = [
    (DIDCOMM_SERVICE_FRAGMENT, "SERVICE_DIDCOMM"),
    (REST_SERVICE_FRAGMENT, "SERVICE_REST"),
    (TRUST_REGISTRY_SERVICE_FRAGMENT, "SERVICE_TRUST_REGISTRY"),
    (TSP_SERVICE_FRAGMENT, "SERVICE_TSP"),
];

/// The `{DID}` sentinel the template renderer leaves in caller-supplied
/// entries; `didwebvh-rs` replaces it with the minted DID once the SCID is
/// known.
const DID_SENTINEL: &str = "{DID}";

/// `trust-registry setup --from <file>`. Relative paths resolve against the
/// working directory.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SetupFile {
    /// The VTA to provision at.
    pub vta_did: String,
    /// The VTA context the phase-1 key was granted admin in. Becomes
    /// `TR_VTA_CONTEXT_ID`.
    #[serde(default = "default_context")]
    pub context: String,
    /// The phase-1 setup key.
    pub setup_key_file: PathBuf,
    /// Where to write the `TR_VTA_CREDENTIAL` bundle. Must not exist yet.
    pub credential_out: PathBuf,
    /// Optionally, where to write the registry's environment (`KEY=value`
    /// lines). Overwritten if it exists.
    #[serde(default)]
    pub env_out: Option<PathBuf>,
    /// The transports the registry serves and its DID advertises. The same
    /// choice as `ENABLE_REST` / `ENABLE_DIDCOMM` / `ENABLE_TSP`, which the
    /// registry then has to be started with.
    pub transports: Vec<Transport>,
    /// The registry's public URL (`TR_PUBLIC_URL`). Required to advertise REST.
    #[serde(default)]
    pub public_url: Option<String>,
    /// The mediator the registry connects through (`MEDIATOR_DID`). Required
    /// for DIDComm and TSP.
    #[serde(default)]
    pub mediator_did: Option<String>,
    /// Where the VTA publishes the registry's `did:webvh`.
    pub webvh: WebvhTarget,
    /// Force how this command reaches the VTA. Default: the best the VTA
    /// advertises.
    #[serde(default)]
    pub provision_transport: Option<ProvisionTransport>,
}

fn default_context() -> String {
    DEFAULT_CONTEXT.to_string()
}

#[derive(Debug, Deserialize, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "lowercase")]
pub enum Transport {
    Rest,
    Didcomm,
    Tsp,
}

#[derive(Debug, Deserialize, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum ProvisionTransport {
    Rest,
    Didcomm,
    Tsp,
}

impl ProvisionTransport {
    fn protocol(self) -> Protocol {
        match self {
            Self::Rest => Protocol::Rest,
            Self::Didcomm => Protocol::DidComm,
            Self::Tsp => Protocol::Tsp,
        }
    }
}

/// A DID-hosting server registered at the VTA (`vta did-mgmt servers add` /
/// `pnm did-mgmt servers add`).
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WebvhTarget {
    /// The server's id at the VTA.
    pub server_id: String,
    /// The DID's path on the server. Default: the server assigns one.
    #[serde(default)]
    pub path: Option<String>,
    /// The server's hosting domain, when it serves several.
    #[serde(default)]
    pub domain: Option<String>,
}

impl SetupFile {
    fn flags(&self) -> TransportFlags {
        TransportFlags {
            rest: self.transports.contains(&Transport::Rest),
            didcomm: self.transports.contains(&Transport::Didcomm),
            tsp: self.transports.contains(&Transport::Tsp),
        }
    }

    fn public_url(&self) -> Option<&str> {
        self.public_url
            .as_deref()
            .map(str::trim)
            .filter(|u| !u.is_empty())
    }

    fn mediator_did(&self) -> Option<&str> {
        self.mediator_did
            .as_deref()
            .map(str::trim)
            .filter(|d| !d.is_empty())
    }

    /// Every problem with the file at once, before anything reaches the VTA.
    ///
    /// The rules are the ones the registry applies at startup, so a file that
    /// passes provisions a DID the registry can then serve as advertised.
    fn validate(&self) -> Result<(), String> {
        let mut errors = Vec::new();
        if !self.vta_did.starts_with("did:") {
            errors.push(format!("vta_did must be a DID (got {:?})", self.vta_did));
        }
        if self.context.trim().is_empty() {
            errors.push("context must not be empty".into());
        }
        if self.webvh.server_id.trim().is_empty() {
            errors.push(
                "webvh.server_id must name a DID-hosting server registered at the VTA".into(),
            );
        }

        let mut seen = self.transports.clone();
        seen.sort_unstable();
        seen.dedup();
        if seen.len() != self.transports.len() {
            errors.push("transports must not repeat a transport".into());
        }
        let flags = self.flags();
        if let Err(e) = flags.validate() {
            errors.push(format!("transports: {e}"));
        }
        // The registry reads its VTA identity on the DIDComm path only: with
        // ENABLE_DIDCOMM=false it never contacts the VTA, so provisioning one
        // would mint a DID and admin nothing uses.
        if !flags.didcomm {
            errors.push(
                "transports must include \"didcomm\": a registry loads its identity from the \
                 VTA only when DIDComm is enabled"
                    .into(),
            );
        }
        if flags.rest {
            match self.public_url() {
                Some(url) => {
                    if let Err(e) = validate_public_url(url) {
                        errors.push(format!("public_url: {e}"));
                    }
                }
                // The registry would serve REST but could not say where: it
                // advertises REST only at a public URL.
                None => errors.push("transports includes \"rest\", which needs public_url".into()),
            }
        }
        if flags.didcomm || flags.tsp {
            match self.mediator_did() {
                Some(did) if !did.starts_with("did:") => {
                    errors.push(format!("mediator_did must be a DID (got {did:?})"));
                }
                Some(_) => {}
                None => errors.push(
                    "transports includes \"didcomm\" or \"tsp\", which needs mediator_did".into(),
                ),
            }
        }

        if errors.is_empty() {
            Ok(())
        } else {
            Err(format!(
                "setup file has {} problem(s):\n  - {}",
                errors.len(),
                errors.join("\n  - ")
            ))
        }
    }

    /// The template vars: the registry's own service entries in their slots,
    /// plus the sideband vars that tell the VTA where to publish.
    fn template_vars(&self) -> Result<BTreeMap<String, Value>, String> {
        let mut vars = BTreeMap::new();
        let services = build_services(
            DID_SENTINEL,
            self.mediator_did().unwrap_or_default(),
            self.public_url(),
            self.flags(),
        );
        for service in services {
            let id = service["id"].as_str().unwrap_or_default();
            let slot = SERVICE_SLOTS
                .iter()
                .find(|(fragment, _)| id == format!("{DID_SENTINEL}{fragment}"))
                .map(|(_, slot)| *slot)
                .ok_or_else(|| {
                    format!("the `{TEMPLATE_NAME}` template has no slot for service {id:?}")
                })?;
            vars.insert(slot.to_string(), service);
        }
        vars.insert(
            "WEBVH_SERVER".into(),
            Value::String(self.webvh.server_id.clone()),
        );
        if let Some(path) = &self.webvh.path {
            vars.insert("WEBVH_PATH".into(), Value::String(path.clone()));
        }
        if let Some(domain) = &self.webvh.domain {
            vars.insert("WEBVH_DOMAIN".into(), Value::String(domain.clone()));
        }
        Ok(vars)
    }

    /// The environment the registry needs to run as what was provisioned.
    fn env_lines(&self, credential_path: &Path) -> Vec<String> {
        let flags = self.flags();
        let mut lines = vec![
            format!("TR_VTA_CREDENTIAL=file://{}", credential_path.display()),
            format!("TR_VTA_CONTEXT_ID={}", self.context),
            format!("ENABLE_REST={}", flags.rest),
            format!("ENABLE_DIDCOMM={}", flags.didcomm),
            format!("ENABLE_TSP={}", flags.tsp),
        ];
        if let Some(did) = self.mediator_did() {
            lines.push(format!("MEDIATOR_DID={did}"));
        }
        if let Some(url) = self.public_url() {
            lines.push(format!("TR_PUBLIC_URL={url}"));
        }
        lines
    }
}

/// Parse and validate `path`.
pub(crate) fn parse_setup_file(path: &Path) -> Result<SetupFile, String> {
    let raw = std::fs::read_to_string(path)
        .map_err(|e| format!("could not read {}: {e}", path.display()))?;
    let file: SetupFile = toml::from_str(&raw)
        .map_err(|e| format!("{} is not a valid setup file: {e}", path.display()))?;
    file.validate()?;
    Ok(file)
}

/// `trust-registry setup --from <file>`.
pub async fn run_setup_from_file(path: &Path) -> Result<(), String> {
    eprintln!(
        "Running non-interactive Trust Registry setup from {} ...",
        path.display()
    );
    let file = parse_setup_file(path)?;

    // Refuse before reaching the VTA: provisioning twice mints a second DID
    // and a second admin, and overwriting the file would orphan the first.
    if file.credential_out.exists() {
        return Err(format!(
            "{} already exists: this registry looks provisioned already. Remove it to \
             provision again (that mints a new DID and admin at the VTA)",
            file.credential_out.display()
        ));
    }
    let setup_key = EphemeralSetupKey::load_from(&file.setup_key_file).map_err(|e| {
        format!(
            "could not load the setup key {} (run `trust-registry setup --setup-key-out` \
             first): {e}",
            file.setup_key_file.display()
        )
    })?;

    let ask =
        ProvisionAsk::for_template(TEMPLATE_NAME, file.template_vars()?, file.context.clone())
            .with_label("trust-registry integration");
    let reply = drive_provision(
        file.vta_did.clone(),
        &setup_key,
        ask,
        file.provision_transport.map(ProvisionTransport::protocol),
    )
    .await?;
    let provision = match reply {
        VtaReply::Full(result) => *result,
        VtaReply::AdminOnly(_) => {
            return Err(format!(
                "the VTA returned an admin-only reply, but the `{TEMPLATE_NAME}` template \
                 needs it to mint the registry's DID"
            ));
        }
    };

    let outcome = Outcome::from_provision(&provision)?;
    write_private_file(
        &file.credential_out,
        &serde_json::to_string_pretty(&outcome.credential)
            .map_err(|e| format!("could not serialise the credential: {e}"))?,
    )?;
    let credential_path =
        std::path::absolute(&file.credential_out).unwrap_or_else(|_| file.credential_out.clone());
    let env = file.env_lines(&credential_path);
    if let Some(env_out) = &file.env_out {
        std::fs::write(env_out, format!("{}\n", env.join("\n")))
            .map_err(|e| format!("could not write {}: {e}", env_out.display()))?;
    }

    println!("Trust Registry setup complete.");
    println!("registry_did={}", outcome.registry_did);
    println!("admin_did={}", outcome.credential.did);
    println!("vta_did={}", outcome.credential.vta_did);
    println!("context_id={}", file.context);
    println!("credential_path={}", credential_path.display());
    if let Some(env_out) = &file.env_out {
        println!("env_path={}", env_out.display());
    }
    eprintln!();
    eprintln!("Run the registry (built with `--features vta`) with:");
    for line in &env {
        eprintln!("  {line}");
    }
    Ok(())
}

/// What phase 2 takes from the provisioning reply.
struct Outcome {
    registry_did: String,
    credential: CredentialBundle,
}

impl Outcome {
    fn from_provision(provision: &ProvisionResultV2) -> Result<Self, String> {
        let registry_did = provision
            .integration_did()
            .ok_or("the VTA's reply names no registry DID")?
            .to_string();
        // The setup key's grant expires (`--admin-expires`), so a credential
        // for it would stop working within the hour. Only a rotated admin is
        // a credential the registry can keep.
        if !provision.summary.admin_rolled_over {
            return Err(
                "the VTA did not roll the setup key over to a long-term admin. Grant the setup \
                 key with --admin-handoff (`vta contexts create … --admin-expires 1h \
                 --admin-handoff`) and run phase 1 and 2 again"
                    .into(),
            );
        }
        let admin_did = provision.admin_did();
        let admin_key = provision
            .admin_key()
            .ok_or("the VTA's reply carries no key for the rotated admin")?;
        let config = &provision.payload.config;
        let (credential, derived_did) = CredentialBundle::from_ed25519_seed_multibase(
            &admin_key.signing_key.private_key_multibase,
            &config.vta_trust.vta_did,
            config.vta_url.as_deref(),
        )
        .map_err(|e| format!("the rotated admin key is not an Ed25519 key: {e}"))?;
        // A key that is not the named admin's would authenticate as someone
        // the VTA never granted.
        if derived_did != admin_did {
            return Err(format!(
                "the VTA named {admin_did} as the admin but returned the key for {derived_did}"
            ));
        }
        Ok(Self {
            registry_did,
            credential,
        })
    }
}

/// Create `path` with `contents`, readable by its owner only, refusing to
/// replace an existing file.
fn write_private_file(path: &Path, contents: &str) -> Result<(), String> {
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut f = options
        .open(path)
        .map_err(|e| format!("could not create {}: {e}", path.display()))?;
    f.write_all(contents.as_bytes())
        .map_err(|e| format!("could not write {}: {e}", path.display()))
}

/// Drive the provisioning to its reply, publishing to the server the ask names.
///
/// `vta_sdk::provision_client::run_provision` picks the hosting server itself
/// on the DIDComm path, and refuses a VTA with two or more. This is its loop
/// with `None`/`None` handed to the flight instead, so the `WEBVH_SERVER` /
/// `WEBVH_PATH` / `WEBVH_DOMAIN` vars already in `ask` decide on every
/// transport. `vtc setup` drives it the same way for the same reason.
async fn drive_provision(
    vta_did: String,
    setup_key: &EphemeralSetupKey,
    ask: ProvisionAsk,
    force_transport: Option<Protocol>,
) -> Result<VtaReply, String> {
    let (tx, mut rx) = mpsc::unbounded_channel();
    tokio::spawn(run_connection_test(
        VtaIntent::FullSetup,
        vta_did.clone(),
        setup_key.did.clone(),
        setup_key.private_key_multibase().to_string(),
        ask.clone(),
        force_transport,
        tx,
    ));

    while let Some(event) = rx.recv().await {
        match event {
            // The REST path finishes in one round trip.
            VtaEvent::Connected { reply, .. } => return Ok(reply),
            VtaEvent::Failed(msg) => return Err(provision_failed(&msg)),
            VtaEvent::PreflightDone {
                rest_url,
                mediator_did,
                ..
            } => {
                let (ftx, mut frx) = mpsc::unbounded_channel();
                tokio::spawn(run_provision_flight(
                    vta_did.clone(),
                    setup_key.did.clone(),
                    setup_key.private_key_multibase().to_string(),
                    mediator_did,
                    rest_url,
                    ask.clone(),
                    None,
                    None,
                    Arc::new(TrustRegistryMessages),
                    ftx,
                ));
                while let Some(event) = frx.recv().await {
                    match event {
                        VtaEvent::Connected { reply, .. } => return Ok(reply),
                        VtaEvent::Failed(msg) => return Err(provision_failed(&msg)),
                        _ => {}
                    }
                }
                break;
            }
            _ => {}
        }
    }
    Err(provision_failed("provisioning ended without an answer"))
}

/// A terminal failure with the likeliest fix.
///
/// The usual cause is the grant: missing, expired, for another context, or
/// without `--admin-handoff`. A transport failure is a different layer, and
/// pointing at the grant then sends the operator to check the wrong thing, so
/// the unambiguous transport messages get their own hint.
fn provision_failed(msg: &str) -> String {
    const TRANSPORT_MARKERS: &[&str] = &[
        "timed out",
        "bad gateway",
        "transport error",
        "failed to send message",
    ];
    let lower = msg.to_ascii_lowercase();
    let hint = if TRANSPORT_MARKERS.iter().any(|m| lower.contains(m)) {
        "The VTA could not complete the request with one of its peers (its DID-hosting server \
         or mediator). Check the VTA's logs, and that both are reachable."
    } else {
        "Check that the setup key's DID holds an unexpired admin grant in this context at the \
         VTA, made with --admin-handoff, that the context does not already have a DID, and \
         that webvh.server_id is registered at the VTA."
    };
    format!("provisioning at the VTA failed: {msg}\n\n{hint}")
}

#[cfg(test)]
mod tests {
    use super::*;

    const MEDIATOR: &str = "did:webvh:QmMed:dids.example.com:mediator";

    fn file(extra: &str) -> SetupFile {
        toml::from_str(&format!(
            r#"
            vta_did = "did:webvh:QmVta:dids.example.com:vta"
            setup_key_file = "setup-key.json"
            credential_out = "vta-credential.json"
            mediator_did = "{MEDIATOR}"
            public_url = "https://tr.example.com"
            {extra}
            [webvh]
            server_id = "did-hosting-daemon"
            path = "trust-registry"
            "#
        ))
        .unwrap()
    }

    #[test]
    fn a_full_file_parses_with_defaults() {
        let f = file(r#"transports = ["rest", "didcomm"]"#);
        f.validate().unwrap();
        assert_eq!(f.context, DEFAULT_CONTEXT);
        assert!(f.env_out.is_none());
        assert!(f.provision_transport.is_none());
    }

    #[test]
    fn unknown_fields_are_refused() {
        let raw = r#"
            vta_did = "did:example:vta"
            setup_key_file = "k"
            credential_out = "c"
            transports = ["didcomm"]
            mediator_did = "did:example:m"
            pre_rotation = 3
            [webvh]
            server_id = "s"
        "#;
        assert!(toml::from_str::<SetupFile>(raw).is_err());
    }

    /// Each rule the registry enforces at startup is enforced here, so setup
    /// never publishes a DID advertising a transport the registry then
    /// refuses to serve, or cannot be reached on.
    #[test]
    fn validation_matches_what_the_registry_will_serve() {
        let cases = [
            (r#"transports = []"#, "at least one transport"),
            (r#"transports = ["rest", "rest"]"#, "must not repeat"),
            (
                r#"transports = ["tsp"]"#,
                "ENABLE_TSP=true requires ENABLE_DIDCOMM=true",
            ),
        ];
        for (transports, expected) in cases {
            let err = file(transports).validate().unwrap_err();
            assert!(err.contains(expected), "{transports}: {err}");
        }

        let err = file(r#"transports = ["rest"]"#).validate().unwrap_err();
        assert!(err.contains("must include \"didcomm\""), "{err}");

        let mut f = file(r#"transports = ["rest", "didcomm"]"#);
        f.public_url = None;
        assert!(f.validate().unwrap_err().contains("needs public_url"));
        f.public_url = Some("http://tr.example.com".into());
        assert!(f.validate().unwrap_err().contains("must be https://"));

        let mut f = file(r#"transports = ["didcomm"]"#);
        f.mediator_did = Some("  ".into());
        assert!(f.validate().unwrap_err().contains("needs mediator_did"));
        f.mediator_did = Some("https://mediator.example.com".into());
        assert!(f.validate().unwrap_err().contains("must be a DID"));
    }

    #[test]
    fn every_problem_is_reported_at_once() {
        let mut f = file(r#"transports = ["rest", "didcomm"]"#);
        f.vta_did = "vta.example.com".into();
        f.public_url = None;
        f.mediator_did = None;
        let err = f.validate().unwrap_err();
        assert!(err.contains("3 problem(s)"), "{err}");
    }

    /// The published document must be the one the registry's runtime builder
    /// would produce for the same flags, so every entry it emits has a slot,
    /// and each lands in the slot named for it.
    #[test]
    fn every_service_lands_in_its_slot() {
        let f = file(r#"transports = ["rest", "didcomm"]"#);
        let vars = f.template_vars().unwrap();
        assert_eq!(vars["SERVICE_DIDCOMM"]["id"], "{DID}#didcomm");
        assert_eq!(vars["SERVICE_DIDCOMM"]["serviceEndpoint"]["uri"], MEDIATOR);
        assert_eq!(
            vars["SERVICE_REST"]["serviceEndpoint"],
            "https://tr.example.com"
        );
        assert_eq!(
            vars["SERVICE_TRUST_REGISTRY"]["serviceEndpoint"]["uri"],
            "https://tr.example.com"
        );
        assert!(!vars.contains_key("SERVICE_TSP"), "TSP was not chosen");
        assert_eq!(vars["WEBVH_SERVER"], "did-hosting-daemon");
        assert_eq!(vars["WEBVH_PATH"], "trust-registry");
        assert!(!vars.contains_key("WEBVH_DOMAIN"));

        let all = build_services(
            DID_SENTINEL,
            MEDIATOR,
            Some("https://tr.example.com"),
            TransportFlags {
                rest: true,
                didcomm: true,
                tsp: true,
            },
        );
        for service in all {
            let id = service["id"].as_str().unwrap();
            assert!(
                SERVICE_SLOTS
                    .iter()
                    .any(|(fragment, _)| id == format!("{DID_SENTINEL}{fragment}")),
                "{id} has no template slot"
            );
        }
    }

    #[test]
    fn env_lines_start_the_registry_as_provisioned() {
        let f = file(r#"transports = ["didcomm"]"#);
        let lines = f.env_lines(Path::new("/work/tr/vta-credential.json"));
        assert_eq!(
            lines,
            [
                "TR_VTA_CREDENTIAL=file:///work/tr/vta-credential.json",
                "TR_VTA_CONTEXT_ID=trust-registry",
                "ENABLE_REST=false",
                "ENABLE_DIDCOMM=true",
                "ENABLE_TSP=false",
                &format!("MEDIATOR_DID={MEDIATOR}"),
                "TR_PUBLIC_URL=https://tr.example.com",
            ]
        );
    }

    #[test]
    fn the_credential_file_is_private_and_never_replaced() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vta-credential.json");
        write_private_file(&path, "{}").unwrap();
        assert!(write_private_file(&path, "{}").is_err());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600);
        }
    }

    /// A reply whose rotated admin is a real Ed25519 key, as the VTA's is.
    fn provision_with_admin(admin: &EphemeralSetupKey) -> ProvisionResultV2 {
        let mut provision =
            vta_sdk::provision_client::test_helpers::sample_provision_result_v2(true, false);
        let sample_admin = provision.summary.admin_did.clone();
        let mut material = provision.payload.secrets.remove(&sample_admin).unwrap();
        material.did = admin.did.clone();
        material.signing_key.private_key_multibase = admin.private_key_multibase().to_string();
        provision
            .payload
            .secrets
            .insert(admin.did.clone(), material);
        provision.summary.admin_did = admin.did.clone();
        provision
    }

    #[test]
    fn the_credential_is_the_rotated_admin() {
        let admin = EphemeralSetupKey::generate().unwrap();
        let outcome = Outcome::from_provision(&provision_with_admin(&admin)).unwrap();

        assert_eq!(outcome.registry_did, "did:webvh:integration.example.com");
        assert_eq!(outcome.credential.did, admin.did);
        assert_eq!(
            outcome.credential.private_key_multibase,
            admin.private_key_multibase()
        );
        assert_eq!(outcome.credential.vta_did, "did:webvh:vta.example.com");
        assert_eq!(
            outcome.credential.vta_url.as_deref(),
            Some("https://vta.example.com")
        );
    }

    /// The setup key's grant expires within the hour, so keeping it as the
    /// registry's credential would break the registry an hour after setup.
    #[test]
    fn a_reply_that_kept_the_setup_key_is_refused() {
        let provision =
            vta_sdk::provision_client::test_helpers::sample_provision_result_v2(false, false);
        let err = Outcome::from_provision(&provision).err().unwrap();
        assert!(err.contains("--admin-handoff"), "{err}");
    }

    #[test]
    fn a_key_that_is_not_the_named_admins_is_refused() {
        let admin = EphemeralSetupKey::generate().unwrap();
        let mut provision = provision_with_admin(&admin);
        let other = EphemeralSetupKey::generate().unwrap();
        provision
            .payload
            .secrets
            .get_mut(&admin.did)
            .unwrap()
            .signing_key
            .private_key_multibase = other.private_key_multibase().to_string();
        let err = Outcome::from_provision(&provision).err().unwrap();
        assert!(err.contains(&other.did), "{err}");
    }

    #[test]
    fn the_shipped_example_parses_and_validates() {
        let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("examples/vta-setup.example.toml");
        parse_setup_file(&path).unwrap();
    }
}
