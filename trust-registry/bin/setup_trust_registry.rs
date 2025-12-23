#![cfg(feature = "dev-tools")]
use affinidi_did_key::DIDKey;
use affinidi_tdk::{
    TDK,
    common::{config::TDKConfig, profiles::TDKProfile},
    did_common::{
        Document,
        one_or_many::OneOrMany,
        service::{Endpoint, Service},
        verification_method::{VerificationMethod, VerificationRelationship},
    },
    messaging::{
        profiles::ATMProfile,
        protocols::{
            Protocols,
            mediator::acls::{AccessListModeType, MediatorACLSet},
        },
    },
    secrets_resolver::secrets::{KeyType, Secret, SecretMaterial},
};

use clap::Parser;
use did_peer::{
    DIDPeer, DIDPeerCreateKeys, DIDPeerKeyType, DIDPeerKeys, DIDPeerService, PeerServiceEndPoint,
    PeerServiceEndPointLong, PeerServiceEndPointLongMap,
};
use didwebvh_rs::{DIDWebVHState, parameters::Parameters, url::WebVHURL};
use serde_json::Value;
use serde_json::json;
use sha256::digest;
use url::Url;
// use base64;
use crossterm::{
    event::{self, Event},
    terminal,
};
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    error::Error,
    fs::{self, File, OpenOptions},
    io::{BufRead, BufReader, Write},
    path::Path,
    println,
    sync::Arc,
};

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ProfileConfig {
    alias: String,
    did: String,
    secrets: Vec<Secret>,
}

#[derive(Parser, Debug)]
#[command(version, about = "Affinidi Trust Registry Setup Tool", long_about = None)]
struct Args {
    /// Mediator URL to connect the Trust Registry (e.g., https://mediator.goodcompany.com)
    #[arg(long, short = 'u')]
    mediator_url: Option<String>,

    /// Mediator DID to connect the Trust Registry (e.g., did:example:123456789abcdefghi)
    #[arg(long, short = 'd')]
    mediator_did: Option<String>,

    /// DID method to use for Trust Registry (peer, web, or webvh). Generate new DID when specified.
    #[arg(long, short = 'm', value_parser = ["peer", "web", "webvh"], default_value = "peer")]
    did_method: Option<String>,

    /// URL to host the DID document (required only for did:web and did:webvh)
    #[arg(long, short = 'w', required_if_eq_any([("did_method", "web"), ("did_method", "webvh")]))]
    didweb_url: Option<String>,

    /// Profile configuration location using URI schemes:
    ///
    /// - Direct value (default when not specified): '<JSON_STRING>'
    ///
    /// - String protocol: 'string://<JSON_STRING>'
    ///
    /// - File system: 'file:///path/to/config.json'
    ///
    /// - AWS Secrets Manager: 'aws_secrets://<SECRET_NAME>'
    ///
    /// - AWS Parameter Store: 'aws_parameter_store://<PARAMETER_NAME>'
    ///
    /// When --did-method is used, this specifies where to save the generated profile.
    ///
    /// When --did-method is not used, this specifies where to load an existing profile.
    #[arg(long, short = 'p')]
    profile: Option<String>,

    /// Storage backend for trust records (csv or ddb)
    #[arg(long, short = 's', value_parser = ["csv", "ddb"], default_value = "csv")]
    storage_backend: String,

    /// Path to CSV file (required when storage_backend is csv)
    #[arg(
        long,
        short = 'f',
        required_if_eq("storage_backend", "csv"),
        default_value = "./sample-data/data.csv"
    )]
    file_storage_path: Option<String>,

    /// DynamoDB table name (required when storage_backend is ddb)
    #[arg(
        long,
        short = 't',
        required_if_eq("storage_backend", "ddb"),
        default_value = "test"
    )]
    ddb_table_name: Option<String>,

    /// Admin DIDs that can manage Trust Registry records (comma-separated)
    #[arg(long, short = 'a')]
    admin_dids: Option<String>,

    /// Trust Registry DID (optional, used to set existing DID)
    #[arg(long, short = 'r')]
    tr_did: Option<String>,

    /// Trust Registry DID secret (optional, used to set existing DID)
    #[arg(long, short = 'e')]
    tr_did_secret: Option<String>,

    /// Trust Registry test configuration
    #[arg(long, short = 'l', default_value = "false")]
    test_in_pipeline: Option<bool>,

    /// Trust Registry audit log output format
    #[arg(long, short = 'o', default_value = "json")]
    audit_log_format: Option<String>,

    /// Trust Registry only admin operations. use didcomm
    #[arg(long, short = 'x', default_value = "false")]
    only_admin_operations: Option<bool>,
}

fn insert_env_vars(
    file_path: &str,
    new_vars: HashMap<String, String>,
    example_file_path: Option<&str>,
) -> std::io::Result<()> {
    let path = Path::new(file_path);
    let mut existing_vars = HashMap::new();

    if !path.exists()
        && let Some(example_path) = example_file_path
    {
        let example = Path::new(example_path);
        if example.exists() {
            fs::copy(example, path)?;
        }
    }

    if path.exists() {
        let file = fs::File::open(path)?;
        let reader = BufReader::new(file);
        for line in reader.lines() {
            let line = line?;
            if let Some((key, value)) = line.split_once('=') {
                existing_vars.insert(key.trim().to_string(), value.trim().to_string());
            }
        }
    }

    for (key, value) in new_vars {
        existing_vars.insert(key, value);
    }

    let mut file = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(path)?;

    for (key, value) in existing_vars {
        writeln!(file, "{}={}", key, value)?;
    }

    Ok(())
}

pub async fn set_acl(alias: &str, did: &str, mediator_did: &str, secrets: Vec<Secret>) {
    let profile = TDKProfile::new(alias, did, Some(mediator_did), secrets);

    let tdk = TDK::new(
        TDKConfig::builder()
            .with_load_environment(false)
            .build()
            .unwrap(),
        None,
    )
    .await
    .unwrap();
    tdk.add_profile(&profile).await;
    let atm = Arc::new(tdk.atm.clone().unwrap());

    let atm_profile = match ATMProfile::from_tdk_profile(&atm, &profile).await {
        Ok(p) => p,
        Err(e) => {
            println!("Error creating ATM profile: {:#?}", e);
            println!(
                "This might indicate an issue with DID resolution or service endpoint configuration"
            );
            return;
        }
    };

    let profile = match atm.profile_add(&atm_profile, true).await {
        Ok(p) => p,
        Err(e) => {
            println!("Error connecting to mediator (websocket timeout): {:#?}", e);
            println!("Possible causes:");
            println!("  - Mediator is not running or unreachable");
            println!("  - DID document service endpoints are incorrect");
            println!("  - Network connectivity issues");
            println!("  - Authentication/key mismatch");
            return;
        }
    };
    let protocols = Protocols::new();
    let account_get_result = protocols.mediator.account_get(&atm, &profile, None).await;

    if account_get_result.is_err() {
        println!(
            "Error in getting account info: {:#?}",
            account_get_result.err()
        );
        println!("Current mediator does not support account_get");
        return;
    }

    let account_info = account_get_result.unwrap();

    if let Some(info) = account_info {
        let mut acls = MediatorACLSet::from_u64(info.acls);
        if acls.get_access_list_mode().0 == AccessListModeType::ExplicitAllow {
            acls.set_access_list_mode(AccessListModeType::ExplicitDeny, true, false)
                .unwrap();

            protocols
                .mediator
                .acls_set(&atm, &profile, &digest(&profile.inner.did), &acls)
                .await
                .unwrap();
        }
    }
}

fn create_keys() -> (Secret, Secret) {
    let mut verification_key =
        Secret::generate_p256(None, None).expect("Failed to generate P256 key");
    let mut encryption_key =
        Secret::generate_secp256k1(None, None).expect("Failed to generate Secp256k1 key");

    verification_key.id = verification_key.get_public_keymultibase().unwrap();
    encryption_key.id = encryption_key.get_public_keymultibase().unwrap();

    (verification_key, encryption_key)
}

pub fn create_did(service: Option<Vec<String>>, auth_service: bool) -> (String, Vec<Secret>) {
    let (e_did_key, mut e_secp256k1_key) = DIDKey::generate(KeyType::Secp256k1).unwrap();
    let (v_did_key, mut v_p256) = DIDKey::generate(KeyType::P256).unwrap();

    let keys = vec![
        DIDPeerCreateKeys {
            purpose: DIDPeerKeys::Verification,
            type_: Some(DIDPeerKeyType::P256),
            public_key_multibase: Some(v_did_key[8..].to_string()),
        },
        DIDPeerCreateKeys {
            purpose: DIDPeerKeys::Encryption,
            type_: Some(DIDPeerKeyType::Secp256k1),
            public_key_multibase: Some(e_did_key[8..].to_string()),
        },
    ];

    let mut services = service.as_ref().map(|service| {
        let endpoints = service.iter().map(|uri| PeerServiceEndPointLongMap {
            uri: uri.to_string(),
            accept: vec!["didcomm/v2".into()],
            routing_keys: vec![],
        });
        vec![DIDPeerService {
            id: None,
            _type: "dm".into(),
            service_end_point: PeerServiceEndPoint::Long(PeerServiceEndPointLong::Map(
                OneOrMany::Many(endpoints.collect()),
            )),
        }]
    });

    if auth_service {
        let service = service.as_ref().unwrap();

        let auth_service = DIDPeerService {
            id: Some("#auth".into()),
            _type: "Authentication".into(),
            service_end_point: PeerServiceEndPoint::Long(PeerServiceEndPointLong::URI(
                [&service[0], "/authenticate"].concat(),
            )),
        };
        services.as_mut().unwrap().push(auth_service);
    }
    let services = services.as_ref();

    let (did_peer, _) =
        DIDPeer::create_peer_did(&keys, services).expect("Failed to create did:peer");
    v_p256.id = [did_peer.as_str(), "#key-1"].concat();
    e_secp256k1_key.id = [did_peer.as_str(), "#key-2"].concat();

    let secrets_json = vec![v_p256, e_secp256k1_key];
    (did_peer, secrets_json)
}

pub fn setup_did_peer_tr(mediator_url: String) -> (String, Vec<Secret>) {
    println!("Setting up did:peer for Trust Registry...");
    let tr_did = create_did(Some(vec![mediator_url.clone()]), true);

    println!("✓ Trust Registry DID created: {}", tr_did.0);

    (tr_did.0, tr_did.1)
}

pub fn setup_did_web_tr(
    mediator_url: String,
    web_url: String,
    did_method: String,
) -> Result<(String, Vec<Secret>), Box<dyn Error>> {
    println!("Setting up did:{} for Trust Registry...", did_method);

    let parsed_url = Url::parse(&web_url)?;
    let did_url_raw = WebVHURL::parse_url(&parsed_url)?;
    // remove webvh part for did:web
    let mut tr_did = if did_method == "web" {
        did_url_raw.to_string().replace("webvh:{SCID}", "web")
    } else {
        did_url_raw.to_string()
    };

    // Create keys
    let (verification_key, encryption_key) = create_keys();

    // Create the basic DID Document Structure
    let mut did_document = Document::new(&tr_did.to_string())?;

    // Add the verification methods to the DID Document
    let mut property_set: HashMap<String, Value> = HashMap::new();

    // Signing and Authentication Key
    property_set.insert(
        "publicKeyMultibase".to_string(),
        Value::String(verification_key.id.clone()),
    );
    let v_key_id = Url::parse(&[tr_did.to_string(), "#key-1".to_string()].concat())?;
    did_document.verification_method.push(VerificationMethod {
        id: v_key_id.clone(),
        type_: "Multikey".to_string(),
        controller: Url::parse(&tr_did.to_string())?,
        revoked: None,
        expires: None,
        property_set: property_set.clone(),
    });
    did_document
        .assertion_method
        .push(VerificationRelationship::Reference(v_key_id.clone()));

    did_document
        .authentication
        .push(VerificationRelationship::Reference(v_key_id.clone()));

    // Encryption Key
    property_set.insert(
        "publicKeyMultibase".to_string(),
        Value::String(encryption_key.id.clone()),
    );
    let e_key_id = Url::parse(&[tr_did.to_string(), "#key-2".to_string()].concat())?;
    did_document.verification_method.push(VerificationMethod {
        id: e_key_id.clone(),
        type_: "Multikey".to_string(),
        controller: Url::parse(&tr_did.to_string())?,
        revoked: None,
        expires: None,
        property_set: property_set.clone(),
    });
    did_document
        .key_agreement
        .push(VerificationRelationship::Reference(e_key_id.clone()));

    // Add service endpoints to the DID Document
    let endpoint = Endpoint::Map(json!([{"accept": ["didcomm/v2"], "uri": mediator_url}]));
    did_document.service.push(Service {
        id: Some(Url::parse(
            &[tr_did.to_string(), "#service".to_string()].concat(),
        )?),
        type_: vec!["DIDCommMessaging".to_string()],
        property_set: HashMap::new(),
        service_endpoint: endpoint,
    });

    let mediator_auth_url = [mediator_url, "/authenticate".to_string()].concat();
    let auth_endpoint =
        Endpoint::Map(json!([{"accept": ["didcomm/v2"], "uri": mediator_auth_url}]));
    did_document.service.push(Service {
        id: Some(Url::parse(
            &[tr_did.to_string(), "#auth".to_string()].concat(),
        )?),
        type_: vec!["Authentication".to_string()],
        property_set: HashMap::new(),
        service_endpoint: auth_endpoint,
    });

    if did_method == "webvh" {
        // Create the WebVH Parameters
        let mut update_secret = Secret::generate_ed25519(None, None);
        update_secret.id = [
            "did:key:",
            &update_secret.get_public_keymultibase()?,
            "#",
            &update_secret.get_public_keymultibase()?,
        ]
        .concat();

        let next_update_secret = Secret::generate_ed25519(None, None);

        let parameters = Parameters::new()
            .with_key_pre_rotation(true)
            .with_update_keys(vec![update_secret.get_public_keymultibase()?])
            .with_next_key_hashes(vec![next_update_secret.get_public_keymultibase_hash()?])
            .with_portable(true)
            .build();

        // Create the WebVH DID
        let mut didwebvh = DIDWebVHState::default();
        let log_entry = didwebvh.create_log_entry(
            None,
            &serde_json::to_value(&did_document)?,
            &parameters,
            &update_secret,
        )?;
        // Get the final DID after log entry creation
        tr_did = log_entry.get_state().get("id").unwrap().to_string();
        tr_did = tr_did.replace("\"", "");
        // Save the log entry to a file
        log_entry.log_entry.save_to_file("did.jsonl")?;
        // Update the DID Document to the latest from the log entry
        did_document = serde_json::from_value(log_entry.get_did_document()?)?;
    }

    // Build JWKS secrets
    let mut secrets: Vec<Secret> = Vec::new();
    let jwk_v_id = [tr_did.to_string(), "#key-1".to_string()].concat();
    let jwk_e_id = [tr_did.to_string(), "#key-2".to_string()].concat();

    if let SecretMaterial::JWK(jwk) = &verification_key.secret_material {
        let secret: Secret = serde_json::from_value(json!({
            "id": jwk_v_id,
            "type": "JsonWebKey2020",
            "privateKeyJwk": jwk
        }))
        .expect("Failed to deserialize verification key");
        secrets.push(secret);
    }

    if let SecretMaterial::JWK(jwk) = &encryption_key.secret_material {
        let secret: Secret = serde_json::from_value(json!({
            "id": jwk_e_id,
            "type": "JsonWebKey2020",
            "privateKeyJwk": jwk
        }))
        .expect("Failed to deserialize encryption key");
        secrets.push(secret);
    }

    println!("✓ Trust Registry DID created: {}", tr_did);
    println!();
    println!(
        "Saving DID document with did:{} method in the current directory...",
        did_method
    );
    // Write DID configs to a file
    File::create("did.json")?.write_all(serde_json::to_string_pretty(&did_document)?.as_bytes())?;
    println!(
        "✓ DID document saved to did.json and did.jsonl (for did:webvh) files in the current directory."
    );
    println!();
    println!("IMPORTANT: Before you continue...");
    println!(
        "For did:{} method, ensure the DID document is hosted correctly.",
        did_method
    );
    println!(
        "The DID document must be publicly accessible at the specified URL: {}",
        web_url
    );
    println!();

    println!("Press any key to continue after hosting the DID document...");
    println!();
    terminal::enable_raw_mode()?;
    loop {
        // Read the next event
        match event::read()? {
            // If it's a key event and a key press
            Event::Key(key_event) if key_event.kind == event::KeyEventKind::Press => {
                break;
            }
            _ => {} // Ignore other events (mouse, resize, etc.)
        }
    }
    // Disable raw mode when done
    terminal::disable_raw_mode()?;

    Ok((tr_did, secrets))
}

pub async fn setup_test_trust_registry(
    mediator_url: String,
    mediator_did: String,
    in_pipeline: bool,
) -> std::io::Result<()> {
    println!("Generating test DIDs for Trust Registry...");

    let mut dids_and_secrets: Vec<(String, Vec<Secret>)> = vec![];
    let test_tr_did = create_did(Some(vec![mediator_url.to_string()]), true);
    dids_and_secrets.push(test_tr_did.clone());
    let test_tr_profile_configs = json!({
        "did": test_tr_did.0,
        "alias": "Test Trust Registry",
        "secrets": test_tr_did.1
    });

    let test_client_did = create_did(Some(vec![mediator_url.to_string()]), true);
    dids_and_secrets.push(test_client_did.clone());

    let client_secrets = serde_json::to_string(&serde_json::to_string(&test_client_did.1)?)?;
    let test_profile_configs_stringified = serde_json::to_string(&test_tr_profile_configs)?;

    if in_pipeline {
        let mut vars = HashMap::new();
        vars.insert("TRUST_REGISTRY_DID".to_string(), test_tr_did.0);
        vars.insert("CLIENT_DID".to_string(), test_client_did.0.clone());
        vars.insert("ADMIN_DIDS".to_string(), test_client_did.0.clone());
        vars.insert("CLIENT_SECRETS".to_string(), client_secrets);
        vars.insert(
            "PROFILE_CONFIG".to_string(),
            format!("'{}'", test_profile_configs_stringified),
        );
        insert_env_vars("./.env.pipeline", vars, None)?;
        println!("✓ Configured .env.pipeline file for testing.");
    } else {
        let mut test_vars = HashMap::new();
        test_vars.insert("TRUST_REGISTRY_DID".to_string(), test_tr_did.0);
        test_vars.insert("CLIENT_DID".to_string(), test_client_did.0.clone());
        test_vars.insert("ADMIN_DIDS".to_string(), test_client_did.0.clone());
        test_vars.insert("CLIENT_SECRETS".to_string(), client_secrets);
        test_vars.insert("MEDIATOR_DID".to_string(), mediator_did.clone());
        test_vars.insert(
            "PROFILE_CONFIG".to_string(),
            format!("'{}'", test_profile_configs_stringified),
        );
        insert_env_vars(
            "./.env.test",
            test_vars,
            Some("./testing/.env.test.example"),
        )?;
        println!("✓ Configured .env.test file for testing.");
    }

    println!("Configuring mediator ACLs for test DIDs...");
    for ds in dids_and_secrets {
        set_acl(&ds.0, &ds.0, &mediator_did, ds.1.clone()).await;
    }
    println!("✓ Configured test DIDs ACLs on mediator.");

    Ok(())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let args = Args::parse();
    let mut server_vars = HashMap::new();

    println!();
    println!("🚀 Setting up Affinidi Trust Registry");
    println!();

    // DIDComm mediator configuration
    let mediator_url = args.mediator_url.unwrap_or("".to_string());
    let mediator_did = args.mediator_did.unwrap_or("".to_string());
    let admin_dids = args.admin_dids.unwrap_or("".to_string());
    let only_admin_operations = args.only_admin_operations.unwrap_or(false);

    // Request to generate new Trust Registry DID
    let did_method = args.did_method.unwrap_or("".to_string());

    // Existing DID profile
    let existing_tr_did = args.tr_did.unwrap_or("".to_string());
    let existing_tr_did_secret = args.tr_did_secret.unwrap_or("".to_string());

    // Testing in pipeline
    let test_in_pipeline = args.test_in_pipeline.unwrap_or(false);

    // Trust Registry DID profile
    let mut profile = args.profile.unwrap_or("".to_string());

    // Skips DIDComm related tasks if no mediator details are provided
    let enable_didcomm = !mediator_url.is_empty() && !mediator_did.is_empty();

    // If the user has provided mediator details, proceed with DID setup
    if enable_didcomm {
        // Initialise profile configuration
        let mut profile_config: Option<ProfileConfig> = None;

        // Validate mediator URL
        let parsed_mediator_url = Url::parse(&mediator_url.clone())
            .map_err(|e| format!("Invalid mediator URL '{}': {}", mediator_url.clone(), e))?;

        println!("Trust Registry DIDComm Configuration");
        println!("Mediator URL: {}", parsed_mediator_url);
        println!("Mediator DID: {}", mediator_did);
        println!();

        // Handle 3 modes: existing DID, generate DID or use existing profile location
        if !existing_tr_did.is_empty() && !existing_tr_did_secret.is_empty() {
            // Mode 1: Use existing DID
            println!("Mode: Using existing Trust Registry DID");
            println!("Trust Registry DID: {}", existing_tr_did);
            println!();

            // Parse the secret JSON string into Vec<Secret>
            let tr_secrets: Vec<Secret> = serde_json::from_str(&existing_tr_did_secret)
                .map_err(|e| format!("Failed to parse existing_tr_did_secret as JSON: {}", e))?;

            profile_config = Some(ProfileConfig {
                alias: "Trust Registry".to_string(),
                did: existing_tr_did.clone(),
                secrets: tr_secrets.clone(),
            });

            println!("✓ Profile configuration configured.");
            println!();

            profile = format!("'{}'", serde_json::to_string(&profile_config)?);
        } else if !did_method.is_empty() {
            // Mode 2: Generate new DID

            println!("Mode: Generating new Trust Registry DID");
            println!("DID Method: did:{}", did_method);
            println!();

            let (tr_did, tr_secrets) = match did_method.as_str() {
                "peer" => setup_did_peer_tr(parsed_mediator_url.to_string()),
                "web" | "webvh" => {
                    let web_url = args.didweb_url.ok_or(format!(
                        "--didweb-url is required when using did:{} method.",
                        did_method
                    ))?;

                    setup_did_web_tr(parsed_mediator_url.to_string(), web_url, did_method.clone())?
                }
                _ => {
                    return Err(format!("Unsupported DID method: {}.", did_method).into());
                }
            };

            println!("✓ Profile configuration configured.");
            println!();

            profile_config = Some(ProfileConfig {
                alias: "Trust Registry".to_string(),
                did: tr_did.clone(),
                secrets: tr_secrets.clone(),
            });

            if profile.is_empty() {
                profile = format!("'{}'", serde_json::to_string(&profile_config)?);
            } else {
                // Display the generated profile configuration
                println!("Generated Profile Configuration:");
                println!("{}", serde_json::to_string_pretty(&profile_config)?);
                println!();
                println!(
                    "Ensure to save the profile configuration to the specified location: {}.",
                    profile
                );
                println!();
            }
        } else {
            // Mode 3: Use existing profile location
            println!("Mode: Using existing profile configuration.");
            println!(
                "✓ Profile location specified. The Trust Registry expects that the profile is already configured."
            );
            println!(
                "Ensure to save the profile configuration to the specified location: {}.",
                profile
            );
            println!();
        }

        if let Some(config) = &profile_config
            && !only_admin_operations
        {
            println!("Configuring mediator ACLs for Trust Registry DID...");
            // Configure ACLs in the mediator for the Trust Registry DID
            set_acl(
                &config.alias,
                &config.did,
                &mediator_did,
                config.secrets.clone(),
            )
            .await;
            println!("✓ Configured Trust Registry on mediator.");
        }

        // Configure test Trust Registry
        setup_test_trust_registry(mediator_url.clone(), mediator_did.clone(), test_in_pipeline)
            .await?;
    } else {
        println!("No Mediator configuration specified. Skipping Trust Registry DID configuration.");
    }

    // Set environment variables
    // Expected to be empty if DIDComm mediator is not specified
    server_vars.insert("PROFILE_CONFIG".to_string(), profile.clone());
    server_vars.insert("MEDIATOR_DID".to_string(), mediator_did.clone());
    server_vars.insert("ADMIN_DIDS".to_string(), admin_dids.clone());
    server_vars.insert(
        "ONLY_ADMIN_OPERATIONS".to_string(),
        only_admin_operations.to_string(),
    );

    // Storage configuration
    println!();
    println!("Trust Registry Storage Configuration");
    println!("✓ Storage Backend: {}", args.storage_backend);
    // Insert into the env file
    server_vars.insert(
        "TR_STORAGE_BACKEND".to_string(),
        args.storage_backend.clone(),
    );
    if args.storage_backend == "csv" {
        let file_path = args
            .file_storage_path
            .as_ref()
            .ok_or("Error: --file-storage-path is required when using csv storage")?;
        println!("✓ File Storage Path: {}", file_path);
        // Insert into the env file
        server_vars.insert("FILE_STORAGE_PATH".to_string(), file_path.clone());
    } else if args.storage_backend == "ddb" {
        let table_name = args
            .ddb_table_name
            .as_ref()
            .ok_or("Error: --ddb-table-name is required when using ddb storage")?;
        println!("✓ DDB Table Name: {}", table_name);
        // Insert into the env file
        server_vars.insert("DDB_TABLE_NAME".to_string(), table_name.clone());
    }
    // Audit log format - default to json
    server_vars.insert(
        "AUDIT_LOG_FORMAT".to_string(),
        args.audit_log_format.as_ref().unwrap().to_string(),
    );
    println!(
        "✓ Audit Log Format: {}",
        args.audit_log_format.as_ref().unwrap()
    );

    // Display server configuration in JSON format
    println!();
    println!("Environment Configuration:");
    let config_json = serde_json::to_value(&server_vars)?;
    println!("{}", serde_json::to_string_pretty(&config_json)?);
    println!();

    // Insert variables into .env file
    insert_env_vars("./.env", server_vars, Some("./.env.example"))?;
    println!("✓ .env file updated with Trust Registry configuration");
    println!();
    println!("Start Trust Registry with the following command:");

    if enable_didcomm {
        println!("RUST_LOG=info cargo run --bin trust-registry");
    } else {
        println!("ENABLE_DIDCOMM=false RUST_LOG=info cargo run --bin trust-registry");
    }
    println!();

    Ok(())
}
