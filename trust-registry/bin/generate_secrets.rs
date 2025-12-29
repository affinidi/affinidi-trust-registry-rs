#![cfg(feature = "dev-tools")]
use affinidi_did_key::DIDKey;
use affinidi_tdk::{
    TDK,
    common::{config::TDKConfig, profiles::TDKProfile},
    did_common::one_or_many::OneOrMany,
    messaging::{
        profiles::ATMProfile,
        protocols::{
            Protocols,
            mediator::acls::{AccessListModeType, MediatorACLSet},
        },
    },
    secrets_resolver::secrets::{KeyType, Secret},
};
use did_peer::{
    DIDPeer, DIDPeerCreateKeys, DIDPeerKeyType, DIDPeerKeys, DIDPeerService, PeerServiceEndPoint,
    PeerServiceEndPointLong, PeerServiceEndPointLongMap,
};
use serde_json::json;
use sha256::digest;
use std::{
    collections::HashMap,
    error::Error,
    fs::{self, OpenOptions},
    io::{BufRead, BufReader, Write},
    path::Path,
    sync::Arc,
};

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

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let mut dids_and_secrets: Vec<(String, Vec<Secret>)> = vec![];
    let mediator_url = std::env::var("MEDIATOR_URL").expect("MEDIATOR_URL not set");
    let mediator_did = std::env::var("MEDIATOR_DID").expect("MEDIATOR_DID not set");
    let in_pipeline = std::env::var("IN_PIPELINE")
        .unwrap_or("false".to_string())
        .to_lowercase()
        == "true";

    let tr_did = create_did(Some(vec![mediator_url.clone()]), true);
    let tr_profile_configs = json!({
        "did": tr_did.0,
        "alias": "Trust Registry",
        "secrets": tr_did.1
    });
    dids_and_secrets.push(tr_did.clone());
    let test_tr_did = create_did(Some(vec![mediator_url.to_string()]), true);
    dids_and_secrets.push(test_tr_did.clone());
    let test_tr_profile_configs = json!({
        "did": test_tr_did.0,
        "alias": "Test Trust Registry",
        "secrets": test_tr_did.1
    });

    let test_client_did = create_did(Some(vec![mediator_url.to_string()]), true);
    dids_and_secrets.push(test_client_did.clone());

    for ds in dids_and_secrets {
        set_acl(&ds.0, &ds.0, &mediator_did, ds.1.clone()).await;
    }
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
        Ok(())
    } else {
        let mut server_vars = HashMap::new();
        server_vars.insert(
            "PROFILE_CONFIG".to_string(),
            format!("'{}'", serde_json::to_string(&tr_profile_configs)?),
        );
        server_vars.insert("MEDIATOR_DID".to_string(), mediator_did.clone());
        insert_env_vars("./.env", server_vars, Some("./.env.example"))?;
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

        Ok(())
    }
}
