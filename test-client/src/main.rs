use std::sync::Arc;

use affinidi_tdk::{
    TDK,
    common::{config::TDKConfig, profiles::TDKProfile},
    messaging::{
        ATM,
        profiles::ATMProfile,
        protocols::{
            Protocols,
            mediator::acls::{AccessListModeType, MediatorACLSet},
        },
    },
};
use dotenvy::dotenv;

use serde_json::json;
use sha256::digest;

use crate::{
    admin_operations::{
        CommonCrudInput, create_record, delete_record, list_records, read_record, update_record,
    },
    receivers::users_listener::user_listener,
    service_configs::load_user_config,
};

pub mod admin_operations;
pub mod common;
pub mod receivers;
pub mod sender;
pub mod service_configs;

async fn set_public_acls_mode(
    atm: Arc<ATM>,
    profile: Arc<ATMProfile>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let protocols = Protocols::new();

    let account_get_result = protocols.mediator.account_get(&atm, &profile, None).await;

    let account_info = account_get_result?.ok_or(format!(
        "[profile = {}] Failed to get account info",
        &profile.inner.alias
    ))?;
    let mut acls = MediatorACLSet::from_u64(account_info.acls);
    acls.set_access_list_mode(AccessListModeType::ExplicitDeny, true, false)?;

    protocols
        .mediator
        .acls_set(&atm, &profile, &digest(&profile.inner.did), &acls)
        .await?;
    Ok(())
}

#[tokio::main]
async fn main() {
    dotenv().ok();
    let protocols = Arc::new(Protocols::new());
    let user_configs = match load_user_config() {
        Ok(uc) => uc,
        Err(err) => {
            println!("Failed to get user config: {err:#?}");
            return;
        }
    };

    // Get Trust Registry DID: runtime env var or fallback to PROFILE_CONFIG from .env
    let trust_registry_did = std::env::var("TRUST_REGISTRY_DID")
        .or_else(|_| {
            std::env::var("PROFILE_CONFIG")
                .and_then(|config| {
                    config.parse::<serde_json::Value>()
                        .map_err(|_| std::env::VarError::NotPresent)
                        .and_then(|json| {
                            json.get("did")
                                .and_then(|v| v.as_str())
                                .map(|s| s.to_string())
                                .ok_or(std::env::VarError::NotPresent)
                        })
                })
        })
        .expect("TRUST_REGISTRY_DID environment variable is not set, and PROFILE_CONFIG is either missing or does not contain a valid 'did' property.");

    // Get Mediator DID from environment variable (runtime or .env file)
    let mediator_did = std::env::var("MEDIATOR_DID")
        .expect("MEDIATOR_DID environment variable is not set. Set it at runtime or in .env file.");

    println!("\nTrust Registry DID: {trust_registry_did}");
    println!("\nMediator DID: {mediator_did}");

    // let mediator_did = mediator_did.clone();
    println!("\nLoading test user configurations...");
    for (did, did_config) in user_configs {
        let mediator_did_clone = mediator_did.clone();
        let profile = TDKProfile::new(
            &did_config.alias,
            &did,
            Some(&*mediator_did_clone),
            did_config.secrets.clone(),
        );

        let tdk = TDK::new(
            TDKConfig::builder()
                .with_load_environment(false)
                .build()
                .unwrap(),
            None,
        )
        .await
        .unwrap();
        println!("\nAdding profile: {}", &did_config.alias);
        println!("Profile DID: {}", &did);
        tdk.add_profile(&profile).await;

        let atm = Arc::new(tdk.atm.clone().unwrap());
        let atm_clone = Arc::clone(&atm);
        let protocols_clone = Arc::clone(&protocols);

        let profile = atm
            .profile_add(
                &ATMProfile::from_tdk_profile(&atm, &profile).await.unwrap(),
                true,
            )
            .await
            .unwrap();

        // Ensure we only run admin operations for the admin DID
        if did_config.alias.eq("SampleTRAdmin") {
            println!("\nStarting Admin Operations Demo for SampleTRAdmin...\n");
            set_public_acls_mode(Arc::clone(&atm), Arc::clone(&profile))
                .await
                .unwrap();
            tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;

            match create_record(
                CommonCrudInput {
                    atm: Arc::clone(&atm),
                    profile: Arc::clone(&profile),
                    trust_registry_did: trust_registry_did.clone(),
                    protocols: Arc::clone(&protocols),
                    mediator_did: mediator_did.clone(),
                    entity_id: "did:example:entity123".to_string(),
                    authority_id: "did:example:authority456".to_string(),
                    action: "action_xyz".to_string(),
                    resource: "resource_abc".to_string(),
                    record_type: "assertion".to_string(),
                },
                true,
                true,
                Some(json!({
                    "description": "Test credential type",
                    "version": "1.0",
                    "tags": ["test", "demo"]
                })),
            )
            .await
            {
                Ok(_) => println!("Create record request sent - awaiting response..."),
                Err(err) => println!("Create record request failed: {err:#?}"),
            }

            tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;

            match read_record(CommonCrudInput {
                atm: Arc::clone(&atm),
                profile: Arc::clone(&profile),
                trust_registry_did: trust_registry_did.clone(),
                protocols: Arc::clone(&protocols),
                mediator_did: mediator_did.clone(),
                entity_id: "did:example:entity123".to_string(),
                authority_id: "did:example:authority456".to_string(),
                action: "action_xyz".to_string(),
                resource: "resource_abc".to_string(),
                record_type: "assertion".to_string(),
            })
            .await
            {
                Ok(_) => println!("Read record request sent - awaiting response..."),
                Err(err) => println!("Read record request failed: {err:#?}"),
            }

            tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;

            match update_record(
                CommonCrudInput {
                    atm: Arc::clone(&atm),
                    profile: Arc::clone(&profile),
                    trust_registry_did: trust_registry_did.clone(),
                    protocols: Arc::clone(&protocols),
                    mediator_did: mediator_did.clone(),
                    entity_id: "did:example:entity123".to_string(),
                    authority_id: "did:example:authority456".to_string(),
                    action: "action_xyz".to_string(),
                    resource: "resource_abc".to_string(),
                    record_type: "assertion".to_string(),
                },
                false,
                true,
                Some(json!({
                    "description": "Updated test credential type",
                    "version": "2.0",
                    "tags": ["test", "demo", "updated"]
                })),
            )
            .await
            {
                Ok(_) => println!("Update record request sent - awaiting response..."),
                Err(err) => println!("Update record request failed: {err:#?}"),
            }

            tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;

            match list_records(
                &atm,
                profile.clone(),
                &trust_registry_did,
                &protocols,
                &mediator_did,
            )
            .await
            {
                Ok(_) => println!("List records request sent - awaiting response..."),
                Err(err) => println!("List records request failed: {err:#?}"),
            }

            tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;

            match delete_record(CommonCrudInput {
                atm: Arc::clone(&atm),
                profile: Arc::clone(&profile),
                trust_registry_did: trust_registry_did.clone(),
                protocols: Arc::clone(&protocols),
                mediator_did: mediator_did.clone(),
                entity_id: "did:example:entity123".to_string(),
                authority_id: "did:example:authority456".to_string(),
                action: "action_xyz".to_string(),
                resource: "resource_abc".to_string(),
                record_type: "assertion".to_string(),
            })
            .await
            {
                Ok(_) => println!("Delete record request sent - awaiting response..."),
                Err(err) => println!("Delete record request failed: {err:#?}"),
            }

            tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;

            match read_record(CommonCrudInput {
                atm: Arc::clone(&atm),
                profile: Arc::clone(&profile),
                trust_registry_did: trust_registry_did.clone(),
                protocols: Arc::clone(&protocols),
                mediator_did: mediator_did.clone(),
                entity_id: "did:example:entity123".to_string(),
                authority_id: "did:example:authority456".to_string(),
                action: "action_xyz".to_string(),
                resource: "resource_abc".to_string(),
                record_type: "assertion".to_string(),
            })
            .await
            {
                Ok(_) => println!("Read record (after delete) request sent - awaiting response..."),
                Err(err) => println!("Read record (after delete) request failed: {err:#?}"),
            }

            println!("Admin Operations Demo completed!\n");
            println!("\n{}", "=".repeat(60));
        } else {
            println!(
                "\nUnable to find 'SampleTRAdmin' from the user_config.json file of the test-client.\n"
            );
        }

        if did_config.alias.eq("SampleTRAdmin") {
            println!("\nStart listening to responses from the Trust Registry...\n");
            user_listener(did_config, &atm_clone, protocols_clone, &profile).await;
        }
    }
}
