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
    admin_operations::{create_record, delete_record, list_records, read_record, update_record},
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
            println!("Failed to get user config: {:#?}", err);
            return;
        }
    };

    // TODO: provide dids via envs
    let trust_registry_did = std::env::var("TRUST_REGISTRY_DID")
        .unwrap_or("did:peer:2.Vz6Mkjm4p8h47Q9faL3oTrEYLyo8RAAndAyR35oUHBudWZhR3.EzQ3sherFvK5Fp7gfM9etgWwqiKMiaYGA5KbbDQGj4C7APDRHi".to_string());
    let mediator_did = std::env::var("MEDIATOR_DID").unwrap_or(
        "did:web:afddf5a2-bb92-4b9d-a467-9f4b0a57e51f.atlas.dev.affinidi.io".to_string(),
    );
    let mediator_did = Arc::new(mediator_did);
    for (did, did_config) in user_configs {
        let mediator_did_clone = Arc::clone(&mediator_did);
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

        if did_config.alias.eq("Alice") {
            println!("\nStarting Admin Operations Demo for Alice...\n");
            set_public_acls_mode(Arc::clone(&atm), Arc::clone(&profile))
                .await
                .unwrap();
            tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;

            match create_record(
                &atm,
                profile.clone(),
                &trust_registry_did,
                &protocols,
                &mediator_did,
                "did:example:entity123",
                "did:example:authority456",
                "credential_type_xyz",
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
                Ok(_) => println!("Create record completed"),
                Err(err) => println!("Create record failed: {:#?}", err),
            }

            tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;

            match read_record(
                &atm,
                profile.clone(),
                &trust_registry_did,
                &protocols,
                &mediator_did,
                "did:example:entity123",
                "did:example:authority456",
                "credential_type_xyz",
            )
            .await
            {
                Ok(_) => println!("Read record completed"),
                Err(err) => println!("Read record failed: {:#?}", err),
            }

            tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;

            match update_record(
                &atm,
                profile.clone(),
                &trust_registry_did,
                &protocols,
                &mediator_did,
                "did:example:entity123",
                "did:example:authority456",
                "credential_type_xyz",
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
                Ok(_) => println!("Update record completed"),
                Err(err) => println!("Update record failed: {:#?}", err),
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
                Ok(_) => println!("List records completed"),
                Err(err) => println!("List records failed: {:#?}", err),
            }

            tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;

            match delete_record(
                &atm,
                profile.clone(),
                &trust_registry_did,
                &protocols,
                &mediator_did,
                "did:example:entity123",
                "did:example:authority456",
                "credential_type_xyz",
            )
            .await
            {
                Ok(_) => println!("Delete record completed"),
                Err(err) => println!("Delete record failed: {:#?}", err),
            }

            tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;

            match read_record(
                &atm,
                profile.clone(),
                &trust_registry_did,
                &protocols,
                &mediator_did,
                "did:example:entity123",
                "did:example:authority456",
                "credential_type_xyz",
            )
            .await
            {
                Ok(_) => println!("Read record (after delete) completed"),
                Err(err) => println!("Read record (after delete) failed: {:#?}", err),
            }

            println!("\n{}", "=".repeat(60));
            println!("Admin Operations Demo completed!\n");
        }

        if did_config.alias.eq("Alice") {
            user_listener(did_config, &atm_clone, protocols_clone, &profile).await;
        }
    }
}
