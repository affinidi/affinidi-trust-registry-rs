//! A demo of the registry's `registry/record/*` Trust Tasks over DIDComm: it
//! creates, reads, updates, lists and deletes one record as an admin, waits
//! for the registry's answer to each request, and exits non-zero if any answer
//! is not the one expected. It is a reference for the message flow, not an
//! administration tool.

use anyhow::{Result, anyhow, bail};
use std::{sync::Arc, time::Duration};

use affinidi_tdk::{
    TDK,
    common::{config::TDKConfig, profiles::TDKProfile},
    messaging::{ATM, profiles::ATMProfile},
};
use dotenvy::dotenv;

use serde_json::json;

use crate::{
    admin_operations::{
        CommonCrudInput, Reply, await_reply, create_record, delete_record, list_records,
        read_record, update_record,
    },
    service_configs::{ADMIN_ALIAS, UserConfig, load_user_config},
};

pub mod admin_operations;
pub mod service_configs;

/// How long to wait for the registry's answer to each request.
const REPLY_TIMEOUT: Duration = Duration::from_secs(30);

/// Exit status when a new identity was generated and must be registered
/// before the demo can run.
const EXIT_IDENTITY_GENERATED: i32 = 2;

async fn set_public_acls_mode(atm: Arc<ATM>, profile: Arc<ATMProfile>) -> Result<()> {
    use affinidi_tdk::messaging::tasks::messaging::account::update::v0_2::{
        MediatorAcl, MediatorAclAccessListMode,
    };
    // Public: anyone not on the deny list may send. `account/update` is a
    // partial update, so only the access-list mode changes.
    let acl: MediatorAcl = MediatorAcl::builder()
        .access_list_mode(Some(MediatorAclAccessListMode::ExplicitDeny))
        .try_into()
        .map_err(|e| anyhow!("{e}"))?;
    atm.trust_tasks()
        .account_update(&profile, None, None, Some(acl), None)
        .await?;
    Ok(())
}

/// What a step expects the registry to answer.
#[derive(Clone, Copy)]
enum Expect {
    Response,
    Error,
}

/// Wait for the answer to `thread_id` and report whether it is the one
/// `expect`ed.
async fn check(
    step: &str,
    atm: &ATM,
    profile: &Arc<ATMProfile>,
    sent: Result<String, Box<dyn std::error::Error>>,
    expect: Expect,
) -> bool {
    let thread_id = match sent {
        Ok(thread_id) => thread_id,
        Err(err) => {
            println!("FAIL {step}: the request was not sent: {err}");
            return false;
        }
    };
    let reply = match await_reply(atm, profile, &thread_id, REPLY_TIMEOUT).await {
        Ok(reply) => reply,
        Err(err) => {
            println!("FAIL {step}: {err}");
            return false;
        }
    };
    match (expect, &reply) {
        (Expect::Response, Reply::Response(document)) => {
            println!(
                "ok   {step}: response {}",
                serde_json::to_string(&document["payload"]).unwrap_or_default()
            );
            true
        }
        (Expect::Error, Reply::Error { code, .. }) => {
            println!("ok   {step}: refused as expected ({code})");
            true
        }
        (Expect::Response, Reply::Error { code, document }) => {
            println!(
                "FAIL {step}: expected a response, got trust-task-error {code}: {}",
                serde_json::to_string(&document["payload"]).unwrap_or_default()
            );
            false
        }
        (Expect::Error, Reply::Response(_)) => {
            println!("FAIL {step}: expected a trust-task-error, got a response");
            false
        }
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    dotenv().ok();
    // Get Trust Registry DID: runtime env var or fallback to PROFILE_CONFIG from .env
    let trust_registry_did = std::env::var("TRUST_REGISTRY_DID")
        .ok()
        .or_else(|| {
            let config = std::env::var("PROFILE_CONFIG").ok()?;
            let json = config.parse::<serde_json::Value>().ok()?;
            json.get("did")?.as_str().map(str::to_string)
        })
        .ok_or_else(|| {
            anyhow!(
                "TRUST_REGISTRY_DID environment variable is not set, and PROFILE_CONFIG is either \
                 missing or does not contain a valid 'did' property."
            )
        })?;

    // Get Mediator DID from environment variable (runtime or .env file)
    let mediator_did = std::env::var("MEDIATOR_DID").map_err(|_| {
        anyhow!("MEDIATOR_DID environment variable is not set. Set it at runtime or in .env file.")
    })?;

    println!("\nTrust Registry DID: {trust_registry_did}");
    println!("\nMediator DID: {mediator_did}");

    let user_configs = match load_user_config(&mediator_did)
        .map_err(|err| anyhow!("Failed to get user config: {err}"))?
    {
        UserConfig::Loaded(uc) => uc,
        UserConfig::Generated { did, path } => {
            println!(
                "\nNo test client identity was found, so a new one was generated and saved to {} \
                 (keep it private; it is not tracked by git).",
                path.display()
            );
            println!("\nTest client admin DID: {did}");
            println!(
                "\nAdd this DID to the Trust Registry's ADMIN_DIDS, restart the registry, and run \
                 the test client again."
            );
            std::process::exit(EXIT_IDENTITY_GENERATED);
        }
    };

    let (did, did_config) = user_configs
        .into_iter()
        .find(|(_, config)| config.alias == ADMIN_ALIAS)
        .ok_or_else(|| {
            anyhow!(
                "Unable to find '{ADMIN_ALIAS}' in the test client's user_config.json; delete \
                 the file to have a new identity generated."
            )
        })?;

    let profile = TDKProfile::new(
        &did_config.alias,
        &did,
        Some(&*mediator_did),
        did_config.secrets.clone(),
    );
    let tdk = TDK::new(
        TDKConfig::builder().with_load_environment(false).build()?,
        None,
    )
    .await?;
    println!("\nAdding profile: {}", &did_config.alias);
    println!("Profile DID: {}", &did);
    tdk.add_profile(&profile).await;

    let atm = Arc::new(
        tdk.atm
            .clone()
            .ok_or(anyhow!("Failed to initialize ATM client"))?,
    );
    let profile = atm
        .profile_add(&ATMProfile::from_tdk_profile(&atm, &profile).await?, true)
        .await?;

    println!("\nStarting the admin operations demo as {ADMIN_ALIAS}...\n");
    set_public_acls_mode(Arc::clone(&atm), Arc::clone(&profile)).await?;

    let input = |entity_id: &str, action: &str, resource: &str| CommonCrudInput {
        atm: Arc::clone(&atm),
        profile: Arc::clone(&profile),
        trust_registry_did: trust_registry_did.clone(),
        secrets: did_config.secrets.clone(),
        entity_id: entity_id.to_string(),
        authority_id: did.clone(),
        action: action.to_string(),
        resource: resource.to_string(),
        record_type: "authorization".to_string(),
    };
    let record = || input("did:example:entity123", "action_xyz", "resource_abc");

    let mut failed = Vec::new();
    let mut step = async |name: &'static str,
                          sent: Result<String, Box<dyn std::error::Error>>,
                          expect: Expect| {
        if !check(name, &atm, &profile, sent, expect).await {
            failed.push(name);
        }
    };

    step(
        "create",
        create_record(
            record(),
            true,
            true,
            Some(json!({
                "description": "Test credential type",
                "version": "1.0",
                "tags": ["test", "demo"]
            })),
        )
        .await,
        Expect::Response,
    )
    .await;
    step("read", read_record(record()).await, Expect::Response).await;
    step(
        "update",
        update_record(
            record(),
            false,
            true,
            Some(json!({
                "description": "Updated test credential type",
                "version": "2.0",
                "tags": ["test", "demo", "updated"]
            })),
        )
        .await,
        Expect::Response,
    )
    .await;
    step(
        "list",
        list_records(input("", "", "")).await,
        Expect::Response,
    )
    .await;
    step("delete", delete_record(record()).await, Expect::Response).await;
    step(
        "read after delete",
        read_record(record()).await,
        Expect::Error,
    )
    .await;

    println!("\n{}", "=".repeat(60));
    if failed.is_empty() {
        println!("Admin operations demo: every step answered as expected.");
        Ok(())
    } else {
        bail!(
            "admin operations demo: {} step(s) failed: {}",
            failed.len(),
            failed.join(", ")
        )
    }
}
