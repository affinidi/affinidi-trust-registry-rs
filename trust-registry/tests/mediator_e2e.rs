//! End-to-end test of the registry against a real mediator in Docker.
//!
//! Starts Redis and the published mediator image (`tests/e2e/docker.rs`),
//! spawns the `trust-registry` binary against it, and checks the basic
//! surfaces through the mediator with a DIDComm client: TRQP queries, signed
//! `registry/record/*` Trust Tasks, and a refused unsigned write, plus TRQP over
//! REST. The mediator runs with `trust_task_verification = enforce`, so the
//! registry's own `messaging/account/update` (its access-list mode) and the
//! client's are accepted only when signed.
//!
//! Needs Docker, so it is ignored by default:
//!
//! ```text
//! cargo test -p trust-registry --test mediator_e2e -- --ignored --nocapture
//! ```
//!
//! - `E2E_MEDIATOR_IMAGE`: mediator image (default
//!   `public.ecr.aws/affinidi/messaging-mediator:v0.33.1`)
//! - `E2E_REDIS_IMAGE`: Redis image (default `redis:7-alpine`)
//! - `E2E_KEEP_STACK=1`: leave the containers running afterwards
//! - `E2E_TR_LOG`: `RUST_LOG` for the registry (default `info`)
//! - `E2E_IDENTITY_KEYS`: `ed25519` (default) or `p256`, the key type of the
//!   registry's and the client's DIDs in the main test. `p256` is what the
//!   setup tools generated before they moved to Curve25519. The messaging SDK
//!   signs Trust Tasks only with an Ed25519 key, so with `p256` the mediator
//!   refuses the unsigned `messaging/account/update` (`proof_required`) and the
//!   main test fails at its first one.
//!
//! A second test runs a private registry (`ACL_MODE=ExplicitAllow`) with a
//! P-256 DID, whose mode the mediator therefore refuses, and checks that it does
//! not serve DIDComm: `/health` reports `degraded` with the reason.

mod e2e;

use std::time::Duration;

use serde_json::{Value, json};
use trust_registry::didcomm::handlers::trqp::{
    QUERY_RECOGNITION_MESSAGE_TYPE, QUERY_RECOGNITION_RESPONSE_MESSAGE_TYPE,
};
use trust_registry::trust_tasks::type_uris;
use trust_tasks_rs::TrustTask;

use e2e::client::{Client, IdentityKeys};
use e2e::docker::MediatorStack;
use e2e::registry::{RegistryProcess, RegistrySettings};

const REPLY_TIMEOUT: Duration = Duration::from_secs(30);

/// The record the registry starts with, as a CSV row (`e30=` is `{}`).
const SEEDED_ENTITY: &str = "did:example:e2e-member";
const SEEDED_AUTHORITY: &str = "did:example:e2e-community";
const SEEDED_ROW: &str =
    "did:example:e2e-member,did:example:e2e-community,member,community,true,false,e30=,recognition";

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "needs Docker; run with --ignored (see the module docs)"]
async fn registry_against_a_dockerised_mediator() {
    if let Err(e) = run().await {
        panic!("{e}");
    }
}

async fn run() -> Result<(), String> {
    let keys = IdentityKeys::from_env()?;
    println!("identity keys: {keys:?}");

    // Declared before the registry and the client so it is dropped after them.
    let mediator = MediatorStack::start(keys == IdentityKeys::P256).await?;
    println!("mediator {} at {}", mediator.did, mediator.url);

    // The client is the registry's admin, so it can write under its own DID.
    let client = Client::connect("e2e-client", &mediator.did, keys).await?;
    let settings = RegistrySettings {
        mediator_did: &mediator.did,
        admin_did: &client.did,
        records: &[SEEDED_ROW],
        keys,
        acl_mode: "ExplicitDeny",
    };
    let mut registry = match RegistryProcess::start(&settings).await {
        Ok(registry) => registry,
        Err(e) => return Err(format!("{e}\n{}", mediator.logs().await)),
    };

    let result = scenario(&mut registry, &client).await;
    client.shutdown().await;
    match result {
        Ok(()) => Ok(()),
        Err(e) => Err(format!(
            "{e}\n{}\n{}",
            registry.log_tail(80),
            mediator.logs().await
        )),
    }
}

async fn scenario(registry: &mut RegistryProcess, client: &Client) -> Result<(), String> {
    registry
        .wait_for_health(REPLY_TIMEOUT, |h| h["status"] == "OK")
        .await?;
    let http = reqwest::Client::new();

    // TRQP over REST answers from the seeded store.
    let recognition = post(
        &http,
        &format!("{}/recognition", registry.base_url),
        &seeded_key(),
    )
    .await?;
    expect(
        recognition["recognized"] == true,
        "REST recognises the seeded record",
        &recognition,
    )?;
    println!("REST recognition ok");

    // The client opens its inbox with a signed account/update.
    client.accept_replies().await?;

    // TRQP over DIDComm, through the mediator.
    client
        .send(
            &registry.did,
            QUERY_RECOGNITION_MESSAGE_TYPE,
            seeded_key(),
            None,
        )
        .await?;
    let reply = client
        .message_of_type(QUERY_RECOGNITION_RESPONSE_MESSAGE_TYPE, REPLY_TIMEOUT)
        .await?;
    expect(
        reply.body["entity_id"] == SEEDED_ENTITY,
        "the DIDComm answer is for the seeded record",
        &reply.body,
    )?;
    expect(
        reply.body["recognized"] == true,
        "DIDComm recognises the seeded record",
        &reply.body,
    )?;
    println!("DIDComm recognition ok");

    // A signed write under the client's own authority is stored ...
    let put = client
        .trust_task(
            &registry.did,
            type_uris::RECORD_PUT,
            json!({ "record": written_record(&client.did) }),
            true,
        )
        .await?;
    let reply = client
        .round_trip(&registry.did, &put, REPLY_TIMEOUT)
        .await?;
    expect_response(&reply, "the signed put is accepted")?;
    expect(
        reply.payload["ok"] == true,
        "the put reports ok",
        &reply.payload,
    )?;

    // ... and a signed query reads it back.
    let query = client
        .trust_task(
            &registry.did,
            type_uris::RECORD_QUERY,
            written_key(&client.did),
            true,
        )
        .await?;
    let reply = client
        .round_trip(&registry.did, &query, REPLY_TIMEOUT)
        .await?;
    expect_response(&reply, "the signed query is answered")?;
    let stored = &reply.payload["records"][0];
    expect(
        stored["authority_id"] == client.did.as_str() && stored["authorized"] == true,
        "the query returns the written record",
        &reply.payload,
    )?;
    println!("signed put + query ok");

    // An unsigned write is refused.
    let unsigned = client
        .trust_task(
            &registry.did,
            type_uris::RECORD_PUT,
            json!({ "record": written_record(&client.did) }),
            false,
        )
        .await?;
    let reply = client
        .round_trip(&registry.did, &unsigned, REPLY_TIMEOUT)
        .await?;
    expect(
        error_code(&reply) == Some("proofRequired"),
        "an unsigned put is refused with proofRequired",
        &json!({ "type": reply.type_uri.to_string(), "payload": reply.payload }),
    )?;
    println!("unsigned put refused");

    // What was written over DIDComm is visible over REST.
    let authorization = post(
        &http,
        &format!("{}/authorization", registry.base_url),
        &written_key(&client.did),
    )
    .await?;
    expect(
        authorization["authorized"] == true,
        "REST authorises the record written over DIDComm",
        &authorization,
    )?;
    println!("REST authorization of the written record ok");

    // The registry set its own access-list mode at start-up. A failure there is
    // only logged, so check the log as well as the process.
    registry.ensure_running()?;
    expect(
        !registry.log_contains("Failed to set ACL mode"),
        "the registry set its access-list mode at the mediator",
        &json!("see the registry log"),
    )?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "needs Docker; run with --ignored (see the module docs)"]
async fn a_private_registry_whose_mode_is_refused_does_not_serve_didcomm() {
    if let Err(e) = run_private_mode_refused().await {
        panic!("{e}");
    }
}

/// A P-256 registry's `messaging/account/update` goes out unsigned, and the
/// enforcing mediator refuses it, so `ExplicitAllow` is never applied. The
/// registry must then stop rather than serve DIDComm from an account that may
/// accept anyone, while REST reads carry on.
async fn run_private_mode_refused() -> Result<(), String> {
    let mediator = MediatorStack::start(true).await?;
    let settings = RegistrySettings {
        mediator_did: &mediator.did,
        admin_did: "did:example:e2e-nobody",
        records: &[SEEDED_ROW],
        keys: IdentityKeys::P256,
        acl_mode: "ExplicitAllow",
    };
    let mut registry = match RegistryProcess::start(&settings).await {
        Ok(registry) => registry,
        Err(e) => return Err(format!("{e}\n{}", mediator.logs().await)),
    };

    let checks = async {
        let health = registry
            .wait_for_health(REPLY_TIMEOUT, |h| h["status"] == "degraded")
            .await?;
        expect(
            health["detail"]
                .as_str()
                .is_some_and(|d| d.contains("Failed to set ACL mode ExplicitAllow")),
            "/health names the refused private mode",
            &health,
        )?;
        let recognition = post(
            &reqwest::Client::new(),
            &format!("{}/recognition", registry.base_url),
            &seeded_key(),
        )
        .await?;
        expect(
            recognition["recognized"] == true,
            "REST reads still answer",
            &recognition,
        )?;
        registry.ensure_running()
    };
    match checks.await {
        Ok(()) => Ok(()),
        Err(e) => Err(format!(
            "{e}\n{}\n{}",
            registry.log_tail(80),
            mediator.logs().await
        )),
    }
}

fn seeded_key() -> Value {
    json!({
        "entity_id": SEEDED_ENTITY,
        "authority_id": SEEDED_AUTHORITY,
        "action": "member",
        "resource": "community",
    })
}

fn written_key(authority: &str) -> Value {
    json!({
        "entity_id": "did:example:e2e-written",
        "authority_id": authority,
        "action": "issue",
        "resource": "e2e-credential",
    })
}

fn written_record(authority: &str) -> Value {
    let mut record = written_key(authority);
    record["recognized"] = json!(true);
    record["authorized"] = json!(true);
    record["record_type"] = json!("authorization");
    record["context"] = json!({ "description": "written by the e2e test" });
    record
}

async fn post(http: &reqwest::Client, url: &str, body: &Value) -> Result<Value, String> {
    let response = http
        .post(url)
        .json(body)
        .send()
        .await
        .map_err(|e| format!("POST {url}: {e}"))?;
    let status = response.status();
    let body: Value = response.json().await.unwrap_or(Value::Null);
    if !status.is_success() {
        return Err(format!("POST {url}: HTTP {status}: {body}"));
    }
    Ok(body)
}

fn error_code(reply: &TrustTask<Value>) -> Option<&str> {
    if reply.type_uri.is_response() {
        return None;
    }
    reply.payload.get("code").and_then(Value::as_str)
}

fn expect_response(reply: &TrustTask<Value>, what: &str) -> Result<(), String> {
    expect(
        reply.type_uri.is_response(),
        what,
        &json!({ "type": reply.type_uri.to_string(), "payload": reply.payload }),
    )
}

fn expect(ok: bool, what: &str, seen: &Value) -> Result<(), String> {
    if ok {
        Ok(())
    } else {
        Err(format!("expected {what}; got {seen}"))
    }
}
