//! Integration tests for the mediator-wired fixture (`--features mediator`).
//!
//! Spawns an `affinidi-messaging-test-mediator` and a Trust Registry whose
//! DIDComm (and, under `--features tsp`, TSP) Trust Task listeners connect to
//! it, then drives Trust Tasks end-to-end.

#![cfg(feature = "mediator")]

use affinidi_messaging_test_mediator::TestEnvironment;
use serde_json::{Value, json};
use test_trust_registry::TestTrustRegistry;
use trust_registry::domain::{
    Action, AuthorityId, EntityId, RecordType, Resource, TrustRecord, TrustRecordBuilder,
};

fn sample_record() -> TrustRecord {
    TrustRecordBuilder::new()
        .entity_id(EntityId::new("did:example:entity"))
        .authority_id(AuthorityId::new("did:example:authority"))
        .action(Action::new("issue"))
        .resource(Resource::new("vc"))
        .recognized(true)
        .authorized(true)
        .record_type(RecordType::Authorization)
        .build()
        .expect("valid record")
}

fn query_body() -> Value {
    json!({
        "entity_id": "did:example:entity",
        "authority_id": "did:example:authority",
        "action": "issue",
        "resource": "vc"
    })
}

/// The fixture mints a DIDComm identity on the mediator, starts the listener,
/// and still serves the REST/TRQP surface over the same in-memory store.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn spawns_against_a_mediator_and_serves_rest() {
    let env = TestEnvironment::spawn().await.expect("spawn test mediator");

    let tr = TestTrustRegistry::builder()
        .record(sample_record())
        .spawn_with_mediator(&env.mediator)
        .await
        .expect("spawn trust registry against mediator");

    // A DIDComm/TSP identity was minted on the mediator.
    let did = tr.did().expect("mediator-wired registry has a DID");
    assert!(did.starts_with("did:peer:"), "unexpected DID: {did}");

    // The REST surface still answers over the same seeded store.
    let recognition: Value = reqwest::Client::new()
        .post(format!("{}/recognition", tr.base_url()))
        .json(&query_body())
        .send()
        .await
        .expect("recognition request")
        .json()
        .await
        .expect("recognition json");
    assert_eq!(recognition["recognized"], json!(true));

    tr.shutdown().await;
    env.shutdown().await.ok();
}

// --- Routed Trust Task round-trips ------------------------------------------
//
// These drive a full client -> mediator -> Trust Registry -> mediator -> client
// Trust Task exchange. They are `#[ignore]`d because the mediator stack has a
// heavy cold compile and the routed pickup is timing-sensitive; run explicitly:
//
//   cargo test -p test-trust-registry --features mediator --test mediator -- --ignored
//   cargo test -p test-trust-registry --features tsp      --test mediator -- --ignored

use std::sync::Arc;
use std::time::Duration;

use affinidi_messaging_sdk::messages::fetch::FetchOptions;
use affinidi_messaging_sdk::profiles::ATMProfile;
use affinidi_tdk::didcomm::Message;
use trust_registry::trust_tasks::payloads::type_uris;
use trust_tasks_didcomm::ENVELOPE_TYPE;
use trust_tasks_rs::TrustTask;

// The tests build requests and read responses as `serde_json::Value` so they
// stay decoupled from the payload struct representation (which differs across
// the "adopt published specs" change); the wire shape — flat TRQP identifiers
// and a `recognized` bool — is identical either way.
fn build_request(issuer: &str, recipient: &str) -> TrustTask<Value> {
    let type_uri = type_uris::RECOGNITION
        .parse()
        .expect("valid recognition type uri");
    let payload = json!({
        "entity_id": "did:example:entity",
        "authority_id": "did:example:authority",
        "action": "issue",
        "resource": "vc"
    });
    let mut doc = TrustTask::new(
        format!("urn:uuid:{}", uuid::Uuid::new_v4()),
        type_uri,
        payload,
    );
    doc.issuer = Some(issuer.to_string());
    doc.recipient = Some(recipient.to_string());
    doc.issued_at = Some(chrono::Utc::now());
    doc
}

/// Poll the client's inbox until a Trust Task envelope arrives, returning its
/// response payload.
async fn await_recognition_response(env: &TestEnvironment, profile: &Arc<ATMProfile>) -> Value {
    for _ in 0..40 {
        let fetched = env
            .atm
            .fetch_messages(profile, &FetchOptions::default())
            .await
            .expect("fetch messages");
        for item in fetched.success {
            let Some(packed) = item.msg else { continue };
            let Ok((message, _)) = env.atm.unpack(&packed).await else {
                continue;
            };
            if message.typ == ENVELOPE_TYPE {
                let task: TrustTask<Value> =
                    serde_json::from_value(message.body).expect("parse response task");
                return task.payload;
            }
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    panic!("no Trust Task response received within the timeout");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "routed round-trip through the mediator; run with --ignored"]
async fn recognition_round_trips_over_didcomm() {
    let env = TestEnvironment::spawn().await.expect("spawn test mediator");
    let tr = TestTrustRegistry::builder()
        .record(sample_record())
        .spawn_with_mediator(&env.mediator)
        .await
        .expect("spawn trust registry");
    let tr_did = tr.did().expect("tr did").to_string();
    let mediator_did = env.mediator.did().to_string();
    let client = env.add_user("client").await.expect("add client");

    let request = build_request(&client.did, &tr_did);
    let body = serde_json::to_value(&request).expect("serialise task");
    let message = Message::new(ENVELOPE_TYPE, body)
        .from(client.did.clone())
        .to(vec![tr_did.clone()])
        .thid(request.id.clone());
    let (packed, _) = env
        .atm
        .pack_encrypted(&message, &tr_did, Some(&client.did), None)
        .await
        .expect("pack_encrypted");

    env.atm
        .forward_and_send_message(
            &client.profile,
            false,
            &packed,
            None,
            &mediator_did,
            &tr_did,
            None,
            None,
            false,
        )
        .await
        .expect("forward to trust registry");

    let response = await_recognition_response(&env, &client.profile).await;
    assert_eq!(
        response["recognized"],
        json!(true),
        "seeded record recognized"
    );

    tr.shutdown().await;
    env.shutdown().await.ok();
}

// --- Signed record writes over DIDComm ---------------------------------------

use affinidi_messaging_test_mediator::TestUser;
use trust_registry::storage::repository::{TrustRecordAdminRepository, TrustRecordQuery};
use trust_tasks_proof::affinidi::{SignOptions, sign_trust_task};

/// The member record a community writes under `authority`.
fn put_payload(authority: &str) -> Value {
    json!({
        "record": {
            "entity_id": "did:example:member",
            "authority_id": authority,
            "action": "git.commit.sign",
            "resource": "repo",
            "recognized": true,
            "authorized": true,
            "record_type": "authorization"
        }
    })
}

fn member_query(authority: &str) -> TrustRecordQuery {
    TrustRecordQuery::new(
        EntityId::new("did:example:member"),
        AuthorityId::new(authority),
        Action::new("git.commit.sign"),
        Resource::new("repo"),
    )
}

/// A `registry/record/put` issued by `client` and signed with its
/// verification key, as a VTC sends it.
async fn signed_put(client: &TestUser, recipient: &str, authority: &str) -> TrustTask<Value> {
    let mut doc = TrustTask::new(
        format!("urn:uuid:{}", uuid::Uuid::new_v4()),
        type_uris::RECORD_PUT.parse().expect("valid put type uri"),
        put_payload(authority),
    );
    doc.issuer = Some(client.did.clone());
    doc.recipient = Some(recipient.to_string());
    doc.issued_at = Some(chrono::Utc::now());
    let signer = client
        .secrets
        .iter()
        .find(|secret| secret.id.ends_with("#key-1"))
        .expect("the client has a verification key");
    let signed = sign_trust_task(
        &serde_json::to_value(&doc).expect("serialise task"),
        signer,
        SignOptions::new(),
    )
    .await
    .expect("sign the put");
    serde_json::from_value(signed).expect("signed task parses")
}

/// Authcrypt `request` from `client` to the registry and wait for the reply
/// on the same thread.
async fn round_trip(
    env: &TestEnvironment,
    client: &TestUser,
    tr_did: &str,
    request: &TrustTask<Value>,
) -> TrustTask<Value> {
    let body = serde_json::to_value(request).expect("serialise task");
    let message = Message::new(ENVELOPE_TYPE, body)
        .from(client.did.clone())
        .to(vec![tr_did.to_string()])
        .thid(request.id.clone());
    let (packed, _) = env
        .atm
        .pack_encrypted(&message, tr_did, Some(&client.did), None)
        .await
        .expect("pack_encrypted");
    env.atm
        .forward_and_send_message(
            &client.profile,
            false,
            &packed,
            None,
            env.mediator.did(),
            tr_did,
            None,
            None,
            false,
        )
        .await
        .expect("forward to trust registry");

    for _ in 0..40 {
        let fetched = env
            .atm
            .fetch_messages(&client.profile, &FetchOptions::default())
            .await
            .expect("fetch messages");
        for item in fetched.success {
            let Some(packed) = item.msg else { continue };
            let Ok((message, _)) = env.atm.unpack(&packed).await else {
                continue;
            };
            if message.typ != ENVELOPE_TYPE {
                continue;
            }
            let reply: TrustTask<Value> =
                serde_json::from_value(message.body).expect("parse reply task");
            if reply.thread_id.as_deref() == Some(request.id.as_str()) {
                return reply;
            }
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    panic!("no reply to {} within the timeout", request.id);
}

/// The VTC write path: an admin community signs a put under its own DID and
/// sends it authcrypted from that DID. The record lands.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "routed round-trip through the mediator; run with --ignored"]
async fn signed_put_under_own_authority_is_stored_over_didcomm() {
    let env = TestEnvironment::spawn().await.expect("spawn test mediator");
    let client = env.add_user("community").await.expect("add client");
    let tr = TestTrustRegistry::builder()
        .admin_dids(vec![client.did.clone()])
        .spawn_with_mediator(&env.mediator)
        .await
        .expect("spawn trust registry");
    let tr_did = tr.did().expect("tr did").to_string();

    let request = signed_put(&client, &tr_did, &client.did).await;
    let reply = round_trip(&env, &client, &tr_did, &request).await;

    assert!(reply.type_uri.is_response(), "put refused: {reply:?}");
    tr.repository()
        .read(member_query(&client.did))
        .await
        .expect("the record was stored under the community's authority");

    tr.shutdown().await;
    env.shutdown().await.ok();
}

/// The same admin, signing correctly, cannot write under someone else's
/// authority.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "routed round-trip through the mediator; run with --ignored"]
async fn signed_put_under_another_authority_is_refused_over_didcomm() {
    let env = TestEnvironment::spawn().await.expect("spawn test mediator");
    let client = env.add_user("community").await.expect("add client");
    let tr = TestTrustRegistry::builder()
        .admin_dids(vec![client.did.clone()])
        .spawn_with_mediator(&env.mediator)
        .await
        .expect("spawn trust registry");
    let tr_did = tr.did().expect("tr did").to_string();
    let other_authority = "did:example:another-community";

    let request = signed_put(&client, &tr_did, other_authority).await;
    let reply = round_trip(&env, &client, &tr_did, &request).await;

    assert!(!reply.type_uri.is_response(), "put accepted: {reply:?}");
    assert_eq!(reply.payload["code"], json!("permissionDenied"));
    assert!(
        tr.repository()
            .read(member_query(other_authority))
            .await
            .is_err()
    );

    tr.shutdown().await;
    env.shutdown().await.ok();
}

/// Under `--features tsp`, `serve()` additionally starts the TSP receive loop
/// (raw-TSP websocket to the mediator). This asserts that build wires up and
/// still serves; a full routed TSP Trust Task round-trip — which needs the
/// client↔registry TSP VID/service routing — is a follow-up.
#[cfg(feature = "tsp")]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn tsp_enabled_registry_spawns_against_a_mediator() {
    let env = TestEnvironment::spawn().await.expect("spawn test mediator");
    let tr = TestTrustRegistry::builder()
        .record(sample_record())
        .spawn_with_mediator(&env.mediator)
        .await
        .expect("spawn trust registry");
    assert!(tr.did().is_some_and(|d| d.starts_with("did:peer:")));

    let recognition: Value = reqwest::Client::new()
        .post(format!("{}/recognition", tr.base_url()))
        .json(&query_body())
        .send()
        .await
        .expect("recognition request")
        .json()
        .await
        .expect("recognition json");
    assert_eq!(recognition["recognized"], json!(true));

    tr.shutdown().await;
    env.shutdown().await.ok();
}

/// Full routed TSP round-trip: a client sends a recognition Trust Task to the
/// registry over TSP (through the mediator's TSP relay), and the registry —
/// receiving it multiplexed on its single DIDComm pickup socket — dispatches and
/// seals the response back over TSP.
#[cfg(feature = "tsp")]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "routed TSP round-trip through the mediator; run with --ignored"]
async fn recognition_round_trips_over_tsp() {
    let env = TestEnvironment::spawn().await.expect("spawn test mediator");
    let tr = TestTrustRegistry::builder()
        .record(sample_record())
        .spawn_with_mediator(&env.mediator)
        .await
        .expect("spawn trust registry");
    let tr_did = tr.did().expect("tr did").to_string();
    let client = env.add_user("client").await.expect("add client");

    // Give the registry's pickup socket a moment to establish live delivery.
    tokio::time::sleep(Duration::from_secs(2)).await;

    // The TSP binding envelope is `{ type, document }` bytes — and uses the
    // *TSP* binding envelope type, not the DIDComm one.
    let request = build_request(&client.did, &tr_did);
    let envelope = json!({ "type": trust_tasks_tsp::ENVELOPE_TYPE, "document": request });
    let bytes = serde_json::to_vec(&envelope).expect("serialise tsp envelope");
    env.atm
        .tsp()
        .send(&client.profile, &tr_did, &bytes)
        .await
        .expect("tsp send");

    let mut recognized = None;
    for _ in 0..40 {
        let fetched = env
            .atm
            .fetch_messages(&client.profile, &FetchOptions::default())
            .await
            .expect("fetch messages");
        for item in fetched.success {
            let Some(stored) = item.msg else { continue };
            if !env.atm.tsp().is_tsp(&stored) {
                continue;
            }
            let (payload, _sender) = env
                .atm
                .tsp()
                .unpack(&client.profile, &stored)
                .await
                .expect("tsp unpack");
            let envelope: Value = serde_json::from_slice(&payload).expect("parse tsp envelope");
            let task: TrustTask<Value> =
                serde_json::from_value(envelope["document"].clone()).expect("parse response task");
            recognized = Some(task.payload["recognized"] == json!(true));
        }
        if recognized.is_some() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }

    assert_eq!(recognized, Some(true), "seeded record should be recognized");

    tr.shutdown().await;
    env.shutdown().await.ok();
}
