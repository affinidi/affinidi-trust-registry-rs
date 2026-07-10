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
