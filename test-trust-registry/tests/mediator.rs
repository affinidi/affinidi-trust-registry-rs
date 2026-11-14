//! Integration tests for the mediator-wired fixture (`--features mediator`).
//!
//! Spawns an `affinidi-messaging-test-mediator` and a Trust Registry whose
//! DIDComm (and, under `--features tsp`, TSP) Trust Task listeners connect to
//! it, then drives Trust Tasks end-to-end: some by building and polling
//! envelopes by hand, and some through `trql-client`'s `DidcommTransport` and
//! `TspTransport`, the transports verifiers use.

#![cfg(feature = "mediator")]
#![allow(clippy::unwrap_used, clippy::expect_used)]

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
        SignOptions::new().with_proof_purpose("authentication"),
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
/// still serves without any routed traffic; the routed TSP round trips are
/// `recognition_round_trips_over_tsp` and
/// `trql_client_queries_the_registry_over_tsp` below (`--ignored`).
#[cfg(feature = "tsp")]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn tsp_enabled_registry_spawns_against_a_mediator() {
    let env = TestEnvironment::spawn().await.expect("spawn test mediator");
    let tr = TestTrustRegistry::builder()
        .record(sample_record())
        .tsp(true)
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

/// Form the TSP relationship Spec Rev 3 §7.2.2 requires before any
/// application message: `client` invites the registry, which accepts any
/// authenticated VID, and `client` records the accept. Without it the
/// registry discards the client's Trust Tasks, as specified.
#[cfg(feature = "tsp")]
async fn relate_with_registry(env: &TestEnvironment, client: &TestUser, tr_did: &str) {
    use affinidi_messaging_sdk::messages::DeleteMessageRequest;

    env.atm
        .tsp()
        .form_relationship(&client.profile, tr_did)
        .await
        .expect("send the relationship invite");
    for _ in 0..40 {
        let inbox = env
            .atm
            .fetch_messages(&client.profile, &FetchOptions::default())
            .await
            .expect("fetch messages");
        if let Some(element) = inbox.success.first()
            && let Some(stored) = element.msg.as_ref()
        {
            // Consume it, so it is not mistaken for a reply later.
            env.atm
                .delete_messages_direct(
                    &client.profile,
                    &DeleteMessageRequest {
                        message_ids: vec![element.msg_id.clone()],
                    },
                )
                .await
                .expect("delete the accept");
            let qb2 = env.atm.tsp().decode(stored).expect("decode the accept");
            let (control, sender, _digest) = env
                .atm
                .tsp()
                .unpack_control(&client.profile, &qb2)
                .await
                .expect("unpack the accept");
            assert_eq!(sender, tr_did, "the accept came from another VID");
            env.atm
                .tsp()
                .record_incoming_control(&client.profile, tr_did, &control)
                .await
                .expect("record the accept");
            return;
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    panic!("the registry did not accept the TSP relationship");
}

/// Full routed TSP round-trip: a client sends a recognition Trust Task to the
/// registry over TSP (through the mediator's TSP relay), and the registry —
/// receiving it multiplexed on its single DIDComm pickup socket — dispatches and
/// seals the response back over TSP.
#[cfg(feature = "tsp")]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "routed TSP round-trip through the mediator; run with --ignored"]
async fn recognition_round_trips_over_tsp() {
    // Client and registry share one mediator, so the request and the reply are
    // TSP Direct deliveries. The fixture's default mediator refuses those
    // (`local_direct_delivery_allowed` off, `e.p.direct_delivery.denied`); the
    // shipped `mediator.toml` allows them, and this test is about the round
    // trip, not that policy.
    let env = TestEnvironment::spawn_with_direct_delivery()
        .await
        .expect("spawn test mediator");
    let tr = TestTrustRegistry::builder()
        .record(sample_record())
        .tsp(true)
        .spawn_with_mediator(&env.mediator)
        .await
        .expect("spawn trust registry");
    let tr_did = tr.did().expect("tr did").to_string();
    let client = env.add_user("client").await.expect("add client");

    // Give the registry's pickup socket a moment to establish live delivery.
    tokio::time::sleep(Duration::from_secs(2)).await;
    relate_with_registry(&env, &client, &tr_did).await;

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

// --- Through the real client (trql-client) -----------------------------------
//
// The tests above build envelopes by hand. These query through `TrqlClient`
// over `DidcommTransport` / `TspTransport`, so what is exercised is what a
// verifier runs: the request the client actually emits, the registry's real
// reply, sender binding, routing of concurrent replies to their own waiters,
// and the 0.2 request the registry answers.

use trql_client::{DidcommTransport, DidcommTransportConfig, TrqlClient, TrqlError, TrqpQuery};

fn seeded_query() -> TrqpQuery {
    TrqpQuery::new("did:example:entity", "did:example:authority", "issue", "vc")
}

fn unknown_query() -> TrqpQuery {
    TrqpQuery::new(
        "did:example:stranger",
        "did:example:authority",
        "issue",
        "vc",
    )
}

/// A `TrqlClient` for `registry_did` over DIDComm from `client`'s profile,
/// which the transport then owns (websocket live delivery switched on).
async fn didcomm_client(
    env: &TestEnvironment,
    client: &TestUser,
    registry_did: &str,
    reply_timeout: Duration,
) -> TrqlClient {
    env.atm
        .profile_enable_websocket(&client.profile)
        .await
        .expect("enable websocket live delivery on the client profile");
    let transport = DidcommTransport::new(
        env.atm.clone(),
        client.profile.clone(),
        DidcommTransportConfig::new().with_reply_timeout(reply_timeout),
    )
    .expect("didcomm transport");
    TrqlClient::new(Arc::new(transport), registry_did).with_client_did(client.did.clone())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "routed round-trip through the mediator; run with --ignored"]
async fn trql_client_queries_the_registry_over_didcomm() {
    let env = TestEnvironment::spawn().await.expect("spawn test mediator");
    let tr = TestTrustRegistry::builder()
        .record(sample_record())
        .spawn_with_mediator(&env.mediator)
        .await
        .expect("spawn trust registry");
    let tr_did = tr.did().expect("tr did").to_string();
    let user = env.add_user("verifier").await.expect("add client");
    let client = didcomm_client(&env, &user, &tr_did, Duration::from_secs(20)).await;

    let authorization = client
        .authorization(seeded_query())
        .await
        .expect("authorization over didcomm");
    assert!(authorization.authorized);
    assert!(
        client
            .recognition(seeded_query())
            .await
            .expect("recognition over didcomm")
            .recognized
    );

    // Two queries in flight on the one transport: each reply reaches its
    // own waiter.
    let (known, unknown) = tokio::join!(
        client.authorization(seeded_query()),
        client.authorization(unknown_query())
    );
    let (known, unknown) = (known.expect("known"), unknown.expect("unknown"));
    assert!(known.authorized);
    assert_eq!(known.entity_id, "did:example:entity");
    assert!(!unknown.authorized);
    assert_eq!(unknown.entity_id, "did:example:stranger");

    tr.shutdown().await;
    env.shutdown().await.ok();
}

/// Wait for the Trust Task request `registry` has been sent, and return it.
async fn await_request(env: &TestEnvironment, registry: &TestUser) -> TrustTask<Value> {
    for _ in 0..40 {
        let fetched = env
            .atm
            .fetch_messages(&registry.profile, &FetchOptions::default())
            .await
            .expect("fetch messages");
        for item in fetched.success {
            let Some(packed) = item.msg else { continue };
            let Ok((message, _)) = env.atm.unpack(&packed).await else {
                continue;
            };
            if message.typ == ENVELOPE_TYPE {
                return serde_json::from_value(message.body).expect("parse request task");
            }
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    panic!("no Trust Task request reached the registry's inbox");
}

/// An authorization `#response` to `request` saying `authorized`.
fn authorization_reply(request: &TrustTask<Value>, authorized: bool) -> TrustTask<Value> {
    let payload = json!({
        "entityId": request.payload["entityId"],
        "authorityId": request.payload["authorityId"],
        "action": request.payload["action"],
        "resource": request.payload["resource"],
        "authorized": authorized,
        "evaluatedAt": chrono::Utc::now(),
    });
    request.respond_with(format!("urn:uuid:{}", uuid::Uuid::new_v4()), payload)
}

/// Send `reply` to `to`, authcrypted with `from`'s own key.
async fn send_reply_as(env: &TestEnvironment, from: &TestUser, to: &str, reply: &TrustTask<Value>) {
    let body = serde_json::to_value(reply).expect("serialise reply");
    let message = Message::new(ENVELOPE_TYPE, body)
        .from(from.did.clone())
        .to(vec![to.to_string()])
        .thid(reply.thread_id.clone().expect("a reply is correlated"));
    let (packed, _) = env
        .atm
        .pack_encrypted(&message, to, Some(&from.did), None)
        .await
        .expect("pack_encrypted");
    env.atm
        .forward_and_send_message(
            &from.profile,
            false,
            &packed,
            None,
            env.mediator.did(),
            to,
            None,
            None,
            false,
        )
        .await
        .expect("forward reply");
}

/// A third identity that learns the request id and answers first, correctly
/// correlated and echoing the tuple, does not answer the query: only the
/// party the request was addressed to can. Here the "registry" is a plain
/// mediator user, so the test decides what each party says: the impostor
/// grants, the registry denies, and the client must report the denial.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "routed round-trip through the mediator; run with --ignored"]
async fn trql_client_ignores_a_reply_from_a_third_identity_over_didcomm() {
    let env = TestEnvironment::spawn().await.expect("spawn test mediator");
    let registry = env.add_user("registry").await.expect("add registry");
    let impostor = env.add_user("impostor").await.expect("add impostor");
    let user = env.add_user("verifier").await.expect("add client");
    let client =
        Arc::new(didcomm_client(&env, &user, &registry.did, Duration::from_secs(20)).await);

    let query = tokio::spawn({
        let client = client.clone();
        async move { client.authorization(seeded_query()).await }
    });
    let request = await_request(&env, &registry).await;
    send_reply_as(
        &env,
        &impostor,
        &user.did,
        &authorization_reply(&request, true),
    )
    .await;
    // Give the forged reply time to arrive (and be discarded) first.
    tokio::time::sleep(Duration::from_secs(2)).await;
    assert!(
        !query.is_finished(),
        "the impostor's reply completed the query"
    );
    send_reply_as(
        &env,
        &registry,
        &user.did,
        &authorization_reply(&request, false),
    )
    .await;

    let answer = query
        .await
        .expect("query task")
        .expect("the registry's answer");
    assert!(!answer.authorized, "the impostor's grant was believed");

    // With only the impostor answering, the query times out. (A fresh
    // verifier: a transport owns its profile's stream exclusively.)
    let user = env.add_user("verifier-2").await.expect("add client");
    let client = didcomm_client(&env, &user, &registry.did, Duration::from_secs(5)).await;
    let query = tokio::spawn(async move { client.authorization(seeded_query()).await });
    let request = await_request(&env, &registry).await;
    send_reply_as(
        &env,
        &impostor,
        &user.did,
        &authorization_reply(&request, true),
    )
    .await;
    let result = query.await.expect("query task");
    assert!(
        matches!(result, Err(TrqlError::Timeout { .. })),
        "expected a timeout, got {result:?}"
    );

    env.shutdown().await.ok();
}

/// The same client over TSP: the registry's TSP binding, through the
/// mediator's TSP relay, to `TspTransport`'s demux.
#[cfg(feature = "tsp")]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "routed TSP round-trip through the mediator; run with --ignored"]
async fn trql_client_queries_the_registry_over_tsp() {
    use trql_client::{TspTransport, TspTransportConfig};

    // Client and registry share one mediator: direct delivery, as in
    // `recognition_round_trips_over_tsp`.
    let env = TestEnvironment::spawn_with_direct_delivery()
        .await
        .expect("spawn test mediator");
    let tr = TestTrustRegistry::builder()
        .record(sample_record())
        .tsp(true)
        .spawn_with_mediator(&env.mediator)
        .await
        .expect("spawn trust registry");
    let tr_did = tr.did().expect("tr did").to_string();
    let user = env.add_user("verifier").await.expect("add client");
    // Give the registry's pickup socket a moment to establish live delivery.
    tokio::time::sleep(Duration::from_secs(2)).await;
    // Before the transport owns the profile's stream: the accept is read
    // from the inbox here.
    relate_with_registry(&env, &user, &tr_did).await;
    env.atm
        .profile_enable_websocket(&user.profile)
        .await
        .expect("enable websocket live delivery on the client profile");

    let transport = TspTransport::new(
        env.atm.clone(),
        user.profile.clone(),
        TspTransportConfig::new().with_reply_timeout(Duration::from_secs(20)),
    )
    .expect("tsp transport");
    let client = TrqlClient::new(Arc::new(transport), &tr_did).with_client_did(user.did.clone());

    let (known, unknown) = tokio::join!(
        client.recognition(seeded_query()),
        client.recognition(unknown_query())
    );
    let (known, unknown) = (known.expect("known"), unknown.expect("unknown"));
    assert!(known.recognized);
    assert_eq!(known.entity_id, "did:example:entity");
    assert!(!unknown.recognized);

    tr.shutdown().await;
    env.shutdown().await.ok();
}
