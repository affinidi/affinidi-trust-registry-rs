//! End-to-end smoke test for the embedded fixture: spawn, drive the Trust Task
//! queries over the HTTPS binding (`POST /trust-tasks`) against an in-memory
//! store, and shut down — all in-process, no env vars.

use serde_json::{Value, json};
use test_trust_registry::TestTrustRegistry;
use trust_registry::domain::{
    Action, AuthorityId, EntityId, RecordType, Resource, TrustRecord, TrustRecordBuilder,
};
use trust_registry::trust_tasks::type_uris;
use trust_tasks_rs::TrustTask;

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

/// An anonymous query Trust Task of `type_uri` for the sample record's tuple.
fn query_task(type_uri: &str) -> Value {
    let doc = TrustTask::new(
        format!("urn:uuid:{}", uuid::Uuid::new_v4()),
        type_uri.parse().expect("valid type uri"),
        json!({
            "entity_id": "did:example:entity",
            "authority_id": "did:example:authority",
            "action": "issue",
            "resource": "vc"
        }),
    );
    serde_json::to_value(doc).expect("serialise task")
}

/// `POST /trust-tasks` and return the reply document, asserting a 200.
async fn post_task(base_url: &str, body: &Value) -> TrustTask<Value> {
    let resp = reqwest::Client::new()
        .post(format!("{base_url}/trust-tasks"))
        .json(body)
        .send()
        .await
        .expect("trust-tasks request");
    assert_eq!(resp.status(), 200);
    resp.json().await.expect("reply document")
}

#[tokio::test]
async fn health_endpoint_is_ok() {
    let tr = TestTrustRegistry::spawn().await.expect("spawns");
    let resp = reqwest::get(format!("{}/health", tr.base_url()))
        .await
        .expect("health request");
    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.expect("json");
    // `spawn()` runs without DIDComm, so the write path is deliberately off
    // rather than broken — that must read as healthy, not degraded.
    assert_eq!(body, json!({ "status": "OK", "writes": "disabled" }));
    tr.shutdown().await;
}

#[tokio::test]
async fn registry_recognition_over_https() {
    let tr = TestTrustRegistry::with_records(vec![sample_record()])
        .await
        .expect("spawns");

    let reply = post_task(&tr.base_url(), &query_task(type_uris::RECOGNITION)).await;
    assert!(reply.type_uri.is_response(), "refused: {reply:?}");
    assert_eq!(reply.type_uri.slug(), "registry/recognition");
    assert_eq!(reply.payload["entity_id"], json!("did:example:entity"));
    assert_eq!(reply.payload["recognized"], json!(true));

    tr.shutdown().await;
}

#[tokio::test]
async fn registry_authorization_over_https() {
    let tr = TestTrustRegistry::with_records(vec![sample_record()])
        .await
        .expect("spawns");

    let reply = post_task(&tr.base_url(), &query_task(type_uris::AUTHORIZATION)).await;
    assert!(reply.type_uri.is_response(), "refused: {reply:?}");
    assert_eq!(reply.type_uri.slug(), "registry/authorization");
    assert_eq!(reply.payload["authorized"], json!(true));

    tr.shutdown().await;
}

/// Absence is a denial, not an error.
#[tokio::test]
async fn registry_recognition_over_https_of_an_unknown_record_is_false() {
    let tr = TestTrustRegistry::spawn().await.expect("spawns");
    let reply = post_task(&tr.base_url(), &query_task(type_uris::RECOGNITION)).await;
    assert_eq!(reply.payload["recognized"], json!(false));
    tr.shutdown().await;
}

/// The raw TRQP REST routes are gone: Trust Tasks are the only query surface.
#[tokio::test]
async fn legacy_trqp_rest_routes_are_not_served() {
    let tr = TestTrustRegistry::with_records(vec![sample_record()])
        .await
        .expect("spawns");
    let client = reqwest::Client::new();
    for path in ["recognition", "authorization"] {
        let resp = client
            .post(format!("{}/{path}", tr.base_url()))
            .json(&json!({
                "entity_id": "did:example:entity",
                "authority_id": "did:example:authority",
                "action": "issue",
                "resource": "vc"
            }))
            .send()
            .await
            .expect("request");
        assert_eq!(resp.status(), 404, "/{path} is still served");
    }
    tr.shutdown().await;
}

#[tokio::test]
async fn seeding_after_spawn_is_visible_to_the_server() {
    use trust_registry::storage::repository::TrustRecordAdminRepository;

    let tr = TestTrustRegistry::spawn().await.expect("spawns");
    // The handle's repository is the same store the server reads from.
    tr.repository()
        .create(sample_record())
        .await
        .expect("seed record");

    let reply = post_task(&tr.base_url(), &query_task(type_uris::RECOGNITION)).await;
    assert_eq!(reply.payload["recognized"], json!(true));
    tr.shutdown().await;
}
