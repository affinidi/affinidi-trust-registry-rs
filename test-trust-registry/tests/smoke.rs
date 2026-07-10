//! End-to-end smoke test for the embedded fixture: spawn, drive the REST/TRQP
//! surface over an in-memory store, and shut down — all in-process, no env vars.

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

#[tokio::test]
async fn health_endpoint_is_ok() {
    let tr = TestTrustRegistry::spawn().await.expect("spawns");
    let resp = reqwest::get(format!("{}/health", tr.base_url()))
        .await
        .expect("health request");
    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.expect("json");
    assert_eq!(body, json!({ "status": "OK" }));
    tr.shutdown().await;
}

#[tokio::test]
async fn recognition_and_authorization_against_a_seeded_record() {
    let tr = TestTrustRegistry::with_records(vec![sample_record()])
        .await
        .expect("spawns");
    let client = reqwest::Client::new();

    let recognition: Value = client
        .post(format!("{}/recognition", tr.base_url()))
        .json(&query_body())
        .send()
        .await
        .expect("recognition request")
        .json()
        .await
        .expect("recognition json");
    assert_eq!(recognition["recognized"], json!(true));

    let authorization: Value = client
        .post(format!("{}/authorization", tr.base_url()))
        .json(&query_body())
        .send()
        .await
        .expect("authorization request")
        .json()
        .await
        .expect("authorization json");
    assert_eq!(authorization["authorized"], json!(true));

    tr.shutdown().await;
}

#[tokio::test]
async fn unknown_record_is_not_found() {
    let tr = TestTrustRegistry::spawn().await.expect("spawns");
    let resp = reqwest::Client::new()
        .post(format!("{}/recognition", tr.base_url()))
        .json(&query_body())
        .send()
        .await
        .expect("recognition request");
    assert_eq!(resp.status(), 404);
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

    let recognition = reqwest::Client::new()
        .post(format!("{}/recognition", tr.base_url()))
        .json(&query_body())
        .send()
        .await
        .expect("recognition request");
    assert_eq!(recognition.status(), 200);
    tr.shutdown().await;
}
