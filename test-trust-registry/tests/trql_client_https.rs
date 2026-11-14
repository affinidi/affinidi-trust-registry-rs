//! `trql-client`'s HTTPS transport against the real registry: the request
//! documents the client emits are the ones the registry's `POST /trust-tasks`
//! accepts, and the answers come back through every check the client makes.
//!
//! Runs without a mediator (plain `cargo test -p test-trust-registry`).

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::sync::Arc;

use chrono::{DateTime, Utc};
use test_trust_registry::{TestTrustRegistry, TestTrustRegistryHandle};
use trql_client::{
    HttpsTransport, HttpsTransportConfig, SpecVersion, TrqlClient, TrqlError, TrqpQuery,
};
use trust_registry::domain::{
    Action, AuthorityId, EntityId, RecordType, Resource, TrustRecord, TrustRecordBuilder,
};

const REGISTRY_DID: &str = "did:example:test-registry";

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

async fn registry() -> TestTrustRegistryHandle {
    TestTrustRegistry::builder()
        .did(REGISTRY_DID)
        .record(sample_record())
        .spawn()
        .await
        .expect("spawn trust registry")
}

fn client_for(tr: &TestTrustRegistryHandle) -> TrqlClient {
    // The fixture listens on loopback, which the transport refuses unless
    // told the base URL is trusted.
    let config = HttpsTransportConfig::new(tr.base_url()).with_allow_non_public_addresses(true);
    let transport = HttpsTransport::new(config).expect("https transport");
    TrqlClient::new(Arc::new(transport), REGISTRY_DID)
}

fn seeded() -> TrqpQuery {
    TrqpQuery::new("did:example:entity", "did:example:authority", "issue", "vc")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_client_queries_the_real_registry_over_https() {
    let tr = registry().await;
    let client = client_for(&tr);

    let authorization = client.authorization(seeded()).await.expect("authorization");
    assert!(authorization.authorized);
    assert_eq!(authorization.version, SpecVersion::V0_2);
    assert_eq!(authorization.entity_id, "did:example:entity");

    let recognition = client.recognition(seeded()).await.expect("recognition");
    assert!(recognition.recognized);

    // No record: a denial, not an error.
    let unknown = client
        .authorization(TrqpQuery::new(
            "did:example:stranger",
            "did:example:authority",
            "issue",
            "vc",
        ))
        .await
        .expect("an unknown tuple is answered");
    assert!(!unknown.authorized);

    tr.shutdown().await;
}

/// The registry echoes the evaluation time it was asked for, so the client's
/// `as_of` check accepts its answer.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_historical_query_is_answered_for_the_time_asked() {
    let tr = registry().await;
    let at: DateTime<Utc> = Utc::now() - chrono::Duration::minutes(1);
    let answer = client_for(&tr)
        .authorization(seeded().at(at))
        .await
        .expect("historical authorization");
    assert_eq!(answer.as_of, Some(at));
    tr.shutdown().await;
}

/// Two queries in flight on one client each get their own answer.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn concurrent_queries_get_their_own_answers() {
    let tr = registry().await;
    let client = client_for(&tr);
    let stranger = TrqpQuery::new(
        "did:example:stranger",
        "did:example:authority",
        "issue",
        "vc",
    );
    let (known, unknown) = tokio::join!(
        client.authorization(seeded()),
        client.authorization(stranger)
    );
    let (known, unknown) = (known.expect("known"), unknown.expect("unknown"));
    assert!(known.authorized);
    assert_eq!(known.entity_id, "did:example:entity");
    assert!(!unknown.authorized);
    assert_eq!(unknown.entity_id, "did:example:stranger");
    tr.shutdown().await;
}

/// A document addressed to another registry is refused by this one, and the
/// client reports the refusal as the registry's rejection.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_query_addressed_to_another_registry_is_rejected() {
    let tr = registry().await;
    let config = HttpsTransportConfig::new(tr.base_url()).with_allow_non_public_addresses(true);
    let client = TrqlClient::new(
        Arc::new(HttpsTransport::new(config).expect("https transport")),
        "did:example:some-other-registry",
    );
    let err = client.authorization(seeded()).await.unwrap_err();
    assert!(matches!(err, TrqlError::Rejected { .. }), "{err}");
    tr.shutdown().await;
}
