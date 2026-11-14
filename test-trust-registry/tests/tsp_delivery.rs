//! A TSP-enabled registry (`transport_flags.tsp`) against a test mediator
//! (`--features tsp`): it receives on the delivery-layer path
//! (`trust_registry::messaging::service`), and must still answer DIDComm, and
//! release its mediator socket and messaging store when it shuts down.
//!
//! `#[ignore]`d like the other routed tests (the test mediator needs Redis):
//!
//! ```text
//! cargo test -p test-trust-registry --features tsp --test tsp_delivery -- --ignored
//! ```

#![cfg(feature = "tsp")]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use affinidi_messaging_sdk::messages::fetch::FetchOptions;
use affinidi_messaging_test_mediator::{TestEnvironment, TestMediatorUser, TestUser};
use affinidi_tdk::didcomm::Message;
use affinidi_tdk::messaging::protocols::mediator::acls::AccessListModeType;
use serde_json::{Value, json};
use tokio_util::sync::CancellationToken;
use trust_registry::configs::storage::StorageConfig;
use trust_registry::configs::{
    AdminConfig, DidcommConfig, ProfileConfig, ServerConfig, TrustRegistryConfig,
};
use trust_registry::domain::{
    Action, AuthorityId, EntityId, RecordType, Resource, TrustRecord, TrustRecordBuilder,
};
use trust_registry::health::WriteStatus;
use trust_registry::server::{ServerHandle, serve};
use trust_registry::storage::adapters::local_storage::LocalStorage;
use trust_registry::storage::repository::TrustRecordAdminRepository;
use trust_registry::trust_tasks::payloads::type_uris;
use trust_tasks_didcomm::ENVELOPE_TYPE;
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

/// A registry with TSP enabled, as `TestTrustRegistryBuilder::spawn_with_mediator`
/// builds one but with `transport_flags.tsp` set and its messaging store at
/// `store`.
async fn spawn_tsp_registry(
    env: &TestEnvironment,
    identity: &TestMediatorUser,
    store: &Path,
) -> ServerHandle {
    let repository = Arc::new(LocalStorage::with_records(vec![sample_record()]).unwrap());
    let mut didcomm_config = DidcommConfig {
        is_enabled: true,
        acl_mode: AccessListModeType::ExplicitDeny,
        profile_config: ProfileConfig {
            did: identity.did.clone(),
            alias: "Trust Registry".to_string(),
            secrets: identity.secrets.clone(),
        },
        mediator_did: env.mediator.did().to_string(),
        admin_config: AdminConfig::default(),
        messaging_store_path: Some(store.to_path_buf()),
        ..Default::default()
    };
    didcomm_config.transport_flags.tsp = true;
    let config = Arc::new(TrustRegistryConfig {
        server_config: ServerConfig {
            listen_address: "127.0.0.1:0".to_string(),
            ..Default::default()
        },
        storage_config: StorageConfig::default(),
        didcomm_config,
    });
    let repository: Arc<dyn TrustRecordAdminRepository> = repository;
    serve(config, repository, CancellationToken::new())
        .await
        .expect("serve the registry")
}

/// Send a `trqp` recognition query over DIDComm and wait for the reply on its
/// thread.
async fn recognition_over_didcomm(env: &TestEnvironment, client: &TestUser, tr_did: &str) -> Value {
    let mut request = TrustTask::new(
        format!("urn:uuid:{}", uuid::Uuid::new_v4()),
        type_uris::RECOGNITION.parse().expect("valid type uri"),
        json!({
            "entity_id": "did:example:entity",
            "authority_id": "did:example:authority",
            "action": "issue",
            "resource": "vc"
        }),
    );
    request.issuer = Some(client.did.clone());
    request.recipient = Some(tr_did.to_string());
    request.issued_at = Some(chrono::Utc::now());

    let message = Message::new(ENVELOPE_TYPE, serde_json::to_value(&request).unwrap())
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
            let reply: TrustTask<Value> = serde_json::from_value(message.body).unwrap();
            if reply.thread_id.as_deref() == Some(request.id.as_str()) {
                return reply.payload;
            }
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    panic!("no DIDComm reply from the TSP-enabled registry within the timeout");
}

/// A TSP-enabled registry answers DIDComm: the delivery-layer path used to
/// take messages off the socket before anything consumed them, and answered
/// none until a reconnect. Shut down and rebuilt in the same process with the
/// same DID and store, it answers again: the first instance released its
/// mediator socket and closed its messaging store.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "routed round-trip through the mediator; run with --ignored"]
async fn a_tsp_enabled_registry_answers_didcomm_and_can_be_rebuilt() {
    let env = TestEnvironment::spawn().await.expect("spawn test mediator");
    let identity = env
        .mediator
        .add_user("trust-registry")
        .await
        .expect("mint the registry identity");
    let client = env.add_user("client").await.expect("add client");
    let store = std::env::temp_dir().join(format!("tr-tsp-delivery-{}", uuid::Uuid::new_v4()));

    let first = spawn_tsp_registry(&env, &identity, &store).await;
    let reply = recognition_over_didcomm(&env, &client, &identity.did).await;
    assert_eq!(reply["recognized"], json!(true), "first instance");
    first.shutdown().await;

    let second = spawn_tsp_registry(&env, &identity, &store).await;
    let reply = recognition_over_didcomm(&env, &client, &identity.did).await;
    assert_eq!(reply["recognized"], json!(true), "rebuilt instance");
    assert_eq!(
        second.health().write_status(),
        WriteStatus::Ok,
        "the rebuilt instance's listener failed: {}",
        second.health().to_json()
    );
    second.shutdown().await;

    env.shutdown().await.ok();
    std::fs::remove_dir_all(&store).ok();
}
