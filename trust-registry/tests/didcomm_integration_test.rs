// Test code: a panic on an unexpected `Err`/`None` is the failure report.
#![allow(clippy::unwrap_used, clippy::expect_used)]
// The `registry/record/*` 0.1 types are superseded (deprecated); the registry
// still serves them and these tests speak them on purpose.
#![allow(deprecated)]

use affinidi_tdk::messaging::tasks::messaging::account::update::v0_2::{
    MediatorAcl, MediatorAclAccessListMode,
};
use affinidi_tdk::{
    didcomm::Message,
    messaging::{
        ATM,
        messages::{DeleteMessageRequest, FetchDeletePolicy, fetch::FetchOptions},
        profiles::ATMProfile,
    },
    secrets_resolver::secrets::{KeyType, Secret},
};
use serde_json::{Value, json};
use serial_test::serial;
use sha256::digest;
use std::{env, sync::Arc, time::Duration};
use tokio::sync::OnceCell;
use trust_registry::{
    didcomm::{
        handlers::trqp::{QUERY_RECOGNITION_MESSAGE_TYPE, QUERY_RECOGNITION_RESPONSE_MESSAGE_TYPE},
        prepare_atm_and_profile,
    },
    specs::registry::record::put::v0_1 as put_spec,
    trust_tasks::payloads::{
        RecordDeleteRequest, RecordPutRequest, RecordPutResponse, RecordQueryRequest,
        RecordQueryResponse,
    },
};
use trust_tasks_didcomm::ENVELOPE_TYPE;
use trust_tasks_proof::affinidi::{CryptoSuite, SignOptions, sign_trust_task};
use trust_tasks_rs::{ErrorPayload, Payload, TrustTask};
use uuid::Uuid;

static TEST_CONTEXT: OnceCell<Arc<TestConfig>> = OnceCell::const_new();
static CLEAR_MESSAGES: OnceCell<()> = OnceCell::const_new();

pub const ENTITY_ID: &str = "did:example:entityYW";
pub const ACTION: &str = "action";
pub const RESOURCE: &str = "resource";
pub const OTHER_AUTHORITY: &str = "did:example:another-community";

const TR_ADMIN_CREATE_RECORD: &str =
    "https://affinidi.com/didcomm/protocols/tr-admin/1.0/create-record";

const INITIAL_FETCH_LIMIT: usize = 100;
const REPLY_ATTEMPTS: u64 = 6;
const MESSAGE_WAIT_DURATION_SECS: u64 = 2;
const PIPELINE_MESSAGE_WAIT_DURATION_SECS: u64 = 5;

pub struct TestConfig {
    pub client_did: String,
    pub client_secrets: String,
    pub trust_registry_did: String,
    pub message_wait_duration_secs: u64,
}

pub struct AtmTestContext {
    pub atm: Arc<ATM>,
    pub profile: Arc<ATMProfile>,
}

async fn get_test_context() -> (AtmTestContext, Arc<TestConfig>) {
    dotenvy::from_filename(".env.test").ok();
    let client_did = env::var("CLIENT_DID").expect("CLIENT_DID not set in .env.test");
    let client_secrets = env::var("CLIENT_SECRETS").expect("CLIENT_SECRETS not set in .env.test");
    let mediator_did = env::var("MEDIATOR_DID").expect("MEDIATOR_DID not set in .env.test");
    let in_pipeline = env::var("IN_PIPELINE")
        .unwrap_or("false".to_string())
        .to_lowercase()
        == "true";
    let trust_registry_did =
        env::var("TRUST_REGISTRY_DID").expect("TRUST_REGISTRY_DID not set in .env");
    let message_wait_duration_secs = if in_pipeline {
        PIPELINE_MESSAGE_WAIT_DURATION_SECS
    } else {
        MESSAGE_WAIT_DURATION_SECS
    };

    let (atm, profile) = setup_test_environment(&client_did, &client_secrets, &mediator_did).await;

    (
        AtmTestContext { atm, profile },
        TEST_CONTEXT
            .get_or_init(|| async {
                Arc::new(TestConfig {
                    client_did,
                    client_secrets,
                    trust_registry_did,
                    message_wait_duration_secs,
                })
            })
            .await
            .clone(),
    )
}

async fn setup_test_environment(
    client_did: &str,
    secrets: &str,
    mediator_did: &str,
) -> (Arc<ATM>, Arc<ATMProfile>) {
    let secrets: Vec<Secret> = serde_json::from_str(secrets).unwrap();
    let (atm, profile) =
        prepare_atm_and_profile("test-client", client_did, mediator_did, secrets, true)
            .await
            .unwrap();

    atm.trust_ping()
        .send_ping(&profile, mediator_did, true, true, true)
        .await
        .unwrap();

    tokio::time::sleep(Duration::from_secs(1)).await;

    // Put the client account on a denylist (empty = allow everyone) so the
    // registry's replies reach it. `messaging/account/update` carries a partial
    // ACL, so this names the one flag it changes and leaves the rest alone.
    let acl: MediatorAcl = MediatorAcl::builder()
        .access_list_mode(Some(MediatorAclAccessListMode::ExplicitDeny))
        .try_into()
        .expect("valid acl update");

    atm.trust_tasks()
        .account_update(
            &profile,
            Some(digest(&profile.inner.did)),
            None,
            Some(acl),
            None,
        )
        .await
        .unwrap();

    clear_messages(&atm, &profile).await;

    (atm, profile)
}

async fn clear_messages(atm: &Arc<ATM>, profile: &Arc<ATMProfile>) {
    CLEAR_MESSAGES
        .get_or_init(|| async {
            atm.fetch_messages(
                profile,
                &FetchOptions {
                    limit: INITIAL_FETCH_LIMIT,
                    start_id: None,
                    delete_policy: FetchDeletePolicy::Optimistic,
                },
            )
            .await
            .unwrap();
        })
        .await;
}

/// The client's verification key: the one a registry write is signed with.
fn signing_key(config: &TestConfig) -> Secret {
    let secrets: Vec<Secret> = serde_json::from_str(&config.client_secrets).unwrap();
    secrets
        .into_iter()
        .find(|secret| secret.id.ends_with("#key-1"))
        .expect("the client has a verification key")
}

/// The four-part key of the test's record: entity, authority, action,
/// resource.
fn key_parts(test_name: &str, authority: &str) -> [String; 4] {
    [
        format!("{ENTITY_ID}_{test_name}"),
        authority.to_string(),
        format!("{ACTION}_{test_name}"),
        format!("{RESOURCE}_{test_name}"),
    ]
}

/// The legacy TRQP-over-DIDComm query body (not a Trust Task).
fn trqp_body(test_name: &str, authority: &str) -> Value {
    let [entity_id, authority_id, action, resource] = key_parts(test_name, authority);
    json!({
        "entity_id": entity_id,
        "authority_id": authority_id,
        "action": action,
        "resource": resource,
    })
}

fn record(test_name: &str, authority: &str, granted: bool) -> put_spec::TrustRecord {
    let [entity_id, authority_id, action, resource] = key_parts(test_name, authority);
    put_spec::TrustRecord::builder()
        .entity_id(entity_id)
        .authority_id(authority_id)
        .action(action)
        .resource(resource)
        .recognized(Some(granted))
        .authorized(Some(granted))
        .record_type(put_spec::RecordType::Authorization)
        .context(serde_json::Map::from_iter([
            ("description".to_string(), json!("Test credential type")),
            ("version".to_string(), json!("1.0")),
            ("tags".to_string(), json!(["test", "demo"])),
        ]))
        .try_into()
        .expect("valid record")
}

/// `registry/record/put/0.1` of the test's record.
fn put_request(test_name: &str, authority: &str, granted: bool) -> RecordPutRequest {
    RecordPutRequest::builder()
        .record(record(test_name, authority, granted))
        .try_into()
        .expect("valid put")
}

/// `registry/record/query/0.1`: an exact fetch of the test's record.
fn query_request(test_name: &str, authority: &str) -> RecordQueryRequest {
    let [entity_id, authority_id, action, resource] = key_parts(test_name, authority);
    RecordQueryRequest::builder()
        .entity_id(Some(entity_id))
        .authority_id(Some(authority_id))
        .action(Some(action))
        .resource(Some(resource))
        .try_into()
        .expect("valid query")
}

/// `registry/record/delete/0.1` of the test's record.
fn delete_request(test_name: &str, authority: &str) -> RecordDeleteRequest {
    let [entity_id, authority_id, action, resource] = key_parts(test_name, authority);
    RecordDeleteRequest::builder()
        .entity_id(entity_id)
        .authority_id(authority_id)
        .action(action)
        .resource(resource)
        .try_into()
        .expect("valid delete")
}

/// A success reply's payload as the generated response type.
fn parse<R: Payload>(reply: &TrustTask<Value>) -> R {
    assert!(reply.type_uri.is_response(), "refused: {reply:?}");
    serde_json::from_value(reply.payload.clone()).expect("the reply parses as its response type")
}

/// A Trust Task from the client to the registry, signed with the client's
/// verification key when `sign` is set. The document's `type` is the
/// generated payload's Type URI.
async fn trust_task<P: Payload>(config: &TestConfig, payload: P, sign: bool) -> TrustTask<Value> {
    let mut doc = TrustTask::new(
        format!("urn:uuid:{}", Uuid::new_v4()),
        P::type_uri(),
        serde_json::to_value(payload).unwrap(),
    );
    doc.issuer = Some(config.client_did.clone());
    doc.recipient = Some(config.trust_registry_did.clone());
    doc.issued_at = Some(chrono::Utc::now());
    if !sign {
        return doc;
    }

    let key = signing_key(config);
    let cryptosuite = match key.get_key_type() {
        KeyType::Ed25519 => CryptoSuite::EddsaJcs2022,
        _ => CryptoSuite::EcdsaJcs2019,
    };
    let signed = sign_trust_task(
        &serde_json::to_value(&doc).unwrap(),
        &key,
        SignOptions::new()
            .with_cryptosuite(cryptosuite)
            .with_proof_purpose("authentication"),
    )
    .await
    .expect("sign the Trust Task");
    serde_json::from_value(signed).unwrap()
}

/// Send `doc` to the registry and wait for the reply on its thread.
async fn round_trip(
    context: &AtmTestContext,
    config: &TestConfig,
    doc: &TrustTask<Value>,
) -> TrustTask<Value> {
    send_message(
        &context.atm,
        context.profile.clone(),
        &config.trust_registry_did,
        &serde_json::to_value(doc).unwrap(),
        ENVELOPE_TYPE,
        Some(&doc.id),
    )
    .await
    .unwrap();
    tokio::time::sleep(Duration::from_secs(config.message_wait_duration_secs)).await;

    let reply = fetch_reply(&context.atm, &context.profile, |message| {
        message.typ == ENVELOPE_TYPE
            && message.body.get("threadId").and_then(Value::as_str) == Some(doc.id.as_str())
    })
    .await
    .unwrap_or_else(|| panic!("no reply to {}", doc.id));
    serde_json::from_value(reply).unwrap()
}

/// The error code of a `trust-task-error` reply, read through the
/// framework's error payload type.
fn error_code(reply: &TrustTask<Value>) -> Option<String> {
    if reply.type_uri.is_response() {
        return None;
    }
    serde_json::from_value::<ErrorPayload>(reply.payload.clone())
        .ok()
        .map(|error| error.code.to_string())
}

async fn put(
    context: &AtmTestContext,
    config: &TestConfig,
    test_name: &str,
    authority: &str,
    granted: bool,
) -> TrustTask<Value> {
    let doc = trust_task(config, put_request(test_name, authority, granted), true).await;
    round_trip(context, config, &doc).await
}

async fn query(
    context: &AtmTestContext,
    config: &TestConfig,
    test_name: &str,
    authority: &str,
) -> TrustTask<Value> {
    let doc = trust_task(config, query_request(test_name, authority), true).await;
    round_trip(context, config, &doc).await
}

async fn delete_messages(atm: &Arc<ATM>, profile: &Arc<ATMProfile>, message_ids: Vec<String>) {
    let _ = atm
        .delete_messages_direct(profile, &DeleteMessageRequest { message_ids })
        .await;
}

/// Poll the client's inbox for a message `wanted` accepts and return its body,
/// deleting it. `None` if none arrives within the retry budget.
async fn fetch_reply(
    atm: &Arc<ATM>,
    profile: &Arc<ATMProfile>,
    wanted: impl Fn(&Message) -> bool,
) -> Option<Value> {
    for attempt in 0..REPLY_ATTEMPTS {
        tokio::time::sleep(Duration::from_secs(attempt)).await;
        let fetched = atm
            .fetch_messages(
                profile,
                &FetchOptions {
                    limit: INITIAL_FETCH_LIMIT,
                    start_id: None,
                    delete_policy: FetchDeletePolicy::DoNotDelete,
                },
            )
            .await
            .ok()?;

        for element in &fetched.success {
            let Some(packed) = &element.msg else { continue };
            let Ok((message, meta)) = atm.unpack(packed).await else {
                continue;
            };
            if wanted(&message) {
                delete_messages(atm, profile, vec![meta.sha256_hash.clone()]).await;
                return Some(message.body);
            }
        }
    }
    None
}

/// The VTC write path: a signed put under the client's own DID, then an
/// exact fetch of what was stored.
#[tokio::test]
#[serial]
async fn test_signed_put_under_own_authority_is_stored() {
    let (context, config) = get_test_context().await;

    let reply = put(&context, &config, "put", &config.client_did, true).await;
    let ack: RecordPutResponse = parse(&reply);
    assert!(ack.ok);

    let reply = query(&context, &config, "put", &config.client_did).await;
    let answer: RecordQueryResponse = parse(&reply);
    let stored = &answer.records[0];
    assert_eq!(stored.entity_id, format!("{ENTITY_ID}_put"));
    assert_eq!(stored.authority_id, config.client_did);
    assert_eq!(stored.recognized, Some(true));
    assert_eq!(stored.authorized, Some(true));
}

#[tokio::test]
#[serial]
async fn test_signed_put_replaces_an_existing_record() {
    let (context, config) = get_test_context().await;

    put(&context, &config, "update", &config.client_did, true).await;
    let reply = put(&context, &config, "update", &config.client_did, false).await;
    let ack: RecordPutResponse = parse(&reply);
    assert!(!ack.created);

    let reply = query(&context, &config, "update", &config.client_did).await;
    let answer: RecordQueryResponse = parse(&reply);
    assert_eq!(answer.records[0].recognized, Some(false));
    assert_eq!(answer.records[0].authorized, Some(false));
}

#[tokio::test]
#[serial]
async fn test_signed_delete_removes_the_record() {
    let (context, config) = get_test_context().await;

    put(&context, &config, "delete", &config.client_did, true).await;
    let delete = trust_task(&config, delete_request("delete", &config.client_did), true).await;
    let reply = round_trip(&context, &config, &delete).await;
    assert!(reply.type_uri.is_response(), "delete refused: {reply:?}");

    let reply = query(&context, &config, "delete", &config.client_did).await;
    assert!(
        !reply.type_uri.is_response(),
        "the record should be gone: {reply:?}"
    );
}

#[tokio::test]
#[serial]
async fn test_put_under_another_authority_is_refused() {
    let (context, config) = get_test_context().await;

    let reply = put(&context, &config, "foreign", OTHER_AUTHORITY, true).await;
    assert_eq!(error_code(&reply).as_deref(), Some("permissionDenied"));

    // Records under another authority cannot be read back either.
    let reply = query(&context, &config, "foreign", OTHER_AUTHORITY).await;
    assert_eq!(error_code(&reply).as_deref(), Some("permissionDenied"));
}

#[tokio::test]
#[serial]
async fn test_delete_under_another_authority_is_refused() {
    let (context, config) = get_test_context().await;

    let delete = trust_task(
        &config,
        delete_request("foreign-delete", OTHER_AUTHORITY),
        true,
    )
    .await;
    let reply = round_trip(&context, &config, &delete).await;
    assert_eq!(error_code(&reply).as_deref(), Some("permissionDenied"));
}

#[tokio::test]
#[serial]
async fn test_unsigned_record_query_is_refused() {
    let (context, config) = get_test_context().await;

    put(
        &context,
        &config,
        "unsigned-query",
        &config.client_did,
        true,
    )
    .await;
    let doc = trust_task(
        &config,
        query_request("unsigned-query", &config.client_did),
        false,
    )
    .await;
    let reply = round_trip(&context, &config, &doc).await;
    assert_eq!(error_code(&reply).as_deref(), Some("proofRequired"));
}

#[tokio::test]
#[serial]
async fn test_unsigned_put_is_refused() {
    let (context, config) = get_test_context().await;

    let doc = trust_task(
        &config,
        put_request("unsigned", &config.client_did, true),
        false,
    )
    .await;
    let reply = round_trip(&context, &config, &doc).await;
    assert_eq!(error_code(&reply).as_deref(), Some("proofRequired"));
}

/// The legacy `tr-admin/1.0` record protocol is no longer served: a
/// create-record from an admin gets no answer and stores nothing.
#[tokio::test]
#[serial]
async fn test_tr_admin_create_record_is_not_served() {
    let (context, config) = get_test_context().await;

    send_message(
        &context.atm,
        context.profile.clone(),
        &config.trust_registry_did,
        // The retired tr-admin/1.0 body carried the record's snake_case
        // members, which is what the 0.1 wire record serialises to.
        &serde_json::to_value(record("tr-admin", &config.client_did, true)).unwrap(),
        TR_ADMIN_CREATE_RECORD,
        None,
    )
    .await
    .unwrap();
    tokio::time::sleep(Duration::from_secs(config.message_wait_duration_secs)).await;

    let answered = fetch_reply(&context.atm, &context.profile, |message| {
        message.typ.starts_with(TR_ADMIN_CREATE_RECORD)
    })
    .await;
    assert!(answered.is_none(), "tr-admin/1.0 answered: {answered:?}");

    let reply = query(&context, &config, "tr-admin", &config.client_did).await;
    assert!(!reply.type_uri.is_response(), "nothing was stored");
}

#[tokio::test]
#[serial]
async fn test_trqp_handler() {
    let (context, config) = get_test_context().await;

    put(&context, &config, "trqp", &config.client_did, true).await;

    send_message(
        &context.atm,
        context.profile.clone(),
        &config.trust_registry_did,
        &trqp_body("trqp", &config.client_did),
        QUERY_RECOGNITION_MESSAGE_TYPE,
        None,
    )
    .await
    .unwrap();
    tokio::time::sleep(Duration::from_secs(config.message_wait_duration_secs)).await;

    let response_body = fetch_reply(&context.atm, &context.profile, |message| {
        message.typ == QUERY_RECOGNITION_RESPONSE_MESSAGE_TYPE
    })
    .await
    .expect("recognition response");

    let expected_entity_id = format!("{ENTITY_ID}_trqp");
    assert_eq!(response_body["entity_id"], expected_entity_id);
    assert_eq!(response_body["authority_id"], config.client_did);
    assert_eq!(response_body["action"], format!("{ACTION}_trqp"));
    assert_eq!(response_body["resource"], format!("{RESOURCE}_trqp"));
    assert_eq!(response_body["recognized"].as_bool(), Some(true));
    // Per TRQP spec, recognition queries should not include the 'authorized' field
    assert_eq!(response_body["authorized"].as_bool(), None);

    // Verify response metadata fields (FTL-25196)
    assert!(
        response_body["time_requested"].as_str().is_some(),
        "time_requested should be present"
    );
    assert!(
        response_body["time_evaluated"].as_str().is_some(),
        "time_evaluated should be present"
    );
    let message = response_body["message"]
        .as_str()
        .expect("message should be present");
    assert!(
        message.contains(&expected_entity_id) && message.contains(&config.client_did),
        "message should contain entity_id and authority_id"
    );
}

async fn send_message(
    atm: &Arc<ATM>,
    profile: Arc<ATMProfile>,
    trust_registry_did: &str,
    body: &Value,
    message_type: &str,
    thid: Option<&str>,
) -> Result<(), Box<dyn std::error::Error>> {
    let message_id = Uuid::new_v4().to_string();
    let mut builder = Message::build(message_id.clone(), message_type.to_string(), body.clone())
        .from(profile.inner.did.clone())
        .to(trust_registry_did.to_string());
    if let Some(thid) = thid {
        builder = builder.thid(thid.to_string());
    }
    let message = builder.finalize();

    let packed_msg = atm
        .pack_encrypted(
            &message,
            trust_registry_did,
            Some(&profile.inner.did),
            Some(&profile.inner.did),
        )
        .await?;

    let retries = 3;
    let mut last_error = None;

    for attempt in 0..retries {
        let sending_result = atm
            .forward_and_send_message(
                &profile,
                false,
                &packed_msg.0,
                Some(&message_id),
                &profile.to_tdk_profile().mediator.unwrap(),
                trust_registry_did,
                None,
                None,
                false,
            )
            .await;

        match sending_result {
            Ok(_) => return Ok(()),
            Err(err) => {
                println!(
                    "Failed to send message (attempt {}/{}): {:?}",
                    attempt + 1,
                    retries,
                    err
                );
                last_error = Some(err);
                if attempt < retries - 1 {
                    tokio::time::sleep(Duration::from_secs((attempt + 1) as u64 * 2)).await;
                }
            }
        }
    }

    Err(last_error.unwrap().into())
}
