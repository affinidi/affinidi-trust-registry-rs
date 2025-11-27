use affinidi_tdk::{
    didcomm::Message,
    messaging::{
        ATM,
        messages::{DeleteMessageRequest, FetchDeletePolicy, fetch::FetchOptions},
        profiles::ATMProfile,
        protocols::Protocols,
    },
    secrets_resolver::secrets::Secret,
};
use trust_registry::didcomm::{
    prepare_atm_and_profile,
    handlers::{
        admin::{
            CREATE_RECORD_MESSAGE_TYPE, CREATE_RECORD_RESPONSE_MESSAGE_TYPE,
            DELETE_RECORD_MESSAGE_TYPE, DELETE_RECORD_RESPONSE_MESSAGE_TYPE,
            LIST_RECORDS_MESSAGE_TYPE, LIST_RECORDS_RESPONSE_MESSAGE_TYPE,
            READ_RECORD_MESSAGE_TYPE, READ_RECORD_RESPONSE_MESSAGE_TYPE,
            UPDATE_RECORD_MESSAGE_TYPE, UPDATE_RECORD_RESPONSE_MESSAGE_TYPE,
        },
        trqp::{QUERY_RECOGNITION_MESSAGE_TYPE, QUERY_RECOGNITION_RESPONSE_MESSAGE_TYPE},
    },
};
use serde_json::{Value, json};
use std::{env, sync::Arc, time::Duration, vec};
use tokio::sync::OnceCell;
use uuid::Uuid;

static TEST_CONTEXT: OnceCell<Arc<TestConfig>> = OnceCell::const_new();
static CLEAR_MESSAGES: OnceCell<()> = OnceCell::const_new();
static CREATE_RECORDS: OnceCell<()> = OnceCell::const_new();

pub const ENTITY_ID: &str = "did:example:entityYW";
pub const AUTHORITY_ID: &str = "did:example:authorityWY";
pub const ACTION: &str = "action";
pub const RESOURCE: &str = "resource";
pub const PROBLEM_REPORT_TYPE: &str = "https://didcomm.org/report-problem/2.0/problem-report";

const INITIAL_FETCH_LIMIT: usize = 100;
const MESSAGE_WAIT_DURATION_SECS: u64 = 2;
const PIPELINE_MESSAGE_WAIT_DURATION_SECS: u64 = 5;

pub struct TestConfig {
    pub client_did: String,
    pub client_secrets: String,
    pub mediator_did: String,
    pub trust_registry_did: String,
    pub in_pipeline: bool,
    pub message_wait_duration_secs: u64,
}

pub struct AtmTestContext {
    pub atm: Arc<ATM>,
    pub profile: Arc<ATMProfile>,
    pub protocols: Arc<Protocols>,
}

async fn get_test_context() -> (AtmTestContext, Arc<TestConfig>) {
    dotenvy::from_filename(".env.test").ok();
    let client_did = env::var("CLIENT_DID").expect("CLIENT_DID not set in .env");
    let client_secrets = env::var("CLIENT_SECRETS").expect("CLIENT_SECRETS not set in .env");
    let mediator_did = env::var("MEDIATOR_DID").expect("MEDIATOR_DID not set in .env");
    let in_pipeline = env::var("IN_PIPELINE")
        .unwrap_or("false".to_string())
        .to_lowercase()
        == "true";
    let trust_registry_did =
        env::var("TRUST_REGISTRY_DID").expect("TRUST_REGISTRY_DID not set in .env");
    let message_wait_duration_secs = in_pipeline
        .then(|| PIPELINE_MESSAGE_WAIT_DURATION_SECS)
        .unwrap_or(MESSAGE_WAIT_DURATION_SECS);

    let (atm, profile, protocols) = setup_test_environment(
        &client_did,
        &client_secrets,
        &mediator_did,
        &trust_registry_did,
    )
    .await;

    (
        AtmTestContext {
            atm,
            profile,
            protocols,
        },
        TEST_CONTEXT
            .get_or_init(|| async {
                Arc::new(TestConfig {
                    client_did: client_did.to_string(),
                    client_secrets: client_secrets.to_string(),
                    mediator_did: env::var("MEDIATOR_DID").expect("MEDIATOR_DID not set in .env"),
                    trust_registry_did: trust_registry_did,
                    in_pipeline,
                    message_wait_duration_secs,
                })
            })
            .await
            .clone(),
    )
}

async fn create_records(
    atm: &Arc<ATM>,
    profile: &Arc<ATMProfile>,
    protocols: Arc<Protocols>,
    trust_registry_did: &str,
    mediator_did: &str,
    messages: Vec<Value>,
) {
    CREATE_RECORDS
        .get_or_init(|| async {
            for msg in messages {
                send_message(
                    atm,
                    profile.clone(),
                    &trust_registry_did,
                    &protocols,
                    &mediator_did,
                    &msg,
                    CREATE_RECORD_MESSAGE_TYPE,
                )
                .await
                .unwrap();
            }
        })
        .await;
}

async fn clear_messages(atm: &Arc<ATM>, profile: &Arc<ATMProfile>) {
    CLEAR_MESSAGES
        .get_or_init(|| async {
            atm.fetch_messages(
                &profile,
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

fn create_fetch_options(limit: usize) -> FetchOptions {
    FetchOptions {
        limit,
        start_id: None,
        delete_policy: FetchDeletePolicy::DoNotDelete,
    }
}

fn create_test_record_body(test_name: &str) -> Value {
    json!({
        "entity_id": format!("{}_{}", ENTITY_ID, test_name),
        "authority_id": format!("{}_{}", AUTHORITY_ID, test_name),
        "action": format!("{}_{}", ACTION, test_name),
        "resource": format!("{}_{}", RESOURCE, test_name),
    })
}

async fn delete_message(atm: &Arc<ATM>, profile: &Arc<ATMProfile>, msg_ids: Vec<String>) {
    let _ = atm
        .delete_messages_direct(
            profile,
            &DeleteMessageRequest {
                message_ids: msg_ids,
            },
        )
        .await;
}

async fn fetch_and_verify_response_with_retry(
    atm: &Arc<ATM>,
    profile: &Arc<ATMProfile>,
    expected_message_type: &str,
) -> Result<Value, Box<dyn std::error::Error>> {
    let problem_report_type = "https://didcomm.org/report-problem/2.0/problem-report";
    let retries = 3;
    let mut i = 0;

    while i < retries {
        tokio::time::sleep(Duration::from_secs(i * 2)).await;
        let fetched_messages = atm
            .fetch_messages(profile, &create_fetch_options(INITIAL_FETCH_LIMIT))
            .await?;

        println!("Fetched {} messages", fetched_messages.success.len());

        if fetched_messages.success.is_empty() {
            i += 1;
            if i >= retries {
                return Err("No response received".into());
            }
            continue;
        }

        let mut unpacked_messages = Vec::new();
        for msg_elem in &fetched_messages.success {
            if let Some(message) = &msg_elem.msg {
                let unpacked = atm.unpack(message).await?;
                unpacked_messages.push(unpacked);
            }
        }

        let problem_report_hashes: Vec<String> = unpacked_messages
            .iter()
            .filter(|(msg, _)| msg.type_ == problem_report_type)
            .map(|(msg, meta)| {
                if let Ok(json) = serde_json::to_string_pretty(&msg.body) {
                    println!("Received problem report: {}", json);
                }
                meta.sha256_hash.clone()
            })
            .collect();
        if !problem_report_hashes.is_empty() {
            delete_message(atm, profile, problem_report_hashes).await;
        }

        if let Some((msg, meta)) = unpacked_messages.into_iter().find(|(msg, _)| {
            println!("Checking message type: {}", msg.type_);
            msg.type_ == expected_message_type
        }) {
            let hash = meta.sha256_hash.clone();
            let atm = atm.clone();
            let profile = profile.clone();
            tokio::spawn(async move {
                delete_message(&atm, &profile, vec![hash]).await;
            });
            return Ok(msg.body);
        }

        i += 1;
        if i < retries {
            println!(
                "Retry {}/{}: Expected message type not found: {}",
                i, retries, expected_message_type
            );
        }
    }

    Err(format!("Expected message type not found: {}", expected_message_type).into())
}

fn create_message_with_defaults(test_name: &str) -> Value {
    let mut body = create_test_record_body(test_name);
    body["recognized"] = serde_json::Value::Bool(true);
    body["authorized"] = serde_json::Value::Bool(true);
    body["context"] = json!({
        "description": "Test credential type",
        "version": "1.0",
        "tags": ["test", "demo"]
    });
    body
}

fn get_create_record_messages() -> Vec<Value> {
    ["read", "update", "list", "delete", "trqp"]
        .iter()
        .map(|name| create_message_with_defaults(name))
        .collect()
}

async fn setup_test_environment(
    client_did: &str,
    secrets: &str,
    mediator_did: &str,
    trust_registry_did: &str,
) -> (Arc<ATM>, Arc<ATMProfile>, Arc<Protocols>) {
    let protocols = Arc::new(Protocols::new());
    let secrets: Vec<Secret> = serde_json::from_str(secrets).unwrap();
    let (atm, profile) =
        prepare_atm_and_profile("test-client", client_did, mediator_did, secrets, false)
            .await
            .unwrap();

    tokio::time::sleep(Duration::from_secs(5)).await;

    clear_messages(&atm, &profile).await;
    let create_messages = get_create_record_messages();
    create_records(
        &atm,
        &profile,
        protocols.clone(),
        trust_registry_did,
        mediator_did,
        create_messages,
    )
    .await;

    (atm, profile, protocols)
}

#[tokio::test]
async fn test_admin_read() {
    let (atm_test_context, config) = get_test_context().await;

    let _ = fetch_and_verify_response_with_retry(
        &atm_test_context.atm,
        &atm_test_context.profile,
        CREATE_RECORD_RESPONSE_MESSAGE_TYPE,
    )
    .await;

    let read_body = create_test_record_body("read");

    send_message(
        &atm_test_context.atm,
        atm_test_context.profile.clone(),
        &config.trust_registry_did,
        &atm_test_context.protocols,
        &config.mediator_did,
        &read_body,
        READ_RECORD_MESSAGE_TYPE,
    )
    .await
    .unwrap();
    tokio::time::sleep(Duration::from_secs(config.message_wait_duration_secs)).await;

    let response_body = fetch_and_verify_response_with_retry(
        &atm_test_context.atm,
        &atm_test_context.profile,
        READ_RECORD_RESPONSE_MESSAGE_TYPE,
    )
    .await
    .unwrap();

    let expected_entity_id = format!("{}_{}", ENTITY_ID, "read");
    let expected_authority_id = format!("{}_{}", AUTHORITY_ID, "read");
    let expected_action = format!("{}_{}", ACTION, "read");
    let expected_resource = format!("{}_{}", RESOURCE, "read");

    assert_eq!(response_body["entity_id"], expected_entity_id);
    assert_eq!(response_body["authority_id"], expected_authority_id);
    assert_eq!(response_body["action"], expected_action);
    assert_eq!(response_body["resource"], expected_resource);
    assert_eq!(response_body["recognized"], true);
    assert_eq!(response_body["authorized"], true);
}

#[tokio::test]
async fn test_admin_update() {
    let (atm_test_context, config) = get_test_context().await;

    let _ = fetch_and_verify_response_with_retry(
        &atm_test_context.atm,
        &atm_test_context.profile,
        CREATE_RECORD_RESPONSE_MESSAGE_TYPE,
    )
    .await;

    let mut update_body = create_test_record_body("update");
    update_body["recognized"] = serde_json::Value::Bool(false);
    update_body["authorized"] = serde_json::Value::Bool(false);

    send_message(
        &atm_test_context.atm,
        atm_test_context.profile.clone(),
        &config.trust_registry_did,
        &atm_test_context.protocols,
        &config.mediator_did,
        &update_body,
        UPDATE_RECORD_MESSAGE_TYPE,
    )
    .await
    .unwrap();
    tokio::time::sleep(Duration::from_secs(config.message_wait_duration_secs)).await;

    let response_body = fetch_and_verify_response_with_retry(
        &atm_test_context.atm,
        &atm_test_context.profile,
        UPDATE_RECORD_RESPONSE_MESSAGE_TYPE,
    )
    .await
    .unwrap();

    let expected_entity_id = format!("{}_{}", ENTITY_ID, "update");
    let expected_authority_id = format!("{}_{}", AUTHORITY_ID, "update");
    let expected_action = format!("{}_{}", ACTION, "update");
    let expected_resource = format!("{}_{}", RESOURCE, "update");

    assert_eq!(response_body["entity_id"], expected_entity_id);
    assert_eq!(response_body["authority_id"], expected_authority_id);
    assert_eq!(response_body["action"], expected_action);
    assert_eq!(response_body["resource"], expected_resource);
}

#[tokio::test]
async fn test_admin_list() {
    let (atm_test_context, config) = get_test_context().await;

    let _ = fetch_and_verify_response_with_retry(
        &atm_test_context.atm,
        &atm_test_context.profile,
        CREATE_RECORD_RESPONSE_MESSAGE_TYPE,
    )
    .await;

    let list_body = json!({});

    send_message(
        &atm_test_context.atm,
        atm_test_context.profile.clone(),
        &config.trust_registry_did,
        &atm_test_context.protocols,
        &config.mediator_did,
        &list_body,
        LIST_RECORDS_MESSAGE_TYPE,
    )
    .await
    .unwrap();
    tokio::time::sleep(Duration::from_secs(config.message_wait_duration_secs)).await;

    let response_body = fetch_and_verify_response_with_retry(
        &atm_test_context.atm,
        &atm_test_context.profile,
        LIST_RECORDS_RESPONSE_MESSAGE_TYPE,
    )
    .await
    .unwrap();

    let count = response_body["count"].as_u64().unwrap_or(0);
    let records = response_body["records"]
        .as_array()
        .unwrap_or(&Vec::new())
        .clone();

    assert!(count >= 1);

    let expected_authority_id = format!("{}_{}", AUTHORITY_ID, "list");
    let expected_action = format!("{}_{}", ACTION, "list");
    let expected_resource = format!("{}_{}", RESOURCE, "list");

    let our_record = records
        .iter()
        .find(|record| {
            record["authority_id"] == expected_authority_id
                && record["action"] == expected_action
                && record["resource"] == expected_resource
        })
        .expect("Our test record not found in list");
    assert_eq!(our_record["authority_id"], expected_authority_id);
    assert_eq!(our_record["action"], expected_action);
    assert_eq!(our_record["resource"], expected_resource);
}

#[tokio::test]
async fn test_admin_delete() {
    let (atm_test_context, config) = get_test_context().await;

    let _ = fetch_and_verify_response_with_retry(
        &atm_test_context.atm,
        &atm_test_context.profile,
        CREATE_RECORD_RESPONSE_MESSAGE_TYPE,
    )
    .await;

    let delete_body = create_test_record_body("delete");

    send_message(
        &atm_test_context.atm,
        atm_test_context.profile.clone(),
        &config.trust_registry_did,
        &atm_test_context.protocols,
        &config.mediator_did,
        &delete_body,
        DELETE_RECORD_MESSAGE_TYPE,
    )
    .await
    .unwrap();
    tokio::time::sleep(Duration::from_secs(config.message_wait_duration_secs)).await;

    let response_body = fetch_and_verify_response_with_retry(
        &atm_test_context.atm,
        &atm_test_context.profile,
        DELETE_RECORD_RESPONSE_MESSAGE_TYPE,
    )
    .await
    .unwrap();

    let expected_entity_id = format!("{}_{}", ENTITY_ID, "delete");
    let expected_authority_id = format!("{}_{}", AUTHORITY_ID, "delete");
    let expected_action = format!("{}_{}", ACTION, "delete");
    let expected_resource = format!("{}_{}", RESOURCE, "delete");

    assert_eq!(response_body["authority_id"], expected_authority_id);
    assert_eq!(response_body["action"], expected_action);
    assert_eq!(response_body["resource"], expected_resource);
    assert_eq!(response_body["entity_id"], expected_entity_id);
}

#[tokio::test]
async fn test_trqp_handler() {
    let (atm_test_context, config) = get_test_context().await;

    let _ = fetch_and_verify_response_with_retry(
        &atm_test_context.atm,
        &atm_test_context.profile,
        CREATE_RECORD_RESPONSE_MESSAGE_TYPE,
    )
    .await;

    let recognition_body = create_test_record_body("trqp");

    send_message(
        &atm_test_context.atm,
        atm_test_context.profile.clone(),
        &config.trust_registry_did,
        &atm_test_context.protocols,
        &config.mediator_did,
        &recognition_body,
        QUERY_RECOGNITION_MESSAGE_TYPE,
    )
    .await
    .unwrap();
    tokio::time::sleep(Duration::from_secs(config.message_wait_duration_secs)).await;

    let response_body = fetch_and_verify_response_with_retry(
        &atm_test_context.atm,
        &atm_test_context.profile,
        QUERY_RECOGNITION_RESPONSE_MESSAGE_TYPE,
    )
    .await
    .unwrap();

    let expected_entity_id = format!("{}_{}", ENTITY_ID, "trqp");
    let expected_authority_id = format!("{}_{}", AUTHORITY_ID, "trqp");
    let expected_action = format!("{}_{}", ACTION, "trqp");
    let expected_resource = format!("{}_{}", RESOURCE, "trqp");

    assert_eq!(response_body["entity_id"], expected_entity_id);
    assert_eq!(response_body["authority_id"], expected_authority_id);
    assert_eq!(response_body["action"], expected_action);
    assert_eq!(response_body["resource"], expected_resource);
    assert_eq!(response_body["recognized"].as_bool(), Some(true));
    assert_eq!(response_body["authorized"].as_bool(), Some(true));
}

async fn send_message(
    atm: &Arc<ATM>,
    profile: Arc<ATMProfile>,
    trust_registry_did: &str,
    _protocols: &Arc<Protocols>,
    _mediator_did: &str,
    body: &Value,
    message_type: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let message_id = Uuid::new_v4().to_string();
    let message = Message::build(message_id.clone(), message_type.to_string(), body.clone())
        .from(profile.inner.did.clone())
        .to(trust_registry_did.to_string())
        .finalize();

    let packed_msg = atm
        .pack_encrypted(
            &message,
            trust_registry_did,
            Some(&profile.inner.did),
            Some(&profile.inner.did),
            None,
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
            Ok(_) => {
                if attempt > 0 {
                    println!(
                        "Message sent successfully on attempt {}/{}",
                        attempt + 1,
                        retries
                    );
                } else {
                    println!("Message sent successfully");
                }
                return Ok(());
            }
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
