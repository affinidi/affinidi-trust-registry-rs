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
use didcomm_server::{
    didcomm::prepare_atm_and_profile,
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
    server::start,
};
use dotenvy::dotenv;
use serde_json::{Value, json};
use std::{env, fs::File, sync::Arc, time::Duration, vec};
use tokio::sync::OnceCell;
use uuid::Uuid;

static SERVER_INIT: OnceCell<()> = OnceCell::const_new();
static TEST_CONTEXT: OnceCell<Arc<TestConfig>> = OnceCell::const_new();

pub const ENTITY_ID: &str = "did:example:entityYW";
pub const AUTHORITY_ID: &str = "did:example:authorityWY";
pub const ASSERTION_ID: &str = "credential_type_abc";
pub const PROBLEM_REPORT_TYPE: &str = "https://didcomm.org/report-problem/2.0/problem-report";

const INITIAL_FETCH_LIMIT: usize = 100;
const MESSAGE_WAIT_DURATION_SECS: u64 = 5;

pub struct TestConfig {
    pub client_did: String,
    pub client_secrets: String,
    pub mediator_did: String,
    pub trust_registry_did: String,
}

pub struct AtmTestContext {
    pub atm: Arc<ATM>,
    pub profile: Arc<ATMProfile>,
    pub protocols: Arc<Protocols>,
}

async fn get_test_context() -> (AtmTestContext, Arc<TestConfig>) {
    dotenv().ok();
    let client_did = env::var("CLIENT_DID").expect("CLIENT_DID not set in .env");
    let client_secrets = env::var("CLIENT_SECRETS").expect("CLIENT_SECRETS not set in .env");
    let mediator_did = env::var("MEDIATOR_DID").expect("MEDIATOR_DID not set in .env");

    let (atm, profile, protocols) =
        setup_test_environment(&client_did, &client_secrets, &mediator_did).await;

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
                    trust_registry_did: env::var("TRUST_REGISTRY_DID")
                        .expect("TRUST_REGISTRY_DID not set in .env"),
                })
            })
            .await
            .clone(),
    )
}

async fn init_didcomm_server() {
    SERVER_INIT
        .get_or_init(|| async {
            tokio::spawn(async move { start().await });
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
        "assertion_id": format!("{}_{}", ASSERTION_ID, test_name)
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

async fn fetch_and_verify_response(
    atm: &Arc<ATM>,
    profile: &Arc<ATMProfile>,
    expected_message_type: &str,
) -> Result<Value, Box<dyn std::error::Error>> {
    let problem_report_type = "https://didcomm.org/report-problem/2.0/problem-report";
    let fetched_messages = atm
        .fetch_messages(profile, &create_fetch_options(INITIAL_FETCH_LIMIT))
        .await?;

    println!("Fetched {} messages", fetched_messages.success.len());

    if fetched_messages.success.is_empty() {
        return Err("No response received".into());
    }
    // Collect all messages and unpack them
    let mut unpacked_messages = Vec::new();
    for msg_elem in &fetched_messages.success {
        if let Some(message) = &msg_elem.msg {
            let unpacked = atm.unpack(message).await?;
            unpacked_messages.push(unpacked);
        }
    }
    // Collect problem report hashes and log them
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
    // Find the expected message
    let result = unpacked_messages
        .into_iter()
        .find(|(msg, _)| msg.type_ == expected_message_type)
        .map(|(msg, meta)| {
            // Delete the message we found
            let hash = meta.sha256_hash.clone();
            let atm = atm.clone();
            let profile = profile.clone();
            tokio::spawn(async move {
                delete_message(&atm, &profile, vec![hash]).await;
            });
            msg.body
        })
        .ok_or_else(|| {
            format!("Expected message type not found: {}", expected_message_type).into()
        });
    result
}

// Helper function to set up test environment for admin handlers
async fn setup_test_environment(
    client_did: &str,
    secrets: &str,
    mediator_did: &str,
) -> (Arc<ATM>, Arc<ATMProfile>, Arc<Protocols>) {
    let temp_file = std::env::temp_dir().join("integration_test_data.csv");
    File::create(temp_file.clone()).unwrap();

    if env::var("TR_STORAGE_BACKEND").unwrap_or("csv".to_owned()) == "csv" {
        unsafe {
            env::set_var("FILE_STORAGE_PATH", temp_file.to_str().unwrap());
        }
    }

    init_didcomm_server().await;
    let protocols = Arc::new(Protocols::new());
    let secrets: Vec<Secret> = serde_json::from_str(secrets).unwrap();
    let (atm, profile) =
        prepare_atm_and_profile("test-client", client_did, mediator_did, secrets, false)
            .await
            .unwrap();

    // Wait until server is ready to process messages
    tokio::time::sleep(Duration::from_secs(5)).await;

    // Clear any existing messages
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

    (atm, profile, protocols)
}

#[tokio::test]
async fn test_admin_read() {
    let (atm_test_context, config) = get_test_context().await;

    // First create a record to read with unique IDs for this test
    let mut create_body = create_test_record_body("read");
    create_body["recognized"] = serde_json::Value::Bool(true);
    create_body["assertion_verified"] = serde_json::Value::Bool(true);
    create_body["context"] = json!({
        "description": "Test credential type",
        "version": "1.0",
        "tags": ["test", "demo"]
    });

    send_message(
        &atm_test_context.atm,
        atm_test_context.profile.clone(),
        &config.trust_registry_did,
        &atm_test_context.protocols,
        &config.mediator_did,
        &create_body,
        CREATE_RECORD_MESSAGE_TYPE,
    )
    .await
    .unwrap();
    tokio::time::sleep(Duration::from_secs(MESSAGE_WAIT_DURATION_SECS)).await;

    // Clear create response
    let _ = fetch_and_verify_response(
        &atm_test_context.atm,
        &atm_test_context.profile,
        CREATE_RECORD_RESPONSE_MESSAGE_TYPE,
    )
    .await;

    // Now send read record message
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
    tokio::time::sleep(Duration::from_secs(MESSAGE_WAIT_DURATION_SECS)).await;

    // Receive read record response
    let response_body = fetch_and_verify_response(
        &atm_test_context.atm,
        &atm_test_context.profile,
        READ_RECORD_RESPONSE_MESSAGE_TYPE,
    )
    .await
    .unwrap();

    let expected_entity_id = format!("{}_{}", ENTITY_ID, "read");
    let expected_authority_id = format!("{}_{}", AUTHORITY_ID, "read");
    let expected_assertion_id = format!("{}_{}", ASSERTION_ID, "read");

    assert_eq!(response_body["entity_id"], expected_entity_id);
    assert_eq!(response_body["authority_id"], expected_authority_id);
    assert_eq!(response_body["assertion_id"], expected_assertion_id);
    assert_eq!(response_body["recognized"], true);
    assert_eq!(response_body["assertion_verified"], true);
}

#[tokio::test]
async fn test_admin_update() {
    let (atm_test_context, config) = get_test_context().await;

    // First create a record to update with unique IDs for this test
    let mut create_body = create_test_record_body("update");
    create_body["recognized"] = serde_json::Value::Bool(true);
    create_body["assertion_verified"] = serde_json::Value::Bool(true);
    create_body["context"] = json!({
        "description": "Test credential type",
        "version": "1.0",
        "tags": ["test", "demo"]
    });

    send_message(
        &atm_test_context.atm,
        atm_test_context.profile.clone(),
        &config.trust_registry_did,
        &atm_test_context.protocols,
        &config.mediator_did,
        &create_body,
        CREATE_RECORD_MESSAGE_TYPE,
    )
    .await
    .unwrap();
    tokio::time::sleep(Duration::from_secs(MESSAGE_WAIT_DURATION_SECS)).await;

    // Clear create response
    let _ = fetch_and_verify_response(
        &atm_test_context.atm,
        &atm_test_context.profile,
        CREATE_RECORD_RESPONSE_MESSAGE_TYPE,
    )
    .await;

    // Now send update record message
    let mut update_body = create_test_record_body("update");
    update_body["recognized"] = serde_json::Value::Bool(false);
    update_body["assertion_verified"] = serde_json::Value::Bool(false);

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
    tokio::time::sleep(Duration::from_secs(MESSAGE_WAIT_DURATION_SECS)).await;

    // Receive update record response
    let response_body = fetch_and_verify_response(
        &atm_test_context.atm,
        &atm_test_context.profile,
        UPDATE_RECORD_RESPONSE_MESSAGE_TYPE,
    )
    .await
    .unwrap();

    let expected_entity_id = format!("{}_{}", ENTITY_ID, "update");
    let expected_authority_id = format!("{}_{}", AUTHORITY_ID, "update");
    let expected_assertion_id = format!("{}_{}", ASSERTION_ID, "update");

    assert_eq!(response_body["entity_id"], expected_entity_id);
    assert_eq!(response_body["authority_id"], expected_authority_id);
    assert_eq!(response_body["assertion_id"], expected_assertion_id);
}

#[tokio::test]
async fn test_admin_list() {
    let (atm_test_context, config) = get_test_context().await;

    // First create a record to list with unique IDs for this test
    let mut create_body = create_test_record_body("list");
    create_body["recognized"] = serde_json::Value::Bool(true);
    create_body["assertion_verified"] = serde_json::Value::Bool(true);
    create_body["context"] = json!({
        "description": "Test credential type",
        "version": "1.0",
        "tags": ["test", "demo"]
    });

    send_message(
        &atm_test_context.atm,
        atm_test_context.profile.clone(),
        &config.trust_registry_did,
        &atm_test_context.protocols,
        &config.mediator_did,
        &create_body,
        CREATE_RECORD_MESSAGE_TYPE,
    )
    .await
    .unwrap();
    tokio::time::sleep(Duration::from_secs(MESSAGE_WAIT_DURATION_SECS)).await;

    // Clear create response
    let _ = fetch_and_verify_response(
        &atm_test_context.atm,
        &atm_test_context.profile,
        CREATE_RECORD_RESPONSE_MESSAGE_TYPE,
    )
    .await;

    // Now send list records message
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
    tokio::time::sleep(Duration::from_secs(MESSAGE_WAIT_DURATION_SECS)).await;

    // Receive list records response
    let response_body = fetch_and_verify_response(
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
    let expected_assertion_id = format!("{}_{}", ASSERTION_ID, "list");

    let our_record = records
        .iter()
        .find(|record| {
            record["authority_id"] == expected_authority_id
                && record["assertion_id"] == expected_assertion_id
        })
        .expect("Our test record not found in list");

    assert_eq!(our_record["authority_id"], expected_authority_id);
    assert_eq!(our_record["assertion_id"], expected_assertion_id);
}

#[tokio::test]
async fn test_admin_delete() {
    let (atm_test_context, config) = get_test_context().await;

    // First create a record to delete with unique IDs for this test
    let mut create_body = create_test_record_body("delete");
    create_body["recognized"] = serde_json::Value::Bool(true);
    create_body["assertion_verified"] = serde_json::Value::Bool(true);
    create_body["context"] = json!({
        "description": "Test credential type",
        "version": "1.0",
        "tags": ["test", "demo"]
    });

    send_message(
        &atm_test_context.atm,
        atm_test_context.profile.clone(),
        &config.trust_registry_did,
        &atm_test_context.protocols,
        &config.mediator_did,
        &create_body,
        CREATE_RECORD_MESSAGE_TYPE,
    )
    .await
    .unwrap();
    tokio::time::sleep(Duration::from_secs(MESSAGE_WAIT_DURATION_SECS)).await;

    // Clear create response
    let _ = fetch_and_verify_response(
        &atm_test_context.atm,
        &atm_test_context.profile,
        CREATE_RECORD_RESPONSE_MESSAGE_TYPE,
    )
    .await;

    // Now send delete record message
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
    tokio::time::sleep(Duration::from_secs(MESSAGE_WAIT_DURATION_SECS)).await;

    // Receive delete record response
    let response_body = fetch_and_verify_response(
        &atm_test_context.atm,
        &atm_test_context.profile,
        DELETE_RECORD_RESPONSE_MESSAGE_TYPE,
    )
    .await
    .unwrap();

    let expected_entity_id = format!("{}_{}", ENTITY_ID, "delete");
    let expected_authority_id = format!("{}_{}", AUTHORITY_ID, "delete");
    let expected_assertion_id = format!("{}_{}", ASSERTION_ID, "delete");

    assert_eq!(response_body["authority_id"], expected_authority_id);
    assert_eq!(response_body["assertion_id"], expected_assertion_id);
    assert_eq!(response_body["entity_id"], expected_entity_id);
}

#[tokio::test]
async fn test_trqp_handler() {
    let (atm_test_context, config) = get_test_context().await;

    // First create a record to query with unique IDs for this test
    let mut create_body = create_test_record_body("trqp");
    create_body["recognized"] = serde_json::Value::Bool(true);
    create_body["assertion_verified"] = serde_json::Value::Bool(true);
    create_body["context"] = json!({
        "description": "Test credential type",
        "version": "1.0",
        "tags": ["test", "demo"]
    });

    send_message(
        &atm_test_context.atm,
        atm_test_context.profile.clone(),
        &config.trust_registry_did,
        &atm_test_context.protocols,
        &config.mediator_did,
        &create_body,
        CREATE_RECORD_MESSAGE_TYPE,
    )
    .await
    .unwrap();
    tokio::time::sleep(Duration::from_secs(MESSAGE_WAIT_DURATION_SECS)).await;

    // Clear create response
    let _ = fetch_and_verify_response(
        &atm_test_context.atm,
        &atm_test_context.profile,
        CREATE_RECORD_RESPONSE_MESSAGE_TYPE,
    )
    .await;

    // Send recognition record message
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
    tokio::time::sleep(Duration::from_secs(MESSAGE_WAIT_DURATION_SECS)).await;

    // Receive recognition record response
    let response_body = fetch_and_verify_response(
        &atm_test_context.atm,
        &atm_test_context.profile,
        QUERY_RECOGNITION_RESPONSE_MESSAGE_TYPE,
    )
    .await
    .unwrap();

    let expected_entity_id = format!("{}_{}", ENTITY_ID, "trqp");
    let expected_authority_id = format!("{}_{}", AUTHORITY_ID, "trqp");
    let expected_assertion_id = format!("{}_{}", ASSERTION_ID, "trqp");

    assert_eq!(response_body["entity_id"], expected_entity_id);
    assert_eq!(response_body["authority_id"], expected_authority_id);
    assert_eq!(response_body["assertion_id"], expected_assertion_id);
    assert_eq!(response_body["recognized"].as_bool(), Some(true));
    assert_eq!(response_body["assertion_verified"].as_bool(), Some(true));
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
            println!("Admin message sent successfully");
            Ok(())
        }
        Err(err) => {
            println!("Failed to send admin message: {:?}", err);
            Err(err.into())
        }
    }
}
