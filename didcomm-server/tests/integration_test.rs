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
use serde_json::{Value, json};
use std::{sync::Arc, time::Duration, vec};
use tokio::sync::OnceCell;
use uuid::Uuid;

static SERVER_INIT: OnceCell<()> = OnceCell::const_new();
pub const CLIENT_DID: &str = "did:peer:2.Vz6MkjUP1rEPtqqtNS65nVfAHLG6DoATr9u8TjoaWG1SJ5N43.EzQ3shaX7SqfCRWnR1KVvYfsuLCDzQKzqggfKyRZWkgHNryrYS.SeyJ0IjoiZG0iLCJzIjp7InVyaSI6Imh0dHBzOi8vZWQzOTM5MmItOGIyNC00OWIxLTk4ODQtZWZjOWZiMWZjM2Y4LmF0bGFzLmFmZmluaWRpLmlvIiwiYWNjZXB0IjpbImRpZGNvbW0vdjIiXSwicm91dGluZ19rZXlzIjpbXX0sImlkIjpudWxsfQ";
pub const CLIENT_SECRETS: &str = "[{\"id\":\"did:peer:2.Vz6MkjUP1rEPtqqtNS65nVfAHLG6DoATr9u8TjoaWG1SJ5N43.EzQ3shaX7SqfCRWnR1KVvYfsuLCDzQKzqggfKyRZWkgHNryrYS.SeyJ0IjoiZG0iLCJzIjp7InVyaSI6Imh0dHBzOi8vZWQzOTM5MmItOGIyNC00OWIxLTk4ODQtZWZjOWZiMWZjM2Y4LmF0bGFzLmFmZmluaWRpLmlvIiwiYWNjZXB0IjpbImRpZGNvbW0vdjIiXSwicm91dGluZ19rZXlzIjpbXX0sImlkIjpudWxsfQ#key-1\",\"type\":\"JsonWebKey2020\",\"privateKeyJwk\":{\"crv\":\"Ed25519\",\"d\":\"SqijD_NleY0h6Fql02YYk05IZNZur9jMzIV4AWl-XYs\",\"kty\":\"OKP\",\"x\":\"SpPle1SUBtFBoDMFOKza2Ph6IrJAO9nShev5BXiftHQ\"}},{\"id\":\"did:peer:2.Vz6MkjUP1rEPtqqtNS65nVfAHLG6DoATr9u8TjoaWG1SJ5N43.EzQ3shaX7SqfCRWnR1KVvYfsuLCDzQKzqggfKyRZWkgHNryrYS.SeyJ0IjoiZG0iLCJzIjp7InVyaSI6Imh0dHBzOi8vZWQzOTM5MmItOGIyNC00OWIxLTk4ODQtZWZjOWZiMWZjM2Y4LmF0bGFzLmFmZmluaWRpLmlvIiwiYWNjZXB0IjpbImRpZGNvbW0vdjIiXSwicm91dGluZ19rZXlzIjpbXX0sImlkIjpudWxsfQ#key-2\",\"type\":\"JsonWebKey2020\",\"privateKeyJwk\":{\"crv\":\"secp256k1\",\"d\":\"inEoKYX4-eTqoHfvzxtLc6GWKfjoELcnA0tFilwQwiU\",\"kty\":\"EC\",\"x\":\"wsaMHi-TrwVlQAkO6uS45uN2IvLbcF9R05Is2XWUBHM\",\"y\":\"DV4AZjcw1Bx7KA7Pn-0lPE088928OhgAZqKckaql1Zw\"}}]";
pub const MEDIATOR_DID: &str = "did:web:66a6ec69-0646-4a8d-ae08-94e959855fa9.atlas.affinidi.io";
pub const TRUST_REGISTRY_DID: &str = "did:peer:2.VzDnaebgAmHaKo1svFeu4k3jZQScNjNdRj8XjoWX2FKzMdKHUZ.Vz6MkoxrzY7XtpyihUkXMgwFEREwaSS2Aoc9WGc1pBj7StT9o.EzQ3shwH2HC1AMd4QEK2s3cPsduWKiTJbNmqHhCUarbSvbUoNn.EzDnaewBr6iwmNfiqiXVYvdHxX9YSL2rrnuEqrq5k1vfdtDjmq";
pub const ENTITY_ID: &str = "did:example:entityYW";
pub const AUTHORITY_ID: &str = "did:example:authorityWY";
pub const ASSERTION_ID: &str = "credential_type_abc";

// Test configuration constants
const MESSAGE_FETCH_LIMIT: usize = 10;
const INITIAL_FETCH_LIMIT: usize = 100;
const MESSAGE_WAIT_DURATION_SECS: u64 = 5;

async fn init_didcomm_server() {
    SERVER_INIT
        .get_or_init(|| async {
            tokio::spawn(async move { start().await });
        })
        .await;
}

// Helper function to create standard fetch options
fn create_fetch_options(limit: usize) -> FetchOptions {
    FetchOptions {
        limit,
        start_id: None,
        delete_policy: FetchDeletePolicy::DoNotDelete,
    }
}

// Helper function to create record JSON body
fn create_record_body(number: Option<&str>) -> Value {
    json!({
        "entity_id": format!("{}{}", ENTITY_ID, number.unwrap_or("")),
        "authority_id": format!("{}{}", AUTHORITY_ID, number.unwrap_or("")),
        "assertion_id": format!("{}{}", ASSERTION_ID, number.unwrap_or(""))
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

// Helper function to fetch and process messages
async fn fetch_and_verify_response(
    atm: &Arc<ATM>,
    profile: &Arc<ATMProfile>,
    expected_message_type: &str,
) -> Result<Value, Box<dyn std::error::Error>> {
    let problem_report_type: String =
        "https://didcomm.org/report-problem/2.0/problem-report".to_string();
    let fetched_messages = atm
        .fetch_messages(profile, &create_fetch_options(INITIAL_FETCH_LIMIT))
        .await?;
    println!("Fetched {} messages", fetched_messages.success.len());
    if fetched_messages.success.is_empty() {
        return Err("No response received".into());
    }
    let mut msg_ids: Vec<String> = vec![];
    for msg_elem in fetched_messages.success {
        if let Some(message) = msg_elem.msg {
            let unpacked_msg = atm.unpack(&message).await?;
            println!("Received message of type: {}", unpacked_msg.0.type_);
            if unpacked_msg.0.type_ == expected_message_type {
                delete_message(atm, profile, vec![unpacked_msg.1.sha256_hash]).await;
                return Ok(unpacked_msg.0.body);
            } else if unpacked_msg.0.type_ == problem_report_type {
                println!(
                    "Received problem report: {}",
                    serde_json::to_string_pretty(&unpacked_msg.0.body)?
                );
                msg_ids.push(unpacked_msg.1.sha256_hash);
            }
        }
    }
    delete_message(atm, profile, msg_ids).await;

    Err(format!("Expected message type not found: {}", expected_message_type).into())
}

#[tokio::test]
async fn integration_test_admin_handlers() {
    init_didcomm_server().await;
    let protocols = Arc::new(Protocols::new());
    let secrets: Vec<Secret> = serde_json::from_str(CLIENT_SECRETS).unwrap();
    let (atm, profile) =
        prepare_atm_and_profile("test-client", &CLIENT_DID, MEDIATOR_DID, secrets, false)
            .await
            .unwrap();
    // Wait until server is ready to process messages
    tokio::time::sleep(Duration::from_secs(MESSAGE_WAIT_DURATION_SECS)).await;

    // atm.fetch_messages(&profile, &create_fetch_options(INITIAL_FETCH_LIMIT))
    //     .await
    //     .unwrap();

    // Send create record message
    let body = json!({
        "entity_id": ENTITY_ID,
        "authority_id": AUTHORITY_ID,
        "assertion_id": ASSERTION_ID,
        "recognized": true,
        "assertion_verified": true,
        "context": json!({
        "description": "Test credential type",
        "version": "1.0",
        "tags": ["test", "demo"]
        })
    });

    send_admin_message(
        &atm,
        profile.clone(),
        TRUST_REGISTRY_DID,
        &protocols,
        MEDIATOR_DID,
        &body,
        CREATE_RECORD_MESSAGE_TYPE,
    )
    .await
    .unwrap();
    tokio::time::sleep(Duration::from_secs(MESSAGE_WAIT_DURATION_SECS)).await;

    // Receive create record response
    let response_body =
        fetch_and_verify_response(&atm, &profile, CREATE_RECORD_RESPONSE_MESSAGE_TYPE)
            .await
            .unwrap();

    assert_eq!(response_body, create_record_body(None));

    // Now send read record message
    let read_body = create_record_body(None);

    send_admin_message(
        &atm,
        profile.clone(),
        TRUST_REGISTRY_DID,
        &protocols,
        MEDIATOR_DID,
        &read_body,
        READ_RECORD_MESSAGE_TYPE,
    )
    .await
    .unwrap();
    tokio::time::sleep(Duration::from_secs(MESSAGE_WAIT_DURATION_SECS)).await;
    // Receive read record response
    let response_body =
        fetch_and_verify_response(&atm, &profile, READ_RECORD_RESPONSE_MESSAGE_TYPE)
            .await
            .unwrap();

    assert_eq!(response_body["entity_id"], ENTITY_ID);
    assert_eq!(response_body["authority_id"], AUTHORITY_ID);
    assert_eq!(response_body["assertion_id"], ASSERTION_ID);
    assert_eq!(response_body["recognized"], true);
    assert_eq!(response_body["assertion_verified"], true);

    println!(
        "Read record test passed - received full record: {}",
        serde_json::to_string_pretty(&response_body).unwrap()
    );
    // Now send update record message
    let mut update_body = create_record_body(None);
    update_body["recognized"] = serde_json::Value::Bool(false);
    update_body["assertion_verified"] = serde_json::Value::Bool(false);

    send_admin_message(
        &atm,
        profile.clone(),
        TRUST_REGISTRY_DID,
        &protocols,
        MEDIATOR_DID,
        &update_body,
        UPDATE_RECORD_MESSAGE_TYPE,
    )
    .await
    .unwrap();
    tokio::time::sleep(Duration::from_secs(MESSAGE_WAIT_DURATION_SECS)).await;
    // Receive update record response
    let response_body =
        fetch_and_verify_response(&atm, &profile, UPDATE_RECORD_RESPONSE_MESSAGE_TYPE)
            .await
            .unwrap();

    assert_eq!(response_body["entity_id"], ENTITY_ID);
    assert_eq!(response_body["authority_id"], AUTHORITY_ID);
    assert_eq!(response_body["assertion_id"], ASSERTION_ID);

    println!(
        "Update record test passed - received full record: {}",
        serde_json::to_string_pretty(&response_body).unwrap()
    );
    // Now send list records message
    let list_body = json!({});

    send_admin_message(
        &atm,
        profile.clone(),
        TRUST_REGISTRY_DID,
        &protocols,
        MEDIATOR_DID,
        &list_body,
        LIST_RECORDS_MESSAGE_TYPE,
    )
    .await
    .unwrap();
    tokio::time::sleep(Duration::from_secs(MESSAGE_WAIT_DURATION_SECS)).await;
    // Receive list records response
    let response_body =
        fetch_and_verify_response(&atm, &profile, LIST_RECORDS_RESPONSE_MESSAGE_TYPE)
            .await
            .unwrap();
    let count = response_body["count"].as_u64().unwrap_or(0);
    let records = response_body["records"]
        .as_array()
        .unwrap_or(&Vec::new())
        .clone();
    let record = records.first().expect("Records list is empty").clone();
    assert_eq!(count, 1);
    assert_eq!(record["authority_id"], AUTHORITY_ID);
    assert_eq!(record["assertion_id"], ASSERTION_ID);
    assert_eq!(record["assertion_verified"], false);

    println!(
        "List records test passed - received full record: {}",
        serde_json::to_string_pretty(&response_body).unwrap()
    );
    // Now send delete record message
    let delete_body = create_record_body(None);

    send_admin_message(
        &atm,
        profile.clone(),
        TRUST_REGISTRY_DID,
        &protocols,
        MEDIATOR_DID,
        &delete_body,
        DELETE_RECORD_MESSAGE_TYPE,
    )
    .await
    .unwrap();
    tokio::time::sleep(Duration::from_secs(MESSAGE_WAIT_DURATION_SECS)).await;
    // Receive delete record response
    let response_body =
        fetch_and_verify_response(&atm, &profile, DELETE_RECORD_RESPONSE_MESSAGE_TYPE)
            .await
            .unwrap();

    assert_eq!(response_body["authority_id"], AUTHORITY_ID);
    assert_eq!(response_body["assertion_id"], ASSERTION_ID);
    assert_eq!(response_body["entity_id"], ENTITY_ID);

    println!(
        "Delete records test passed - received full record: {}",
        serde_json::to_string_pretty(&response_body).unwrap()
    );
}

// #[tokio::test]
async fn integration_test_handler() {
    init_didcomm_server().await;
    let protocols = Arc::new(Protocols::new());
    let secrets: Vec<Secret> = serde_json::from_str(CLIENT_SECRETS).unwrap();
    let (atm, profile) =
        prepare_atm_and_profile("test-client", &CLIENT_DID, MEDIATOR_DID, secrets, false)
            .await
            .unwrap();
    let response_body =
        fetch_and_verify_response(&atm, &profile, READ_RECORD_RESPONSE_MESSAGE_TYPE)
            .await
            .unwrap();
    println!(
        "Recognition received full record: {}",
        serde_json::to_string_pretty(&response_body).unwrap()
    );
}
#[tokio::test]
async fn integration_test_trqp_handler() {
    init_didcomm_server().await;
    let protocols = Arc::new(Protocols::new());
    let secrets: Vec<Secret> = serde_json::from_str(CLIENT_SECRETS).unwrap();
    let (atm, profile) =
        prepare_atm_and_profile("test-client", &CLIENT_DID, MEDIATOR_DID, secrets, false)
            .await
            .unwrap();
    // Wait until admin creates a record
    tokio::time::sleep(Duration::from_secs(8)).await;

    // Send recognition record message
    let recognition_body = create_record_body(None);

    send_admin_message(
        &atm,
        profile.clone(),
        TRUST_REGISTRY_DID,
        &protocols,
        MEDIATOR_DID,
        &recognition_body,
        QUERY_RECOGNITION_MESSAGE_TYPE,
    )
    .await
    .unwrap();
    tokio::time::sleep(Duration::from_secs(MESSAGE_WAIT_DURATION_SECS)).await;
    // Receive recognition record response
    let response_body =
        fetch_and_verify_response(&atm, &profile, QUERY_RECOGNITION_RESPONSE_MESSAGE_TYPE)
            .await
            .unwrap();
    println!(
        "Recognition received full record: {}",
        serde_json::to_string_pretty(&response_body).unwrap()
    );
    assert_eq!(response_body["entity_id"], ENTITY_ID);
    assert_eq!(response_body["authority_id"], AUTHORITY_ID);
    assert_eq!(response_body["assertion_id"], ASSERTION_ID);
    assert_eq!(response_body["recognized"].as_bool(), Some(true));
    assert_eq!(response_body["assertion_verified"].as_bool(), Some(true));
}

async fn send_admin_message(
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

    // println!(
    //     "\nSending admin message: {}",
    //     message_type.split('/').last().unwrap_or(message_type)
    // );
    // println!("   Message ID: {}", message_id);
    // println!("   Body: {}", serde_json::to_string_pretty(body)?);

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
