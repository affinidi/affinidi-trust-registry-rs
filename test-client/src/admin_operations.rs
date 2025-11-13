use std::sync::Arc;

use affinidi_tdk::{
    didcomm::Message,
    messaging::{ATM, profiles::ATMProfile, protocols::Protocols},
};
use serde_json::{Value, json};
use uuid::Uuid;

pub const CREATE_RECORD_MESSAGE_TYPE: &str =
    "https://affinidi.com/didcomm/protocols/tr-admin/1.0/create-record";
pub const UPDATE_RECORD_MESSAGE_TYPE: &str =
    "https://affinidi.com/didcomm/protocols/tr-admin/1.0/update-record";
pub const DELETE_RECORD_MESSAGE_TYPE: &str =
    "https://affinidi.com/didcomm/protocols/tr-admin/1.0/delete-record";
pub const READ_RECORD_MESSAGE_TYPE: &str =
    "https://affinidi.com/didcomm/protocols/tr-admin/1.0/read-record";
pub const LIST_RECORDS_MESSAGE_TYPE: &str =
    "https://affinidi.com/didcomm/protocols/tr-admin/1.0/list-records";

pub async fn create_record(
    atm: &Arc<ATM>,
    profile: Arc<ATMProfile>,
    trust_registry_did: &str,
    protocols: &Arc<Protocols>,
    mediator_did: &str,
    entity_id: &str,
    authority_id: &str,
    action: &str,
    resource: &str,
    recognized: bool,
    authorized: bool,
    context: Option<Value>,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut body = json!({
        "entity_id": entity_id,
        "authority_id": authority_id,
        "action": action,
        "resource": resource,
        "recognized": recognized,
        "authorized": authorized,
    });

    if let Some(ctx) = context {
        body["context"] = ctx;
    }

    send_admin_message(
        atm,
        profile,
        trust_registry_did,
        protocols,
        mediator_did,
        &body,
        CREATE_RECORD_MESSAGE_TYPE,
    )
    .await
}

pub async fn update_record(
    atm: &Arc<ATM>,
    profile: Arc<ATMProfile>,
    trust_registry_did: &str,
    protocols: &Arc<Protocols>,
    mediator_did: &str,
    entity_id: &str,
    authority_id: &str,
    action: &str,
    resource: &str,
    recognized: bool,
    authorized: bool,
    context: Option<Value>,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut body = json!({
        "entity_id": entity_id,
        "authority_id": authority_id,
        "action": action,
        "resource": resource,
        "recognized": recognized,
        "authorized": authorized,
    });

    if let Some(ctx) = context {
        body["context"] = ctx;
    }

    send_admin_message(
        atm,
        profile,
        trust_registry_did,
        protocols,
        mediator_did,
        &body,
        UPDATE_RECORD_MESSAGE_TYPE,
    )
    .await
}

pub async fn delete_record(
    atm: &Arc<ATM>,
    profile: Arc<ATMProfile>,
    trust_registry_did: &str,
    protocols: &Arc<Protocols>,
    mediator_did: &str,
    entity_id: &str,
    authority_id: &str,
    action: &str,
    resource: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let body = json!({
        "entity_id": entity_id,
        "authority_id": authority_id,
        "action": action,
        "resource": resource,
    });

    send_admin_message(
        atm,
        profile,
        trust_registry_did,
        protocols,
        mediator_did,
        &body,
        DELETE_RECORD_MESSAGE_TYPE,
    )
    .await
}

pub async fn read_record(
    atm: &Arc<ATM>,
    profile: Arc<ATMProfile>,
    trust_registry_did: &str,
    protocols: &Arc<Protocols>,
    mediator_did: &str,
    entity_id: &str,
    authority_id: &str,
    action: &str,
    resource: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let body = json!({
        "entity_id": entity_id,
        "authority_id": authority_id,
        "action": action,
        "resource": resource,
    });

    send_admin_message(
        atm,
        profile,
        trust_registry_did,
        protocols,
        mediator_did,
        &body,
        READ_RECORD_MESSAGE_TYPE,
    )
    .await
}

pub async fn list_records(
    atm: &Arc<ATM>,
    profile: Arc<ATMProfile>,
    trust_registry_did: &str,
    protocols: &Arc<Protocols>,
    mediator_did: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let body = json!({});

    send_admin_message(
        atm,
        profile,
        trust_registry_did,
        protocols,
        mediator_did,
        &body,
        LIST_RECORDS_MESSAGE_TYPE,
    )
    .await
}

/// Helper function to send admin messages
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

    println!(
        "\nSending admin message: {}",
        message_type.split('/').last().unwrap_or(message_type)
    );
    println!("   Message ID: {}", message_id);
    println!("   Body: {}", serde_json::to_string_pretty(body)?);

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
