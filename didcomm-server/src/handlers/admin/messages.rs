// TODO: refactor function sugnatures to reduce amount of input params
use std::sync::Arc;

use affinidi_tdk::{
    didcomm::Message,
    messaging::{ATM, profiles::ATMProfile},
};
use app::{
    domain::{AssertionId, AuthorityId, Context, EntityId, TrustRecordBuilder},
    storage::repository::{TrustRecordAdminRepository, TrustRecordQuery},
};
use serde::Deserialize;
use serde_json::json;
use tracing::{debug, info};

use crate::didcomm::transport;

use super::{
    AdminMessagesHandler, CREATE_RECORD_RESPONSE_MESSAGE_TYPE, DELETE_RECORD_RESPONSE_MESSAGE_TYPE,
    LIST_RECORDS_RESPONSE_MESSAGE_TYPE, READ_RECORD_RESPONSE_MESSAGE_TYPE,
    UPDATE_RECORD_RESPONSE_MESSAGE_TYPE,
};

#[derive(Debug, Deserialize)]
struct CreateRecordRequest {
    entity_id: String,
    authority_id: String,
    assertion_id: String,
    recognized: bool,
    assertion_verified: bool,
    #[serde(default)]
    context: Option<serde_json::Value>,
}

#[derive(Debug, Deserialize)]
struct UpdateRecordRequest {
    entity_id: String,
    authority_id: String,
    assertion_id: String,
    recognized: bool,
    assertion_verified: bool,
    #[serde(default)]
    context: Option<serde_json::Value>,
}

#[derive(Debug, Deserialize)]
struct DeleteRecordRequest {
    entity_id: String,
    authority_id: String,
    assertion_id: String,
}

#[derive(Debug, Deserialize)]
struct ReadRecordRequest {
    entity_id: String,
    authority_id: String,
    assertion_id: String,
}

pub async fn handle_create_record<R: ?Sized + TrustRecordAdminRepository>(
    handler: &AdminMessagesHandler<R>,
    atm: &Arc<ATM>,
    profile: &Arc<ATMProfile>,
    message: Message,
    sender_did: &str,
    thid: Option<String>,
    pthid: Option<String>,
) -> Result<(), Box<dyn std::error::Error>> {
    let request: CreateRecordRequest = serde_json::from_value(message.body)?;

    debug!(
        "Creating record: {}|{}|{}",
        request.entity_id, request.authority_id, request.assertion_id
    );

    let mut builder = TrustRecordBuilder::new()
        .entity_id(EntityId::new(request.entity_id.clone()))
        .authority_id(AuthorityId::new(request.authority_id.clone()))
        .assertion_id(AssertionId::new(request.assertion_id.clone()))
        .recognized(request.recognized)
        .assertion_verified(request.assertion_verified);

    if let Some(ctx) = request.context {
        builder = builder.context(Context::new(ctx));
    }

    let record = builder.build().map_err(|e| e.to_string())?;

    handler
        .repository
        .create(record)
        .await
        .map_err(|e| e.to_string())?;

    info!(
        "[admin = {}] Created record: {}|{}|{}",
        sender_did, request.entity_id, request.authority_id, request.assertion_id
    );

    let response_body = json!({
        "entity_id": request.entity_id,
        "authority_id": request.authority_id,
        "assertion_id": request.assertion_id
    });

    transport::send_response(
        atm,
        profile,
        CREATE_RECORD_RESPONSE_MESSAGE_TYPE.to_string(),
        response_body,
        sender_did,
        thid,
        pthid,
    )
    .await?;

    Ok(())
}

pub async fn handle_update_record<R: ?Sized + TrustRecordAdminRepository>(
    handler: &AdminMessagesHandler<R>,
    atm: &Arc<ATM>,
    profile: &Arc<ATMProfile>,
    message: Message,
    sender_did: &str,
    thid: Option<String>,
    pthid: Option<String>,
) -> Result<(), Box<dyn std::error::Error>> {
    let request: UpdateRecordRequest = serde_json::from_value(message.body)?;

    debug!(
        "Updating record: {}|{}|{}",
        request.entity_id, request.authority_id, request.assertion_id
    );

    let mut builder = TrustRecordBuilder::new()
        .entity_id(EntityId::new(request.entity_id.clone()))
        .authority_id(AuthorityId::new(request.authority_id.clone()))
        .assertion_id(AssertionId::new(request.assertion_id.clone()))
        .recognized(request.recognized)
        .assertion_verified(request.assertion_verified);

    if let Some(ctx) = request.context {
        builder = builder.context(Context::new(ctx));
    }

    let record = builder.build().map_err(|e| e.to_string())?;

    handler
        .repository
        .update(record)
        .await
        .map_err(|e| e.to_string())?;

    info!(
        "[admin = {}] Updated record: {}|{}|{}",
        sender_did, request.entity_id, request.authority_id, request.assertion_id
    );

    let response_body = json!({
        "entity_id": request.entity_id,
        "authority_id": request.authority_id,
        "assertion_id": request.assertion_id
    });

    transport::send_response(
        atm,
        profile,
        UPDATE_RECORD_RESPONSE_MESSAGE_TYPE.to_string(),
        response_body,
        sender_did,
        thid,
        pthid,
    )
    .await?;

    Ok(())
}

pub async fn handle_delete_record<R: ?Sized + TrustRecordAdminRepository>(
    handler: &AdminMessagesHandler<R>,
    atm: &Arc<ATM>,
    profile: &Arc<ATMProfile>,
    message: Message,
    sender_did: &str,
    thid: Option<String>,
    pthid: Option<String>,
) -> Result<(), Box<dyn std::error::Error>> {
    let request: DeleteRecordRequest = serde_json::from_value(message.body)?;

    debug!(
        "Deleting record: {}|{}|{}",
        request.entity_id, request.authority_id, request.assertion_id
    );

    let query = TrustRecordQuery::new(
        EntityId::new(request.entity_id.clone()),
        AuthorityId::new(request.authority_id.clone()),
        AssertionId::new(request.assertion_id.clone()),
    );

    handler
        .repository
        .delete(query)
        .await
        .map_err(|e| e.to_string())?;

    info!(
        "[admin = {}] Deleted record: {}|{}|{}",
        sender_did, request.entity_id, request.authority_id, request.assertion_id
    );

    let response_body = json!({
        "entity_id": request.entity_id,
        "authority_id": request.authority_id,
        "assertion_id": request.assertion_id
    });

    transport::send_response(
        atm,
        profile,
        DELETE_RECORD_RESPONSE_MESSAGE_TYPE.to_string(),
        response_body,
        sender_did,
        thid,
        pthid,
    )
    .await?;

    Ok(())
}

pub async fn handle_read_record<R: ?Sized + TrustRecordAdminRepository>(
    handler: &AdminMessagesHandler<R>,
    atm: &Arc<ATM>,
    profile: &Arc<ATMProfile>,
    message: Message,
    sender_did: &str,
    thid: Option<String>,
    pthid: Option<String>,
) -> Result<(), Box<dyn std::error::Error>> {
    let request: ReadRecordRequest = serde_json::from_value(message.body)?;

    debug!(
        "Reading record: {}|{}|{}",
        request.entity_id, request.authority_id, request.assertion_id
    );

    let query = TrustRecordQuery::new(
        EntityId::new(request.entity_id.clone()),
        AuthorityId::new(request.authority_id.clone()),
        AssertionId::new(request.assertion_id.clone()),
    );

    let record = handler
        .repository
        .read(query)
        .await
        .map_err(|e| e.to_string())?;

    info!(
        "[admin = {}] Read record: {}|{}|{}",
        sender_did, request.entity_id, request.authority_id, request.assertion_id
    );

    let response_body = json!({
        "entity_id": record.entity_id().to_string(),
        "authority_id": record.authority_id().to_string(),
        "assertion_id": record.assertion_id().to_string(),
        "recognized": record.is_recognized(),
        "assertion_verified": record.is_assertion_verified(),
        "context": record.context().as_value()
    });

    transport::send_response(
        atm,
        profile,
        READ_RECORD_RESPONSE_MESSAGE_TYPE.to_string(),
        response_body,
        sender_did,
        thid,
        pthid,
    )
    .await?;

    Ok(())
}

pub async fn handle_list_records<R: ?Sized + TrustRecordAdminRepository>(
    handler: &AdminMessagesHandler<R>,
    atm: &Arc<ATM>,
    profile: &Arc<ATMProfile>,
    _message: Message,
    sender_did: &str,
    thid: Option<String>,
    pthid: Option<String>,
) -> Result<(), Box<dyn std::error::Error>> {
    debug!("Listing all records");

    let record_list = handler.repository.list().await.map_err(|e| e.to_string())?;

    let records_json: Vec<serde_json::Value> = record_list
        .records()
        .iter()
        .map(|record| {
            json!({
                "entity_id": record.entity_id().to_string(),
                "authority_id": record.authority_id().to_string(),
                "assertion_id": record.assertion_id().to_string(),
                "recognized": record.is_recognized(),
                "assertion_verified": record.is_assertion_verified(),
                "context": record.context().as_value()
            })
        })
        .collect();

    info!(
        "[admin = {}] Listed {} records",
        sender_did,
        records_json.len()
    );

    let response_body = json!({
        "records": records_json,
        "count": records_json.len()
    });

    transport::send_response(
        atm,
        profile,
        LIST_RECORDS_RESPONSE_MESSAGE_TYPE.to_string(),
        response_body,
        sender_did,
        thid,
        pthid,
    )
    .await?;

    Ok(())
}
