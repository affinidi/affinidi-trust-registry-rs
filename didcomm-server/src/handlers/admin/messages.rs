// TODO: refactor function signatures to reduce amount of input params
use std::sync::Arc;

use affinidi_tdk::{
    didcomm::Message,
    messaging::{ATM, profiles::ATMProfile},
};
use app::{
    audit::audit::{AuditOperation, AuditResource},
    domain::{Action, AuthorityId, Context, EntityId, Resource, TrustRecordBuilder},
    storage::repository::{TrustRecordAdminRepository, TrustRecordQuery},
};
use serde::Deserialize;
use serde_json::json;
use tracing::debug;

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
    action: String,
    resource: String,
    recognized: bool,
    authorized: bool,
    #[serde(default)]
    context: Option<serde_json::Value>,
}

#[derive(Debug, Deserialize)]
struct UpdateRecordRequest {
    entity_id: String,
    authority_id: String,
    action: String,
    resource: String,
    recognized: bool,
    authorized: bool,
    #[serde(default)]
    context: Option<serde_json::Value>,
}

#[derive(Debug, Deserialize)]
struct DeleteRecordRequest {
    entity_id: String,
    authority_id: String,
    action: String,
    resource: String,
}

#[derive(Debug, Deserialize)]
struct ReadRecordRequest {
    entity_id: String,
    authority_id: String,
    action: String,
    resource: String,
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
        "Creating record: {}|{}|{}|{}",
        request.entity_id, request.authority_id, request.action, request.resource
    );

    let mut builder = TrustRecordBuilder::new()
        .entity_id(EntityId::new(request.entity_id.clone()))
        .authority_id(AuthorityId::new(request.authority_id.clone()))
        .action(Action::new(request.action.clone()))
        .resource(Resource::new(request.resource.clone()))
        .recognized(request.recognized)
        .authorized(request.authorized);

    if let Some(ctx) = request.context {
        builder = builder.context(Context::new(ctx));
    }

    let record = builder.build().map_err(|e| e.to_string())?;

    let resource = AuditResource::from_record(&record);

    let result = handler.repository.create(record).await;

    match result {
        Ok(_) => {
            handler
                .audit_service
                .log_success(AuditOperation::Create, sender_did, resource, thid.clone())
                .await;

            let response_body = json!({
                "entity_id": request.entity_id,
                "authority_id": request.authority_id,
                "action": request.action,
                "resource": request.resource
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
        Err(e) => {
            let error_msg = e.to_string();
            handler
                .audit_service
                .log_failure(
                    AuditOperation::Create,
                    sender_did,
                    resource,
                    &error_msg,
                    thid,
                )
                .await;

            Err(error_msg.into())
        }
    }
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
        "Updating record: {}|{}|{}|{}",
        request.entity_id, request.authority_id, request.action, request.resource
    );

    let mut builder = TrustRecordBuilder::new()
        .entity_id(EntityId::new(request.entity_id.clone()))
        .authority_id(AuthorityId::new(request.authority_id.clone()))
        .action(Action::new(request.action.clone()))
        .resource(Resource::new(request.resource.clone()))
        .recognized(request.recognized)
        .authorized(request.authorized);

    if let Some(ctx) = request.context {
        builder = builder.context(Context::new(ctx));
    }

    let record = builder.build().map_err(|e| e.to_string())?;

    let resource = AuditResource::from_record(&record);

    let result = handler.repository.update(record).await;

    match result {
        Ok(_) => {
            handler
                .audit_service
                .log_success(AuditOperation::Update, sender_did, resource, thid.clone())
                .await;

            let response_body = json!({
                "entity_id": request.entity_id,
                "authority_id": request.authority_id,
                "action": request.action,
                "resource": request.resource
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
        Err(e) => {
            let error_msg = e.to_string();
            handler
                .audit_service
                .log_failure(
                    AuditOperation::Update,
                    sender_did,
                    resource,
                    &error_msg,
                    thid,
                )
                .await;

            Err(error_msg.into())
        }
    }
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
        "Deleting record: {}|{}|{}|{}",
        request.entity_id, request.authority_id, request.action, request.resource
    );

    let query = TrustRecordQuery::new(
        EntityId::new(request.entity_id.clone()),
        AuthorityId::new(request.authority_id.clone()),
        Action::new(request.action.clone()),
        Resource::new(request.resource.clone()),
    );

    let resource = AuditResource::new(
        Some(EntityId::new(request.entity_id.clone())),
        Some(AuthorityId::new(request.authority_id.clone())),
        Some(Action::new(request.action.clone())),
        Some(Resource::new(request.resource.clone())),
    );

    let result = handler.repository.delete(query).await;

    match result {
        Ok(_) => {
            handler
                .audit_service
                .log_success(AuditOperation::Delete, sender_did, resource, thid.clone())
                .await;

            let response_body = json!({
                "entity_id": request.entity_id,
                "authority_id": request.authority_id,
                "action": request.action,
                "resource": request.resource
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
        Err(e) => {
            let error_msg = e.to_string();
            handler
                .audit_service
                .log_failure(
                    AuditOperation::Delete,
                    sender_did,
                    resource,
                    &error_msg,
                    thid,
                )
                .await;

            Err(error_msg.into())
        }
    }
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
        "Reading record: {}|{}|{}|{}",
        request.entity_id, request.authority_id, request.action, request.resource
    );

    let query = TrustRecordQuery::new(
        EntityId::new(request.entity_id.clone()),
        AuthorityId::new(request.authority_id.clone()),
        Action::new(request.action.clone()),
        Resource::new(request.resource.clone()),
    );

    let resource = AuditResource::new(
        Some(EntityId::new(request.entity_id.clone())),
        Some(AuthorityId::new(request.authority_id.clone())),
        Some(Action::new(request.action.clone())),
        Some(Resource::new(request.resource.clone())),
    );

    let result = handler.repository.read(query).await;

    match result {
        Ok(record) => {
            handler
                .audit_service
                .log_success(AuditOperation::Read, sender_did, resource, thid.clone())
                .await;

            let response_body = json!({
                "entity_id": record.entity_id().to_string(),
                "authority_id": record.authority_id().to_string(),
                "action": record.action().to_string(),
                "resource": record.resource().to_string(),
                "recognized": record.is_recognized(),
                "authorized": record.is_authorized(),
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
        Err(e) => {
            let error_msg = e.to_string();
            handler
                .audit_service
                .log_failure(AuditOperation::Read, sender_did, resource, &error_msg, thid)
                .await;

            Err(error_msg.into())
        }
    }
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

    let resource = AuditResource::empty();

    let result = handler.repository.list().await;

    match result {
        Ok(record_list) => {
            let records_json: Vec<serde_json::Value> = record_list
                .records()
                .iter()
                .map(|record| {
                    json!({
                        "entity_id": record.entity_id().to_string(),
                        "authority_id": record.authority_id().to_string(),
                        "action": record.action().to_string(),
                        "resource": record.resource().to_string(),
                        "recognized": record.is_recognized(),
                        "authorized": record.is_authorized(),
                        "context": record.context().as_value()
                    })
                })
                .collect();

            handler
                .audit_service
                .log_success(AuditOperation::List, sender_did, resource, thid.clone())
                .await;

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
        Err(e) => {
            let error_msg = e.to_string();
            handler
                .audit_service
                .log_failure(AuditOperation::List, sender_did, resource, &error_msg, thid)
                .await;

            Err(error_msg.into())
        }
    }
}
