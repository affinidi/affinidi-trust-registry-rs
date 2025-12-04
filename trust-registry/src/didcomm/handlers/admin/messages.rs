use std::str::FromStr;

// TODO: refactor function signatures to reduce amount of input params
use crate::{
    domain::{Action, AuthorityId, Context, EntityId, RecordType, Resource, TrustRecordBuilder},
    storage::repository::{TrustRecordAdminRepository, TrustRecordQuery},
};
use affinidi_tdk::didcomm::Message;
use serde::Deserialize;
use serde_json::json;
use tracing::debug;

use super::AdminMessagesHandler;

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
    record_type: String,
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
    record_type: String,
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
    message: Message,
) -> Result<serde_json::Value, String> {
    let request: CreateRecordRequest =
        serde_json::from_value(message.body).map_err(|e| e.to_string())?;

    debug!(
        "Creating record: {}|{}|{}|{}",
        request.entity_id, request.authority_id, request.action, request.resource
    );

    let record_type = RecordType::from_str(&request.record_type).map_err(|e| e.to_string())?;

    let mut builder = TrustRecordBuilder::new()
        .entity_id(EntityId::new(request.entity_id.clone()))
        .authority_id(AuthorityId::new(request.authority_id.clone()))
        .action(Action::new(request.action.clone()))
        .resource(Resource::new(request.resource.clone()))
        .recognized(request.recognized)
        .authorized(request.authorized)
        .record_type(record_type);

    if let Some(ctx) = request.context {
        builder = builder.context(Context::new(ctx));
    }

    let record = builder.build().map_err(|e| e.to_string())?;

    handler
        .repository
        .create(record)
        .await
        .map_err(|e| e.to_string())?;

    Ok(json!({
        "entity_id": request.entity_id,
        "authority_id": request.authority_id,
        "action": request.action,
        "resource": request.resource
    }))
}

pub async fn handle_update_record<R: ?Sized + TrustRecordAdminRepository>(
    handler: &AdminMessagesHandler<R>,
    message: Message,
) -> Result<serde_json::Value, String> {
    let request: UpdateRecordRequest =
        serde_json::from_value(message.body).map_err(|e| e.to_string())?;

    debug!(
        "Updating record: {}|{}|{}|{}",
        request.entity_id, request.authority_id, request.action, request.resource
    );
    let record_type = RecordType::from_str(&request.record_type).map_err(|e| e.to_string())?;
    let mut builder = TrustRecordBuilder::new()
        .entity_id(EntityId::new(request.entity_id.clone()))
        .authority_id(AuthorityId::new(request.authority_id.clone()))
        .action(Action::new(request.action.clone()))
        .resource(Resource::new(request.resource.clone()))
        .recognized(request.recognized)
        .authorized(request.authorized)
        .record_type(record_type);

    if let Some(ctx) = request.context {
        builder = builder.context(Context::new(ctx));
    }

    let record = builder.build().map_err(|e| e.to_string())?;

    handler
        .repository
        .update(record)
        .await
        .map_err(|e| e.to_string())?;

    Ok(json!({
        "entity_id": request.entity_id,
        "authority_id": request.authority_id,
        "action": request.action,
        "resource": request.resource
    }))
}

pub async fn handle_delete_record<R: ?Sized + TrustRecordAdminRepository>(
    handler: &AdminMessagesHandler<R>,
    message: Message,
) -> Result<serde_json::Value, String> {
    let request: DeleteRecordRequest =
        serde_json::from_value(message.body).map_err(|e| e.to_string())?;

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

    handler
        .repository
        .delete(query)
        .await
        .map_err(|e| e.to_string())?;

    Ok(json!({
        "entity_id": request.entity_id,
        "authority_id": request.authority_id,
        "action": request.action,
        "resource": request.resource
    }))
}

pub async fn handle_read_record<R: ?Sized + TrustRecordAdminRepository>(
    handler: &AdminMessagesHandler<R>,
    message: Message,
) -> Result<serde_json::Value, String> {
    let request: ReadRecordRequest =
        serde_json::from_value(message.body).map_err(|e| e.to_string())?;

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

    let record = handler
        .repository
        .read(query)
        .await
        .map_err(|e| e.to_string())?;

    Ok(json!({
        "entity_id": record.entity_id().to_string(),
        "authority_id": record.authority_id().to_string(),
        "action": record.action().to_string(),
        "resource": record.resource().to_string(),
        "recognized": record.is_recognized(),
        "authorized": record.is_authorized(),
        "context": record.context().as_value()
    }))
}

pub async fn handle_list_records<R: ?Sized + TrustRecordAdminRepository>(
    handler: &AdminMessagesHandler<R>,
) -> Result<serde_json::Value, String> {
    debug!("Listing all records");

    let record_list = handler.repository.list().await.map_err(|e| e.to_string())?;

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

    Ok(json!({
        "records": records_json,
        "count": records_json.len()
    }))
}
