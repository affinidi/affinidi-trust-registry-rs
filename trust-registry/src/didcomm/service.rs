use std::sync::Arc;

use affinidi_messaging_didcomm::Message;
use affinidi_messaging_didcomm_service::{
    DIDCommResponse, DIDCommService, DIDCommServiceConfig, DIDCommServiceError, Extension,
    HandlerContext, ListenerConfig, MESSAGE_PICKUP_STATUS_TYPE, MessagePolicy, ProblemReport,
    Protocols, RequestLogging, RestartPolicy, RetryConfig, Router, ServiceProblemReport,
    TRUST_PING_TYPE, handler_fn, ignore_handler, trust_ping_handler,
};
use affinidi_tdk::common::profiles::TDKProfile;
use serde_json::json;
use tokio_util::sync::CancellationToken;
use tracing::{error, info, warn};

use crate::audit::audit_logger::BaseAuditLogger;
use crate::audit::model::{AuditLogBuilder, AuditLogger, AuditOperation, AuditResource};
use crate::configs::{AdminConfig, DidcommConfig};
use crate::domain;
use crate::storage::repository::TrustRecordAdminRepository;

use super::handlers::admin::{
    CREATE_RECORD_MESSAGE_TYPE, CREATE_RECORD_RESPONSE_MESSAGE_TYPE, DELETE_RECORD_MESSAGE_TYPE,
    DELETE_RECORD_RESPONSE_MESSAGE_TYPE, LIST_RECORDS_MESSAGE_TYPE,
    LIST_RECORDS_RESPONSE_MESSAGE_TYPE, READ_RECORD_MESSAGE_TYPE,
    READ_RECORD_RESPONSE_MESSAGE_TYPE, UPDATE_RECORD_MESSAGE_TYPE,
    UPDATE_RECORD_RESPONSE_MESSAGE_TYPE,
};
use super::handlers::trqp::QUERY_AUTHORIZATION_MESSAGE_TYPE;

// ─── Shared state types ─────────────────────────────────────────────────────

type Repo = Arc<dyn TrustRecordAdminRepository>;
type Audit = Arc<dyn AuditLogger>;

// ─── Admin handler ──────────────────────────────────────────────────────────

async fn admin_handler(
    ctx: HandlerContext,
    message: Message,
    Extension(repo): Extension<Repo>,
    Extension(admin_config): Extension<AdminConfig>,
    Extension(audit): Extension<Audit>,
) -> Result<Option<DIDCommResponse>, DIDCommServiceError> {
    let sender_did = ctx.sender_did.as_deref().unwrap_or("anon").to_string();
    let message_type = message.typ.clone();

    // Inline admin DID check (decision #2)
    if !admin_config.admin_dids.contains(&sender_did) {
        warn!("Unauthorized admin access attempt from {}", sender_did);

        let operation = get_operation_from_message_type(&message_type);
        audit
            .log(
                AuditLogBuilder::new()
                    .operation(operation)
                    .actor(&sender_did)
                    .resource(AuditResource::empty())
                    .thread_id(Some(ctx.thread_id.clone()))
                    .build_unauthorized(format!(
                        "Unauthorized: DID {sender_did} is not in admin list"
                    )),
            )
            .await;

        let report = ProblemReport::unauthorized(format!(
            "Unauthorized: DID {sender_did} is not in admin list"
        ));
        return Ok(Some(DIDCommResponse::problem_report(report)));
    }

    let operation = get_operation_from_message_type(&message_type);
    let resource = extract_audit_resource(&message);

    info!("Admin operation: {} from {}", message_type, sender_did);

    let (response_message_type, handler_result) = match message_type.as_str() {
        CREATE_RECORD_MESSAGE_TYPE => (
            CREATE_RECORD_RESPONSE_MESSAGE_TYPE,
            handle_create_record(&repo, message).await,
        ),
        UPDATE_RECORD_MESSAGE_TYPE => (
            UPDATE_RECORD_RESPONSE_MESSAGE_TYPE,
            handle_update_record(&repo, message).await,
        ),
        DELETE_RECORD_MESSAGE_TYPE => (
            DELETE_RECORD_RESPONSE_MESSAGE_TYPE,
            handle_delete_record(&repo, message).await,
        ),
        READ_RECORD_MESSAGE_TYPE => (
            READ_RECORD_RESPONSE_MESSAGE_TYPE,
            handle_read_record(&repo, message).await,
        ),
        LIST_RECORDS_MESSAGE_TYPE => (
            LIST_RECORDS_RESPONSE_MESSAGE_TYPE,
            handle_list_records(&repo).await,
        ),
        _ => {
            warn!("Unknown admin message type: {}", message_type);
            let report =
                ProblemReport::bad_request(format!("Unknown message type: {message_type}"));
            return Ok(Some(DIDCommResponse::problem_report(report)));
        }
    };

    match handler_result {
        Ok(response_body) => {
            // Audit success inline (decision #3)
            audit
                .log(
                    AuditLogBuilder::new()
                        .operation(operation)
                        .actor(&sender_did)
                        .resource(resource)
                        .thread_id(Some(ctx.thread_id.clone()))
                        .build_success(),
                )
                .await;

            Ok(Some(DIDCommResponse::new(
                response_message_type,
                response_body,
            )))
        }
        Err(error_msg) => {
            // Audit failure inline (decision #3)
            error!("Admin operation failed: {}", error_msg);
            audit
                .log(
                    AuditLogBuilder::new()
                        .operation(operation)
                        .actor(&sender_did)
                        .resource(resource)
                        .thread_id(Some(ctx.thread_id.clone()))
                        .build_failure(&error_msg),
                )
                .await;

            let report = ProblemReport::internal_error(error_msg);
            Ok(Some(DIDCommResponse::problem_report(report)))
        }
    }
}

// ─── TRQP handler ───────────────────────────────────────────────────────────

async fn trqp_handler(
    _ctx: HandlerContext,
    message: Message,
    Extension(repo): Extension<Repo>,
) -> Result<Option<DIDCommResponse>, DIDCommServiceError> {
    use crate::storage::repository::TrustRecordQuery;
    use chrono::{SecondsFormat, Utc};

    let requested_at = Utc::now();
    let is_authorization = message.typ == QUERY_AUTHORIZATION_MESSAGE_TYPE;
    let output_message_type = format!("{}/response", message.typ);

    let query: TrustRecordQuery = serde_json::from_value(message.body)
        .map_err(|e| DIDCommServiceError::Handler(e.to_string()))?;

    let record = repo
        .find_by_query(query)
        .await
        .map_err(|e| DIDCommServiceError::Handler(e.to_string()))?;

    let evaluated_at = Utc::now();

    let mut output_body = json!({});
    if let Some(tr) = record {
        let tr = if is_authorization {
            tr.none_recognized()
        } else {
            tr.none_authorized()
        };

        let message_text = if is_authorization {
            format!(
                "{} authorized to {}+{} by {}",
                tr.entity_id(),
                tr.action(),
                tr.resource(),
                tr.authority_id()
            )
        } else {
            format!("{} recognized by {}", tr.entity_id(), tr.authority_id())
        };

        output_body = serde_json::to_value(&tr).unwrap_or_default();
        if let Some(obj) = output_body.as_object_mut() {
            obj.insert(
                "time_requested".to_string(),
                json!(requested_at.to_rfc3339_opts(SecondsFormat::Secs, true)),
            );
            obj.insert(
                "time_evaluated".to_string(),
                json!(evaluated_at.to_rfc3339_opts(SecondsFormat::Secs, true)),
            );
            obj.insert("message".to_string(), json!(message_text));
        }
    }

    Ok(Some(DIDCommResponse::new(output_message_type, output_body)))
}

// ─── Admin business logic wrappers ──────────────────────────────────────────
// These delegate to the existing messages.rs functions but with a simpler
// signature (no AdminMessagesHandler self param).

use crate::domain::{
    Action, AuthorityId, Context, EntityId, RecordType, Resource, TrustRecordBuilder,
};
use crate::storage::repository::TrustRecordQuery;
use serde::Deserialize;
use std::str::FromStr;

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

async fn handle_create_record(
    repo: &Arc<dyn TrustRecordAdminRepository>,
    message: Message,
) -> Result<serde_json::Value, String> {
    let request: CreateRecordRequest =
        serde_json::from_value(message.body).map_err(|e| e.to_string())?;

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
    repo.create(record).await.map_err(|e| e.to_string())?;

    Ok(json!({
        "entity_id": request.entity_id,
        "authority_id": request.authority_id,
        "action": request.action,
        "resource": request.resource
    }))
}

async fn handle_update_record(
    repo: &Arc<dyn TrustRecordAdminRepository>,
    message: Message,
) -> Result<serde_json::Value, String> {
    let request: UpdateRecordRequest =
        serde_json::from_value(message.body).map_err(|e| e.to_string())?;

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
    repo.update(record).await.map_err(|e| e.to_string())?;

    Ok(json!({
        "entity_id": request.entity_id,
        "authority_id": request.authority_id,
        "action": request.action,
        "resource": request.resource
    }))
}

async fn handle_delete_record(
    repo: &Arc<dyn TrustRecordAdminRepository>,
    message: Message,
) -> Result<serde_json::Value, String> {
    let request: DeleteRecordRequest =
        serde_json::from_value(message.body).map_err(|e| e.to_string())?;

    let query = TrustRecordQuery::new(
        EntityId::new(request.entity_id.clone()),
        AuthorityId::new(request.authority_id.clone()),
        Action::new(request.action.clone()),
        Resource::new(request.resource.clone()),
    );

    repo.delete(query).await.map_err(|e| e.to_string())?;

    Ok(json!({
        "entity_id": request.entity_id,
        "authority_id": request.authority_id,
        "action": request.action,
        "resource": request.resource
    }))
}

async fn handle_read_record(
    repo: &Arc<dyn TrustRecordAdminRepository>,
    message: Message,
) -> Result<serde_json::Value, String> {
    let request: ReadRecordRequest =
        serde_json::from_value(message.body).map_err(|e| e.to_string())?;

    let query = TrustRecordQuery::new(
        EntityId::new(request.entity_id.clone()),
        AuthorityId::new(request.authority_id.clone()),
        Action::new(request.action.clone()),
        Resource::new(request.resource.clone()),
    );

    let record = repo.read(query).await.map_err(|e| e.to_string())?;

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

async fn handle_list_records(
    repo: &Arc<dyn TrustRecordAdminRepository>,
) -> Result<serde_json::Value, String> {
    let record_list = repo.list().await.map_err(|e| e.to_string())?;

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

// ─── Helpers ────────────────────────────────────────────────────────────────

fn get_operation_from_message_type(message_type: &str) -> AuditOperation {
    match message_type {
        CREATE_RECORD_MESSAGE_TYPE => AuditOperation::Create,
        UPDATE_RECORD_MESSAGE_TYPE => AuditOperation::Update,
        DELETE_RECORD_MESSAGE_TYPE => AuditOperation::Delete,
        READ_RECORD_MESSAGE_TYPE => AuditOperation::Read,
        LIST_RECORDS_MESSAGE_TYPE => AuditOperation::List,
        _ => AuditOperation::Create,
    }
}

fn extract_audit_resource(message: &Message) -> AuditResource {
    message
        .body
        .as_object()
        .and_then(|body| {
            let entity_id = body
                .get("entity_id")
                .and_then(|v| v.as_str())
                .map(domain::EntityId::new);
            let authority_id = body
                .get("authority_id")
                .and_then(|v| v.as_str())
                .map(domain::AuthorityId::new);
            let action = body
                .get("action")
                .and_then(|v| v.as_str())
                .map(domain::Action::new);
            let resource = body
                .get("resource")
                .and_then(|v| v.as_str())
                .map(domain::Resource::new);

            if entity_id.is_some()
                || authority_id.is_some()
                || action.is_some()
                || resource.is_some()
            {
                Some(AuditResource::new(
                    entity_id,
                    authority_id,
                    action,
                    resource,
                ))
            } else {
                None
            }
        })
        .unwrap_or_else(AuditResource::empty)
}

// ─── Router builder ─────────────────────────────────────────────────────────

fn build_router(
    repo: Repo,
    admin_config: AdminConfig,
    audit: Audit,
) -> Result<Router, DIDCommServiceError> {
    let router = Router::new()
        .extension(repo)
        .extension(admin_config)
        .extension(audit)
        // Built-in protocols
        .route(TRUST_PING_TYPE, handler_fn(trust_ping_handler))
        .map_err(|e| DIDCommServiceError::Handler(e.to_string()))?
        .route(MESSAGE_PICKUP_STATUS_TYPE, handler_fn(ignore_handler))
        .map_err(|e| DIDCommServiceError::Handler(e.to_string()))?
        // Admin routes (regex matches all tr-admin message types)
        .route_regex(
            r"https://affinidi\.com/didcomm/protocols/tr-admin/1\.0/.+",
            handler_fn(admin_handler),
        )
        .map_err(|e| DIDCommServiceError::Handler(e.to_string()))?
        // TRQP routes (regex matches all trqp message types)
        .route_regex(
            r"https://affinidi\.com/didcomm/protocols/trqp/1\.0/.+",
            handler_fn(trqp_handler),
        )
        .map_err(|e| DIDCommServiceError::Handler(e.to_string()))?
        // Global middleware
        .layer(
            MessagePolicy::new()
                .require_encrypted(true)
                .require_authenticated(true)
                .allow_anonymous_sender(false),
        )
        .layer(RequestLogging);

    Ok(router)
}

// ─── Public entry point ─────────────────────────────────────────────────────

pub async fn start_didcomm_service(
    config: DidcommConfig,
    repository: Arc<dyn TrustRecordAdminRepository>,
    shutdown: CancellationToken,
) -> Result<DIDCommService, Box<dyn std::error::Error + Send + Sync>> {
    let audit: Audit = Arc::new(BaseAuditLogger::new(
        config.admin_config.audit_config.clone(),
    ));

    let listener_config = ListenerConfig {
        id: "trust-registry-listener".to_string(),
        profile: TDKProfile::new(
            &config.profile_config.alias,
            &config.profile_config.did,
            Some(&config.mediator_did),
            config.profile_config.secrets.clone(),
        ),
        restart_policy: RestartPolicy::Always {
            backoff: RetryConfig {
                initial_delay_secs: 5,
                max_delay_secs: 60,
            },
        },
        acl_mode: Some(config.acl_mode),
        protocols: Protocols::DIDCOMM_ONLY,
        ..Default::default()
    };

    let service_config = DIDCommServiceConfig {
        listeners: vec![listener_config],
    };

    let router = build_router(repository, config.admin_config, audit)?;

    let service = DIDCommService::start(service_config, router, shutdown).await?;

    info!("DIDComm service started successfully");

    Ok(service)
}
