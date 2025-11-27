use crate::audit::model::{AuditLogBuilder, AuditLogger, AuditOperation, AuditResource};
use crate::storage::repository::TrustRecordAdminRepository;
use crate::{
    configs::AdminConfig,
    didcomm::{
        handlers::{HandlerContext, ProtocolHandler},
        problem_report, transport,
    },
};
use affinidi_tdk::didcomm::{Message, UnpackMetadata};
use async_trait::async_trait;
use std::sync::Arc;
use tracing::{error, info, warn};

pub mod messages;

// Message type constants
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

// Response message types
pub const CREATE_RECORD_RESPONSE_MESSAGE_TYPE: &str =
    "https://affinidi.com/didcomm/protocols/tr-admin/1.0/create-record/response";
pub const UPDATE_RECORD_RESPONSE_MESSAGE_TYPE: &str =
    "https://affinidi.com/didcomm/protocols/tr-admin/1.0/update-record/response";
pub const DELETE_RECORD_RESPONSE_MESSAGE_TYPE: &str =
    "https://affinidi.com/didcomm/protocols/tr-admin/1.0/delete-record/response";
pub const READ_RECORD_RESPONSE_MESSAGE_TYPE: &str =
    "https://affinidi.com/didcomm/protocols/tr-admin/1.0/read-record/response";
pub const LIST_RECORDS_RESPONSE_MESSAGE_TYPE: &str =
    "https://affinidi.com/didcomm/protocols/tr-admin/1.0/list-records/response";

pub struct AdminMessagesHandler<R: ?Sized + TrustRecordAdminRepository> {
    pub repository: Arc<R>,
    pub admin_config: AdminConfig,
    pub audit_service: Arc<dyn AuditLogger>,
}

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
                .map(|s| crate::domain::EntityId::new(s));
            let authority_id = body
                .get("authority_id")
                .and_then(|v| v.as_str())
                .map(|s| crate::domain::AuthorityId::new(s));
            let action = body
                .get("action")
                .and_then(|v| v.as_str())
                .map(|s| crate::domain::Action::new(s));
            let resource = body
                .get("resource")
                .and_then(|v| v.as_str())
                .map(|s| crate::domain::Resource::new(s));

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

impl<R: ?Sized + TrustRecordAdminRepository> AdminMessagesHandler<R> {
    pub fn new(
        repository: Arc<R>,
        admin_config: AdminConfig,
        audit_service: Arc<dyn AuditLogger>,
    ) -> Self {
        Self {
            repository,
            admin_config,
            audit_service,
        }
    }

    /// Validate that the sender DID is authorized as an admin
    fn validate_admin_did(&self, sender_did: &str) -> Result<(), String> {
        if self
            .admin_config
            .admin_dids
            .contains(&sender_did.to_string())
        {
            Ok(())
        } else {
            Err(format!(
                "Unauthorized: DID {} is not in admin list",
                sender_did
            ))
        }
    }

    async fn handle_success(
        &self,
        ctx: &Arc<HandlerContext>,
        response_message_type: String,
        response_body: serde_json::Value,
        operation: AuditOperation,
        resource: AuditResource,
    ) {
        self.audit_service
            .log(
                AuditLogBuilder::new()
                    .operation(operation)
                    .actor(&ctx.sender_did)
                    .resource(resource)
                    .thread_id(ctx.thid.clone())
                    .build_success(),
            )
            .await;

        if let Err(e) = transport::send_response(
            &ctx.atm,
            &ctx.profile,
            response_message_type,
            response_body,
            &ctx.sender_did,
            ctx.thid.clone(),
            ctx.pthid.clone(),
        )
        .await
        {
            error!("Failed to send response: {}", e);
        }
    }

    async fn handle_failure(
        &self,
        ctx: &Arc<HandlerContext>,
        error_msg: String,
        operation: AuditOperation,
        resource: AuditResource,
    ) {
        self.audit_service
            .log(
                AuditLogBuilder::new()
                    .operation(operation)
                    .actor(&ctx.sender_did)
                    .resource(resource)
                    .thread_id(ctx.thid.clone())
                    .build_failure(&error_msg),
            )
            .await;

        error!(
            "[profile = {}] Admin operation failed: {}",
            &ctx.profile.inner.alias, error_msg
        );
        let report = problem_report::ProblemReport::internal_error(error_msg);
        if let Err(send_err) = problem_report::send_problem_report(
            &ctx.atm,
            &ctx.profile,
            report,
            &ctx.sender_did,
            ctx.thid.clone(),
            ctx.pthid.clone(),
        )
        .await
        {
            error!("Failed to send problem report: {}", send_err);
        }
    }

    async fn handle_unauthorized(
        &self,
        ctx: &Arc<HandlerContext>,
        auth_error: String,
        message_type: &str,
    ) {
        warn!(
            "[profile = {}] Unauthorized admin access attempt from {}: {}",
            &ctx.profile.inner.alias, ctx.sender_did, auth_error
        );

        let operation = get_operation_from_message_type(message_type);

        self.audit_service
            .log(
                AuditLogBuilder::new()
                    .operation(operation)
                    .actor(&ctx.sender_did)
                    .resource(AuditResource::empty())
                    .thread_id(ctx.thid.clone())
                    .build_unauthorized(&auth_error),
            )
            .await;

        let report = problem_report::ProblemReport::unauthorized(auth_error);
        if let Err(e) = problem_report::send_problem_report(
            &ctx.atm,
            &ctx.profile,
            report,
            &ctx.sender_did,
            ctx.thid.clone(),
            ctx.pthid.clone(),
        )
        .await
        {
            error!("Failed to send problem report: {}", e);
        }
    }

    async fn handle_request(
        &self,
        ctx: &Arc<HandlerContext>,
        message: Message,
        message_type: &str,
    ) -> Result<(), Box<dyn std::error::Error>> {
        info!(
            "[profile = {}] Admin operation: {} from {}",
            &ctx.profile.inner.alias, message_type, ctx.sender_did
        );

        let operation = get_operation_from_message_type(message_type);
        let resource = extract_audit_resource(&message);

        let (response_message_type, handler_result) = match message_type {
            CREATE_RECORD_MESSAGE_TYPE => (
                CREATE_RECORD_RESPONSE_MESSAGE_TYPE,
                messages::handle_create_record(self, message).await,
            ),
            UPDATE_RECORD_MESSAGE_TYPE => (
                UPDATE_RECORD_RESPONSE_MESSAGE_TYPE,
                messages::handle_update_record(self, message).await,
            ),
            DELETE_RECORD_MESSAGE_TYPE => (
                DELETE_RECORD_RESPONSE_MESSAGE_TYPE,
                messages::handle_delete_record(self, message).await,
            ),
            READ_RECORD_MESSAGE_TYPE => (
                READ_RECORD_RESPONSE_MESSAGE_TYPE,
                messages::handle_read_record(self, message).await,
            ),
            LIST_RECORDS_MESSAGE_TYPE => (
                LIST_RECORDS_RESPONSE_MESSAGE_TYPE,
                messages::handle_list_records(self).await,
            ),
            _ => {
                warn!("Unknown admin message type: {}", message_type);
                let report = problem_report::ProblemReport::bad_request(format!(
                    "Unknown message type: {}",
                    message_type
                ));
                if let Err(e) = problem_report::send_problem_report(
                    &ctx.atm,
                    &ctx.profile,
                    report,
                    &ctx.sender_did,
                    ctx.thid.clone(),
                    ctx.pthid.clone(),
                )
                .await
                {
                    error!("Failed to send problem report: {}", e);
                }
                return Ok(());
            }
        };

        match handler_result {
            Ok(response_body) => {
                self.handle_success(
                    ctx,
                    response_message_type.to_string(),
                    response_body,
                    operation,
                    resource,
                )
                .await
            }
            Err(error_msg) => {
                self.handle_failure(ctx, error_msg, operation, resource)
                    .await
            }
        };

        Ok(())
    }
}

#[async_trait]
impl<R: ?Sized + TrustRecordAdminRepository + 'static> ProtocolHandler for AdminMessagesHandler<R> {
    fn get_supported_inbound_message_types(&self) -> Vec<String> {
        vec![
            CREATE_RECORD_MESSAGE_TYPE.to_string(),
            UPDATE_RECORD_MESSAGE_TYPE.to_string(),
            DELETE_RECORD_MESSAGE_TYPE.to_string(),
            READ_RECORD_MESSAGE_TYPE.to_string(),
            LIST_RECORDS_MESSAGE_TYPE.to_string(),
        ]
    }

    async fn handle(
        &self,
        ctx: &Arc<HandlerContext>,
        message: Message,
        _meta: UnpackMetadata,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let message_type = message.type_.clone();

        if let Err(auth_error) = self.validate_admin_did(&ctx.sender_did) {
            self.handle_unauthorized(ctx, auth_error, &message_type)
                .await;
            return Ok(());
        }

        self.handle_request(ctx, message, &message_type).await
    }
}
