use crate::{
    audit::audit::{AuditLogger, AuditOperation, AuditResource},
    configs::AuditConfig,
};
use chrono::Utc;
use serde_json::{Value, json};
use tracing::info;

pub const AUDIT_ROLE_ADMIN: &str = "ADMIN";
pub const NA: &str = "N/A";

#[derive(Clone)]
pub struct LoggingAuditLogger {
    config: AuditConfig,
}

impl LoggingAuditLogger {
    pub fn new(config: AuditConfig) -> Self {
        Self { config }
    }

    fn thread_id_or_na(&self, thread_id: Option<String>) -> String {
        thread_id.unwrap_or_else(|| NA.to_string())
    }

    fn resource_json_value(&self, resource: &AuditResource) -> Value {
        json!({
            "entity_id": resource.entity_id.as_ref().map(|id| id.to_string()).unwrap_or(NA.to_string()),
            "authority_id": resource.authority_id.as_ref().map(|id| id.to_string()).unwrap_or(NA.to_string()),
            "action": resource.action.as_ref().map(|id| id.to_string()).unwrap_or(NA.to_string()),
            "resource": resource.resource.as_ref().map(|id| id.to_string()).unwrap_or(NA.to_string()),
        })
    }

    fn resource_text_fields(&self, resource: &AuditResource) -> (String, String, String, String) {
        (
            resource
                .entity_id
                .as_ref()
                .map(|id| id.to_string())
                .unwrap_or(NA.to_string()),
            resource
                .authority_id
                .as_ref()
                .map(|id| id.to_string())
                .unwrap_or(NA.to_string()),
            resource
                .action
                .as_ref()
                .map(|id| id.to_string())
                .unwrap_or(NA.to_string()),
            resource
                .resource
                .as_ref()
                .map(|id| id.to_string())
                .unwrap_or(NA.to_string()),
        )
    }

    fn emit_json(
        &self,
        target: &str,
        operation: &AuditOperation,
        actor: &str,
        status: &str,
        resource: &AuditResource,
        extra: Option<(&str, &str)>,
        thread_id: Option<String>,
        timestamp: chrono::DateTime<Utc>,
    ) {
        let mut map = serde_json::Map::new();
        let op_value = serde_json::to_value(operation).unwrap_or(json!(format!("{:?}", operation)));
        map.insert("role".to_string(), json!(AUDIT_ROLE_ADMIN));
        map.insert("actor".to_string(), json!(actor));
        map.insert("operation".to_string(), op_value);
        map.insert("status".to_string(), json!(status));
        map.insert("resource".to_string(), self.resource_json_value(resource));
        if let Some((k, v)) = extra {
            map.insert(k.to_string(), json!(v));
        }
        map.insert("timestamp".to_string(), json!(timestamp.to_rfc3339()));
        map.insert(
            "thread_id".to_string(),
            json!(self.thread_id_or_na(thread_id)),
        );
        let value = Value::Object(map);
        info!(target = ?target, "{}", value);
    }

    fn emit_text(
        &self,
        operation: &AuditOperation,
        actor: &str,
        status: &str,
        resource: &AuditResource,
        extra: Option<&str>,
        thread_id: Option<String>,
        timestamp: chrono::DateTime<Utc>,
    ) {
        let (entity_id, authority_id, action, resource_id) = self.resource_text_fields(resource);
        let thread_id_str = self.thread_id_or_na(thread_id);

        match (status, extra) {
            ("SUCCESS", None) => {
                info!(
                    audit.role=AUDIT_ROLE_ADMIN,
                    audit.actor = %actor,
                    audit.operation = ?operation,
                    audit.status = "SUCCESS",
                    audit.resource.entity_id = ?entity_id,
                    audit.resource.authority_id = ?authority_id,
                    audit.resource.action = ?action,
                    audit.resource.resource = ?resource_id,
                    audit.timestamp = %timestamp.to_rfc3339(),
                    audit.thread_id = ?thread_id_str,
                    "{}: {} operation by {} - SUCCESS",
                    AUDIT_ROLE_ADMIN,
                    operation,
                    actor
                );
            }
            ("FAILURE", Some(err)) => {
                info!(
                    audit.role=AUDIT_ROLE_ADMIN,
                    audit.actor = %actor,
                    audit.operation = ?operation,
                    audit.status = "FAILURE",
                    audit.resource.entity_id = ?entity_id,
                    audit.resource.authority_id = ?authority_id,
                    audit.resource.action = ?action,
                    audit.resource.resource = ?resource_id,
                    audit.error = %err,
                    audit.timestamp = %timestamp.to_rfc3339(),
                    audit.thread_id = ?thread_id_str,
                    "{}: {} operation by {} - FAILURE: {}",
                    AUDIT_ROLE_ADMIN,
                    operation,
                    actor,
                    err
                );
            }
            ("UNAUTHORIZED", Some(reason)) => {
                info!(
                    audit.role=AUDIT_ROLE_ADMIN,
                    audit.actor = %actor,
                    audit.operation = ?operation,
                    audit.status = "UNAUTHORIZED",
                    audit.resource.entity_id = ?entity_id,
                    audit.resource.authority_id = ?authority_id,
                    audit.resource.action = ?action,
                    audit.resource.resource = ?resource_id,
                    audit.reason = %reason,
                    audit.timestamp = %timestamp.to_rfc3339(),
                    audit.thread_id = ?thread_id_str,
                    "{}: {} operation by {} - UNAUTHORIZED: {}",
                    AUDIT_ROLE_ADMIN,
                    operation,
                    actor,
                    reason
                );
            }
            _ => {
                info!(
                    audit.role=AUDIT_ROLE_ADMIN,
                    audit.actor = %actor,
                    audit.operation = ?operation,
                    audit.status = %status,
                    audit.timestamp = %timestamp.to_rfc3339(),
                    audit.thread_id = ?thread_id_str,
                    "{}: {} operation by {} - {}",
                    AUDIT_ROLE_ADMIN,
                    operation,
                    actor,
                    status
                );
            }
        }
    }
}

#[async_trait::async_trait]
impl AuditLogger for LoggingAuditLogger {
    async fn log_success(
        &self,
        operation: AuditOperation,
        actor_did: &str,
        resource: AuditResource,
        thread_id: Option<String>,
    ) {
        let timestamp = Utc::now();
        match self.config.log_format {
            crate::configs::AuditLogFormat::Json => self.emit_json(
                AUDIT_ROLE_ADMIN,
                &operation,
                actor_did,
                "SUCCESS",
                &resource,
                None,
                thread_id,
                timestamp,
            ),
            crate::configs::AuditLogFormat::Text => self.emit_text(
                &operation, actor_did, "SUCCESS", &resource, None, thread_id, timestamp,
            ),
        }
    }

    async fn log_failure(
        &self,
        operation: AuditOperation,
        actor_did: &str,
        resource: AuditResource,
        error_message: &str,
        thread_id: Option<String>,
    ) {
        let timestamp = Utc::now();
        match self.config.log_format {
            crate::configs::AuditLogFormat::Json => self.emit_json(
                AUDIT_ROLE_ADMIN,
                &operation,
                actor_did,
                "FAILURE",
                &resource,
                Some(("error", error_message)),
                thread_id,
                timestamp,
            ),
            crate::configs::AuditLogFormat::Text => self.emit_text(
                &operation,
                actor_did,
                "FAILURE",
                &resource,
                Some(error_message),
                thread_id,
                timestamp,
            ),
        }
    }

    async fn log_unauthorized(
        &self,
        operation: AuditOperation,
        actor_did: &str,
        resource: AuditResource,
        reason: &str,
        thread_id: Option<String>,
    ) {
        let timestamp = Utc::now();
        match self.config.log_format {
            crate::configs::AuditLogFormat::Json => self.emit_json(
                AUDIT_ROLE_ADMIN,
                &operation,
                actor_did,
                "UNAUTHORIZED",
                &resource,
                Some(("reason", reason)),
                thread_id,
                timestamp,
            ),
            crate::configs::AuditLogFormat::Text => self.emit_text(
                &operation,
                actor_did,
                "UNAUTHORIZED",
                &resource,
                Some(reason),
                thread_id,
                timestamp,
            ),
        }
    }
}

// Tests pass if no panic occurs
#[cfg(test)]
mod tests {
    use super::*;
    use crate::configs::{AuditConfig, AuditLogFormat};
    use crate::domain::{Action, AuthorityId, EntityId, Resource};

    #[tokio::test]
    async fn test_log_success_text() {
        let config = AuditConfig {
            log_format: AuditLogFormat::Text,
        };
        let logger = LoggingAuditLogger::new(config);

        let resource = AuditResource::new(
            Some(EntityId::new("entity-1")),
            Some(AuthorityId::new("authority-1")),
            Some(Action::new("action-1")),
            Some(Resource::new("resource-1")),
        );

        logger
            .log_success(
                AuditOperation::Create,
                "did:example:admin",
                resource,
                Some("thread-1".to_string()),
            )
            .await;
    }
    #[tokio::test]
    async fn test_log_success_json() {
        let config = AuditConfig {
            log_format: AuditLogFormat::Json,
        };
        let logger = LoggingAuditLogger::new(config);

        let resource = AuditResource::new(
            Some(EntityId::new("entity-1")),
            Some(AuthorityId::new("authority-1")),
            Some(Action::new("action-1")),
            Some(Resource::new("resource-1")),
        );

        logger
            .log_success(
                AuditOperation::Create,
                "did:example:admin",
                resource,
                Some("thread-1".to_string()),
            )
            .await;
    }

    #[tokio::test]
    async fn test_log_failure_text() {
        let config = AuditConfig {
            log_format: AuditLogFormat::Text,
        };
        let logger = LoggingAuditLogger::new(config);

        let resource = AuditResource::empty();

        logger
            .log_failure(
                AuditOperation::Delete,
                "did:example:admin",
                resource,
                "Record not found",
                None,
            )
            .await;
    }
    #[tokio::test]
    async fn test_log_failure_json() {
        let config = AuditConfig {
            log_format: AuditLogFormat::Json,
        };
        let logger = LoggingAuditLogger::new(config);

        let resource = AuditResource::empty();

        logger
            .log_failure(
                AuditOperation::Delete,
                "did:example:admin",
                resource,
                "Record not found",
                None,
            )
            .await;
    }

    #[tokio::test]
    async fn test_log_unauthorized_text() {
        let config = AuditConfig {
            log_format: AuditLogFormat::Text,
        };
        let logger = LoggingAuditLogger::new(config);

        let resource = AuditResource::empty();

        logger
            .log_unauthorized(
                AuditOperation::Update,
                "did:example:unauthorized",
                resource,
                "Not in admin list",
                None,
            )
            .await;
    }
    #[tokio::test]
    async fn test_log_unauthorized_json() {
        let config = AuditConfig {
            log_format: AuditLogFormat::Json,
        };
        let logger = LoggingAuditLogger::new(config);

        let resource = AuditResource::empty();

        logger
            .log_unauthorized(
                AuditOperation::Update,
                "did:example:unauthorized",
                resource,
                "Not in admin list",
                None,
            )
            .await;
    }
}
