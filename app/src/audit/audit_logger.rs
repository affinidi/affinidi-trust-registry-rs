use crate::{
    audit::audit::{AuditLogger, AuditOperation, AuditResource},
    configs::AuditConfig,
};
use chrono::Utc;
use serde_json::json;
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
            crate::configs::AuditLogFormat::Json => {
                let log_entry = json!({
                    "role": AUDIT_ROLE_ADMIN,
                    "actor": actor_did,
                    "operation": operation,
                    "status": "SUCCESS",
                    "resource": {
                        "entity_id": resource.entity_id.as_ref().map(|id| id.to_string()).unwrap_or(NA.to_string()),
                        "authority_id": resource.authority_id.as_ref().map(|id| id.to_string()).unwrap_or(NA.to_string()),
                        "assertion_id": resource.assertion_id.as_ref().map(|id| id.to_string()).unwrap_or(NA.to_string()),
                    },
                    "timestamp": timestamp.to_rfc3339(),
                    "thread_id": thread_id.unwrap_or(NA.to_string()),
                });
                info!(target: "audit", "{}", log_entry);
            }
            crate::configs::AuditLogFormat::Text => {
                info!(
                    audit.role=AUDIT_ROLE_ADMIN,
                    audit.actor = %actor_did,
                    audit.operation = ?operation,
                    audit.status = "SUCCESS",
                    audit.resource.entity_id = ?resource.entity_id.as_ref().map(|id| id.to_string()).unwrap_or(NA.to_string()),
                    audit.resource.authority_id = ?resource.authority_id.as_ref().map(|id| id.to_string()).unwrap_or(NA.to_string()),
                    audit.resource.assertion_id = ?resource.assertion_id.as_ref().map(|id| id.to_string()).unwrap_or(NA.to_string()),
                    audit.timestamp = %timestamp.to_rfc3339(),
                    audit.thread_id = ?thread_id.unwrap_or(NA.to_string()),
                    "{}: {} operation by {} - SUCCESS",
                    AUDIT_ROLE_ADMIN,
                    operation,
                    actor_did
                );
            }
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
            crate::configs::AuditLogFormat::Json => {
                let log_entry = json!({
                    "role": AUDIT_ROLE_ADMIN,
                    "actor": actor_did,
                    "operation": operation,
                    "status": "FAILURE",
                    "resource": {
                        "entity_id": resource.entity_id.as_ref().map(|id| id.to_string()).unwrap_or(NA.to_string()),
                        "authority_id": resource.authority_id.as_ref().map(|id| id.to_string()).unwrap_or(NA.to_string()),
                        "assertion_id": resource.assertion_id.as_ref().map(|id| id.to_string()).unwrap_or(NA.to_string()),
                    },
                    "error": error_message,
                    "timestamp": timestamp.to_rfc3339(),
                    "thread_id": thread_id.unwrap_or(NA.to_string()),
                });
                info!(target: "audit", "{}", log_entry);
            }
            crate::configs::AuditLogFormat::Text => {
                info!(
                    audit.role=AUDIT_ROLE_ADMIN,
                    audit.actor = %actor_did,
                    audit.operation = ?operation,
                    audit.status = "FAILURE",
                    audit.resource.entity_id = ?resource.entity_id.as_ref().map(|id| id.to_string()).unwrap_or(NA.to_string()),
                    audit.resource.authority_id = ?resource.authority_id.as_ref().map(|id| id.to_string()).unwrap_or(NA.to_string()),
                    audit.resource.assertion_id = ?resource.assertion_id.as_ref().map(|id| id.to_string()).unwrap_or(NA.to_string()),
                    audit.error = %error_message,
                    audit.timestamp = %timestamp.to_rfc3339(),
                    audit.thread_id = ?thread_id.unwrap_or(NA.to_string()),
                    "{}: {} operation by {} - FAILURE: {}",
                    AUDIT_ROLE_ADMIN,
                    operation,
                    actor_did,
                    error_message
                );
            }
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
            crate::configs::AuditLogFormat::Json => {
                let log_entry = json!({
                    "role": AUDIT_ROLE_ADMIN,
                    "actor": actor_did,
                    "operation": operation,
                    "status": "UNAUTHORIZED",
                    "resource": {
                        "entity_id": resource.entity_id.as_ref().map(|id| id.to_string()).unwrap_or(NA.to_string()),
                        "authority_id": resource.authority_id.as_ref().map(|id| id.to_string()).unwrap_or(NA.to_string()),
                        "assertion_id": resource.assertion_id.as_ref().map(|id| id.to_string()).unwrap_or(NA.to_string()),
                    },
                    "reason": reason,
                    "timestamp": timestamp.to_rfc3339(),
                    "thread_id": thread_id.unwrap_or(NA.to_string()),
                });
                info!(target: "audit", "{}", log_entry);
            }
            crate::configs::AuditLogFormat::Text => {
                info!(
                    audit.role=AUDIT_ROLE_ADMIN,
                    audit.actor = %actor_did,
                    audit.operation = ?operation,
                    audit.status = "UNAUTHORIZED",
                    audit.resource.entity_id = ?resource.entity_id.as_ref().map(|id| id.to_string()).unwrap_or(NA.to_string()),
                    audit.resource.authority_id = ?resource.authority_id.as_ref().map(|id| id.to_string()).unwrap_or(NA.to_string()),
                    audit.resource.assertion_id = ?resource.assertion_id.as_ref().map(|id| id.to_string()).unwrap_or(NA.to_string()),
                    audit.reason = %reason,
                    audit.timestamp = %timestamp.to_rfc3339(),
                    audit.thread_id = ?thread_id.unwrap_or(NA.to_string()),
                    "{}: {} operation by {} - UNAUTHORIZED: {}",
                    AUDIT_ROLE_ADMIN,
                    operation,
                    actor_did,
                    reason
                );
            }
        }
    }
}

// Tests pass if no panic occurs
#[cfg(test)]
mod tests {
    use super::*;
    use crate::configs::{AuditConfig, AuditLogFormat};
    use crate::domain::{AssertionId, AuthorityId, EntityId};

    #[tokio::test]
    async fn test_log_success_text() {
        let config = AuditConfig {
            log_format: AuditLogFormat::Text,
        };
        let logger = LoggingAuditLogger::new(config);

        let resource = AuditResource::new(
            Some(EntityId::new("entity-1")),
            Some(AuthorityId::new("authority-1")),
            Some(AssertionId::new("assertion-1")),
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
            Some(AssertionId::new("assertion-1")),
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
