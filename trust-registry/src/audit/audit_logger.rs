use crate::{
    audit::model::{AuditLog, AuditLogger, AuditOperation, AuditResource},
    configs::AuditConfig,
};
use chrono::Utc;
use serde_json::{Value, json};
use tracing::info;

pub use crate::audit::model::{AuditLogBuilder, AuditStatus};

pub const AUDIT_ROLE_ADMIN: &str = "ADMIN";
pub const NA: &str = "N/A";

pub struct EmitInput {
    pub target: String,
    pub operation: AuditOperation,
    pub actor: String,
    pub status: String,
    pub resource: AuditResource,
    pub extra: Option<String>,
    pub thread_id: Option<String>,
    pub timestamp: chrono::DateTime<Utc>,
}
#[derive(Clone)]
pub struct BaseAuditLogger {
    config: AuditConfig,
}

impl BaseAuditLogger {
    pub fn new(config: AuditConfig) -> Self {
        Self { config }
    }

    fn thread_id_or_na(&self, thread_id: Option<String>) -> String {
        thread_id.unwrap_or_else(|| NA.to_string())
    }

    fn opt_to_string<T: ToString>(&self, opt: &Option<T>) -> String {
        opt.as_ref()
            .map_or_else(|| NA.to_string(), |v| v.to_string())
    }

    fn resource_json_value(&self, resource: &AuditResource) -> Value {
        json!({
            "entity_id": self.opt_to_string(&resource.entity_id),
            "authority_id": self.opt_to_string(&resource.authority_id),
            "action": self.opt_to_string(&resource.action),
            "resource": self.opt_to_string(&resource.resource),
        })
    }

    fn resource_text_fields(&self, resource: &AuditResource) -> (String, String, String, String) {
        (
            self.opt_to_string(&resource.entity_id),
            self.opt_to_string(&resource.authority_id),
            self.opt_to_string(&resource.action),
            self.opt_to_string(&resource.resource),
        )
    }

    fn emit_json(&self, input: &EmitInput) {
        let mut map = serde_json::Map::new();
        let op_value = serde_json::to_value(input.operation)
            .unwrap_or(json!(format!("{:?}", input.operation)));
        map.insert("role".to_string(), json!(AUDIT_ROLE_ADMIN));
        map.insert("actor".to_string(), json!(input.actor));
        map.insert("operation".to_string(), op_value);
        map.insert("status".to_string(), json!(input.status));
        map.insert(
            "resource".to_string(),
            self.resource_json_value(&input.resource),
        );
        if let Some(extra_field) = input.extra.clone() {
            let ex = extra_field.split("=").collect::<Vec<&str>>()[..2]
                .iter()
                .map(|f| f.to_string())
                .collect::<Vec<String>>();
            map.insert(ex[0].to_string(), json!(ex[1]));
        }
        map.insert("timestamp".to_string(), json!(input.timestamp.to_rfc3339()));
        map.insert(
            "thread_id".to_string(),
            json!(self.thread_id_or_na(input.thread_id.clone())),
        );
        let value = Value::Object(map);
        info!(target = ?input.target, "{}", value);
    }

    fn emit_text(&self, input: &EmitInput) {
        let (entity_id, authority_id, action, resource_id) =
            self.resource_text_fields(&input.resource);
        let thread_id_str = self.thread_id_or_na(input.thread_id.clone());
        let (_status, text, extra) = match (input.status.as_str(), input.extra.clone()) {
            ("SUCCESS", None) => (
                "SUCCESS",
                format!(
                    "{}: {} operation by {} - SUCCESS",
                    AUDIT_ROLE_ADMIN, input.operation, input.actor,
                ),
                None,
            ),
            ("FAILURE", Some(err)) => (
                "FAILURE",
                format!(
                    "{}: {} operation by {} - FAILURE: {}",
                    AUDIT_ROLE_ADMIN, input.operation, input.actor, err,
                ),
                Some(("audit.error", err)),
            ),
            ("UNAUTHORIZED", Some(reason)) => (
                "UNAUTHORIZED",
                format!(
                    "{}: {} operation by {} - UNAUTHORIZED: {}",
                    AUDIT_ROLE_ADMIN, input.operation, input.actor, reason
                ),
                Some(("audit.reason", reason)),
            ),
            _ => (
                input.status.as_str(),
                format!(
                    "{}: {} operation by {} - {}",
                    AUDIT_ROLE_ADMIN, input.operation, input.actor, input.status
                ),
                None,
            ),
        };

        let mut log_parts = vec![
            format!("audit.role={}", AUDIT_ROLE_ADMIN),
            format!("audit.actor={}", input.actor),
            format!("audit.operation={}", input.operation.to_string()),
            format!("audit.status={}", input.status),
            format!("audit.resource.entity_id={}", entity_id),
            format!("audit.resource.authority_id={}", authority_id),
            format!("audit.resource.action={}", action),
            format!("audit.resource.resource={}", resource_id),
            format!("audit.timestamp={}", input.timestamp.to_rfc3339()),
            format!("audit.thread_id={}", thread_id_str),
        ];

        if let Some((key, val)) = extra {
            log_parts.push(format!("{key}={val}"));
        }

        let structured_log = log_parts.join(" ");

        info!("{} | {}", text, structured_log);
    }
}

#[async_trait::async_trait]
impl AuditLogger for BaseAuditLogger {
    async fn log(&self, audit_log: AuditLog) {
        let emit_input = EmitInput {
            target: audit_log.target,
            operation: audit_log.operation,
            actor: audit_log.actor,
            status: audit_log.status.to_string(),
            resource: audit_log.resource,
            extra: audit_log.extra,
            thread_id: audit_log.thread_id,
            timestamp: audit_log.timestamp,
        };

        match self.config.log_format {
            crate::configs::AuditLogFormat::Json => self.emit_json(&emit_input),
            crate::configs::AuditLogFormat::Text => self.emit_text(&emit_input),
        }
    }
}

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
        let logger = BaseAuditLogger::new(config);

        let resource = AuditResource::new(
            Some(EntityId::new("entity-1")),
            Some(AuthorityId::new("authority-1")),
            Some(Action::new("action-1")),
            Some(Resource::new("resource-1")),
        );

        logger
            .log(
                AuditLogBuilder::new()
                    .operation(AuditOperation::Create)
                    .actor("did:example:admin")
                    .resource(resource)
                    .thread_id(Some("thread-1".to_string()))
                    .build_success(),
            )
            .await;
    }

    #[tokio::test]
    async fn test_log_success_json() {
        let config = AuditConfig {
            log_format: AuditLogFormat::Json,
        };
        let logger = BaseAuditLogger::new(config);

        let resource = AuditResource::new(
            Some(EntityId::new("entity-1")),
            Some(AuthorityId::new("authority-1")),
            Some(Action::new("action-1")),
            Some(Resource::new("resource-1")),
        );

        logger
            .log(
                AuditLogBuilder::new()
                    .operation(AuditOperation::Create)
                    .actor("did:example:admin")
                    .resource(resource)
                    .thread_id(Some("thread-1".to_string()))
                    .build_success(),
            )
            .await;
    }

    #[tokio::test]
    async fn test_log_failure_text() {
        let config = AuditConfig {
            log_format: AuditLogFormat::Text,
        };
        let logger = BaseAuditLogger::new(config);

        let resource = AuditResource::empty();

        logger
            .log(
                AuditLogBuilder::new()
                    .operation(AuditOperation::Delete)
                    .actor("did:example:admin")
                    .resource(resource)
                    .build_failure("Record not found"),
            )
            .await;
    }

    #[tokio::test]
    async fn test_log_failure_json() {
        let config = AuditConfig {
            log_format: AuditLogFormat::Json,
        };
        let logger = BaseAuditLogger::new(config);

        let resource = AuditResource::empty();

        logger
            .log(
                AuditLogBuilder::new()
                    .operation(AuditOperation::Delete)
                    .actor("did:example:admin")
                    .resource(resource)
                    .build_failure("Record not found"),
            )
            .await;
    }

    #[tokio::test]
    async fn test_log_unauthorized_text() {
        let config = AuditConfig {
            log_format: AuditLogFormat::Text,
        };
        let logger = BaseAuditLogger::new(config);

        let resource = AuditResource::empty();

        logger
            .log(
                AuditLogBuilder::new()
                    .operation(AuditOperation::Update)
                    .actor("did:example:unauthorized")
                    .resource(resource)
                    .build_unauthorized("Not in admin list"),
            )
            .await;
    }

    #[tokio::test]
    async fn test_log_unauthorized_json() {
        let config = AuditConfig {
            log_format: AuditLogFormat::Json,
        };
        let logger = BaseAuditLogger::new(config);

        let resource = AuditResource::empty();

        logger
            .log(
                AuditLogBuilder::new()
                    .operation(AuditOperation::Update)
                    .actor("did:example:unauthorized")
                    .resource(resource)
                    .build_unauthorized("Not in admin list"),
            )
            .await;
    }
}
