//! Renders [`AuditLog`] entries as one log line each.
//!
//! Most of what an entry carries comes from the document being audited — its
//! id, thread, claimed issuer, record key and the refusal reason that echoes
//! them — and a refused document can come from anyone. So every value is
//! capped at [`MAX_FIELD_CHARS`] and rendered escaped: in the text format each
//! value is quoted with its control characters escaped, and the JSON format
//! (the default) escapes them by construction. An entry is therefore always
//! exactly one line, and no value can end it early or forge another.

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

/// The longest value an audit entry records for any one field, in characters.
/// Longer values are cut and marked with `…`.
pub const MAX_FIELD_CHARS: usize = 256;

pub struct EmitInput {
    pub target: String,
    pub operation: AuditOperation,
    pub actor: String,
    pub status: String,
    pub resource: AuditResource,
    pub extra: Option<String>,
    pub thread_id: Option<String>,
    pub task: Option<String>,
    pub document_id: Option<String>,
    pub claimed_actor: Option<String>,
    pub timestamp: chrono::DateTime<Utc>,
}

/// Cap `value` at [`MAX_FIELD_CHARS`].
fn capped(value: &str) -> String {
    if value.chars().count() <= MAX_FIELD_CHARS {
        return value.to_string();
    }
    let mut cut: String = value.chars().take(MAX_FIELD_CHARS).collect();
    cut.push('…');
    cut
}

/// Cap `value` and quote it with every control character escaped, so it
/// cannot break the line it is written on.
fn quoted(value: &str) -> String {
    format!("{:?}", capped(value))
}

impl EmitInput {
    /// The entry's `(key, value)` pairs in a fixed order, `None` meaning the
    /// value is absent. The reason's `audit.error=` / `audit.reason=` label is
    /// the key, not part of the value.
    fn fields(&self) -> Vec<(&'static str, Option<String>)> {
        let resource = |value: Option<String>| value.or_else(|| Some(NA.to_string()));
        let (reason_key, reason) = match self.extra.as_deref().map(|e| e.split_once('=')) {
            Some(Some(("audit.error", value))) => ("error", Some(value.to_string())),
            Some(Some((_, value))) => ("reason", Some(value.to_string())),
            Some(None) => ("reason", self.extra.clone()),
            None => ("reason", None),
        };
        vec![
            ("role", Some(AUDIT_ROLE_ADMIN.to_string())),
            ("actor", Some(self.actor.clone())),
            ("claimed_actor", self.claimed_actor.clone()),
            ("operation", Some(self.operation.to_string())),
            ("task", self.task.clone()),
            ("status", Some(self.status.clone())),
            (
                "resource.entity_id",
                resource(self.resource.entity_id.as_ref().map(|v| v.to_string())),
            ),
            (
                "resource.authority_id",
                resource(self.resource.authority_id.as_ref().map(|v| v.to_string())),
            ),
            (
                "resource.action",
                resource(self.resource.action.as_ref().map(|v| v.to_string())),
            ),
            (
                "resource.resource",
                resource(self.resource.resource.as_ref().map(|v| v.to_string())),
            ),
            ("document_id", self.document_id.clone()),
            (
                "thread_id",
                Some(self.thread_id.clone().unwrap_or_else(|| NA.to_string())),
            ),
            ("timestamp", Some(self.timestamp.to_rfc3339())),
            (reason_key, reason),
        ]
    }
}

/// One JSON object on one line.
pub fn render_json(input: &EmitInput) -> String {
    let mut map = serde_json::Map::new();
    for (key, value) in input.fields() {
        let Some(value) = value else { continue };
        let value = json!(capped(&value));
        match key.split_once('.') {
            Some((outer, inner)) => {
                let nested = map
                    .entry(outer.to_string())
                    .or_insert_with(|| Value::Object(serde_json::Map::new()));
                if let Value::Object(nested) = nested {
                    nested.insert(inner.to_string(), value);
                }
            }
            None => {
                map.insert(key.to_string(), value);
            }
        }
    }
    Value::Object(map).to_string()
}

/// `audit.<key>="<value>"` pairs on one line, every value quoted and escaped.
pub fn render_text(input: &EmitInput) -> String {
    input
        .fields()
        .into_iter()
        .filter_map(|(key, value)| value.map(|value| format!("audit.{key}={}", quoted(&value))))
        .collect::<Vec<_>>()
        .join(" ")
}

#[derive(Clone)]
pub struct BaseAuditLogger {
    config: AuditConfig,
}

impl BaseAuditLogger {
    pub fn new(config: AuditConfig) -> Self {
        Self { config }
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
            task: audit_log.task,
            document_id: audit_log.document_id,
            claimed_actor: audit_log.claimed_actor,
            timestamp: audit_log.timestamp,
        };

        match self.config.log_format {
            crate::configs::AuditLogFormat::Json => {
                info!(target: "audit", "{}", render_json(&emit_input))
            }
            crate::configs::AuditLogFormat::Text => {
                info!(target: "audit", "{}", render_text(&emit_input))
            }
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

    fn hostile_input() -> EmitInput {
        EmitInput {
            target: AUDIT_ROLE_ADMIN.to_string(),
            operation: AuditOperation::Put,
            actor: String::new(),
            status: "UNAUTHORIZED".to_string(),
            resource: AuditResource::new(
                Some(EntityId::new(
                    "did:x\nADMIN: PUT operation by did:admin - SUCCESS",
                )),
                None,
                None,
                None,
            ),
            extra: Some("audit.reason=bad\r\naudit.status=SUCCESS".to_string()),
            thread_id: Some("t\u{1b}[2J".to_string()),
            task: Some("registry/record/put".to_string()),
            document_id: Some("x".repeat(10_000)),
            claimed_actor: Some("did:example:anyone\n".to_string()),
            timestamp: Utc::now(),
        }
    }

    #[test]
    fn a_hostile_text_entry_stays_on_one_line() {
        let line = render_text(&hostile_input());
        assert!(!line.contains('\n') && !line.contains('\r') && !line.contains('\u{1b}'));
        assert!(line.contains(r#"audit.resource.entity_id="did:x\nADMIN"#));
        assert_eq!(line.matches("audit.reason=").count(), 1);
        assert!(line.contains(r#"audit.reason="bad\r\naudit.status=SUCCESS""#));
    }

    #[test]
    fn a_hostile_json_entry_stays_on_one_line() {
        let line = render_json(&hostile_input());
        assert!(!line.contains('\n') && !line.contains('\r') && !line.contains('\u{1b}'));
        let parsed: Value = serde_json::from_str(&line).expect("one JSON object");
        assert_eq!(parsed["status"], "UNAUTHORIZED");
        assert_eq!(parsed["reason"], "bad\r\naudit.status=SUCCESS");
    }

    #[test]
    fn long_values_are_capped() {
        let parsed: Value = serde_json::from_str(&render_json(&hostile_input())).expect("json");
        let id = parsed["document_id"].as_str().expect("document id");
        assert_eq!(id.chars().count(), MAX_FIELD_CHARS + 1);
        assert!(id.ends_with('…'));
    }

    #[test]
    fn an_error_is_labelled_once() {
        let mut input = hostile_input();
        input.extra = Some("audit.error=Record not found".to_string());
        let line = render_text(&input);
        assert!(line.contains(r#"audit.error="Record not found""#));
        assert!(!line.contains("audit.error=\"audit.error"));
    }
}
