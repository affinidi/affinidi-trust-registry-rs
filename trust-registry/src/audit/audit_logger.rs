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
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use tracing::info;

pub use crate::audit::model::{AuditLogBuilder, AuditStatus};

pub const AUDIT_ROLE_ADMIN: &str = "ADMIN";
pub const NA: &str = "N/A";

/// The `tracing` target every audit entry is written under.
///
/// The standalone service gives this target its own output layer, enabled at
/// `INFO` whatever `RUST_LOG` says, so lowering the diagnostic log level does
/// not drop audit entries. A host embedding the registry must keep this target
/// enabled at `INFO` in its own subscriber, or route entries elsewhere with
/// `TrustRegistryBuilder::audit_logger`.
pub const AUDIT_TARGET: &str = "audit";

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
    pub authenticated_sender: Option<String>,
    /// The entry's position in this process's audit sequence, starting at 1. A
    /// gap shows that an entry was lost.
    pub sequence: Option<u64>,
    pub timestamp: chrono::DateTime<Utc>,
}

/// Characters that can end a line or change how the rest of it reads: the
/// control characters, the line and paragraph separators (U+2028, U+2029),
/// and the Unicode format characters (category Cf), which include the bidi
/// overrides and zero-width characters.
fn is_disruptive(c: char) -> bool {
    c.is_control()
        || matches!(
            c,
            '\u{00AD}'
                | '\u{0600}'..='\u{0605}'
                | '\u{061C}'
                | '\u{06DD}'
                | '\u{070F}'
                | '\u{0890}'..='\u{0891}'
                | '\u{08E2}'
                | '\u{180E}'
                | '\u{200B}'..='\u{200F}'
                | '\u{2028}'..='\u{202E}'
                | '\u{2060}'..='\u{2064}'
                | '\u{2066}'..='\u{206F}'
                | '\u{FEFF}'
                | '\u{FFF9}'..='\u{FFFB}'
                | '\u{110BD}'
                | '\u{110CD}'
                | '\u{13430}'..='\u{1343F}'
                | '\u{1BCA0}'..='\u{1BCA3}'
                | '\u{1D173}'..='\u{1D17A}'
                | '\u{E0001}'
                | '\u{E0020}'..='\u{E007F}'
        )
}

/// Cap `value` at [`MAX_FIELD_CHARS`] and replace every disruptive character
/// with its `\u{…}` escape, for both formats alike.
fn capped(value: &str) -> String {
    let mut out = String::new();
    for (index, c) in value.chars().enumerate() {
        if index == MAX_FIELD_CHARS {
            out.push('…');
            break;
        }
        if is_disruptive(c) {
            out.push_str(&c.escape_unicode().to_string());
        } else {
            out.push(c);
        }
    }
    out
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
            ("seq", self.sequence.map(|sequence| sequence.to_string())),
            ("role", Some(AUDIT_ROLE_ADMIN.to_string())),
            ("actor", Some(self.actor.clone())),
            ("claimed_actor", self.claimed_actor.clone()),
            ("authenticated_sender", self.authenticated_sender.clone()),
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

/// Writes each entry as one line to the `tracing` target [`AUDIT_TARGET`] at
/// `INFO`, numbered in sequence.
#[derive(Clone)]
pub struct BaseAuditLogger {
    config: AuditConfig,
    sequence: Arc<AtomicU64>,
}

impl BaseAuditLogger {
    pub fn new(config: AuditConfig) -> Self {
        Self {
            config,
            sequence: Arc::new(AtomicU64::new(0)),
        }
    }

    /// Whether the current `tracing` subscriber records entries written to
    /// [`AUDIT_TARGET`]. When it does not, this logger's entries are lost.
    pub fn sink_enabled() -> bool {
        tracing::enabled!(target: AUDIT_TARGET, tracing::Level::INFO)
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
            authenticated_sender: audit_log.authenticated_sender,
            sequence: Some(self.sequence.fetch_add(1, Ordering::Relaxed) + 1),
            timestamp: audit_log.timestamp,
        };

        match self.config.log_format {
            crate::configs::AuditLogFormat::Json => {
                info!(target: AUDIT_TARGET, "{}", render_json(&emit_input))
            }
            crate::configs::AuditLogFormat::Text => {
                info!(target: AUDIT_TARGET, "{}", render_text(&emit_input))
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
            authenticated_sender: None,
            sequence: Some(7),
            timestamp: Utc::now(),
        }
    }

    #[test]
    fn a_hostile_text_entry_stays_on_one_line() {
        let line = render_text(&hostile_input());
        assert!(!line.contains('\n') && !line.contains('\r') && !line.contains('\u{1b}'));
        assert!(line.contains(r#"audit.resource.entity_id="did:x\\u{a}ADMIN"#));
        assert_eq!(line.matches("audit.reason=").count(), 1);
        assert!(line.contains(r#"audit.reason="bad\\u{d}\\u{a}audit.status=SUCCESS""#));
    }

    #[test]
    fn a_hostile_json_entry_stays_on_one_line() {
        let line = render_json(&hostile_input());
        assert!(!line.contains('\n') && !line.contains('\r') && !line.contains('\u{1b}'));
        let parsed: Value = serde_json::from_str(&line).expect("one JSON object");
        assert_eq!(parsed["status"], "UNAUTHORIZED");
        assert_eq!(parsed["reason"], r"bad\u{d}\u{a}audit.status=SUCCESS");
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

    #[test]
    fn separators_and_format_characters_are_escaped_in_both_formats() {
        let mut input = hostile_input();
        input.claimed_actor = Some("did:a\u{2028}b\u{2029}c\u{202E}d\u{200B}e".to_string());
        for line in [render_json(&input), render_text(&input)] {
            for c in ['\u{2028}', '\u{2029}', '\u{202E}', '\u{200B}'] {
                assert!(!line.contains(c), "{c:?} survived in {line}");
            }
            assert!(line.contains("u{2028}") && line.contains("u{202e}"));
        }
    }

    #[test]
    fn entries_carry_their_sequence_number_and_authenticated_sender() {
        let mut input = hostile_input();
        input.authenticated_sender = Some("did:example:peer".to_string());
        let parsed: Value = serde_json::from_str(&render_json(&input)).expect("json");
        assert_eq!(parsed["seq"], "7");
        assert_eq!(parsed["authenticated_sender"], "did:example:peer");
        let line = render_text(&input);
        assert!(line.starts_with(r#"audit.seq="7""#), "{line}");
        assert!(line.contains(r#"audit.authenticated_sender="did:example:peer""#));
    }

    /// Captures what is written to the audit target.
    #[derive(Clone, Default)]
    struct Captured(Arc<std::sync::Mutex<Vec<u8>>>);

    impl std::io::Write for Captured {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    #[tokio::test]
    async fn sequence_numbers_increase_across_clones() {
        use tracing_subscriber::{Layer, layer::SubscriberExt};

        let captured = Captured::default();
        let writer = captured.clone();
        let subscriber = tracing_subscriber::registry().with(
            tracing_subscriber::fmt::layer()
                .with_writer(move || writer.clone())
                .with_ansi(false)
                .with_filter(
                    tracing_subscriber::filter::Targets::new()
                        .with_target(AUDIT_TARGET, tracing::Level::INFO),
                ),
        );
        let _guard = tracing::subscriber::set_default(subscriber);
        assert!(BaseAuditLogger::sink_enabled());

        let logger = BaseAuditLogger::new(AuditConfig {
            log_format: AuditLogFormat::Json,
        });
        let clone = logger.clone();
        logger.log(AuditLogBuilder::new().build_success()).await;
        clone.log(AuditLogBuilder::new().build_success()).await;
        logger.log(AuditLogBuilder::new().build_success()).await;

        let output = String::from_utf8(captured.0.lock().unwrap().clone()).unwrap();
        let sequence: Vec<u64> = output
            .lines()
            .map(|line| {
                let json = &line[line.find('{').expect("a JSON entry")..];
                let parsed: Value = serde_json::from_str(json).expect("json");
                parsed["seq"]
                    .as_str()
                    .expect("seq")
                    .parse()
                    .expect("number")
            })
            .collect();
        assert_eq!(sequence, vec![1, 2, 3]);
    }

    #[test]
    fn the_sink_is_reported_disabled_when_the_subscriber_filters_it_out() {
        use tracing_subscriber::{Layer, layer::SubscriberExt};

        let subscriber = tracing_subscriber::registry().with(
            tracing_subscriber::fmt::layer()
                .with_writer(std::io::sink)
                .with_filter(tracing_subscriber::filter::LevelFilter::WARN),
        );
        let _guard = tracing::subscriber::set_default(subscriber);
        assert!(!BaseAuditLogger::sink_enabled());
    }
}
