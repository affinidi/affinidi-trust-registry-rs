use crate::domain::{Action, AuthorityId, EntityId, Resource, TrustRecord};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::fmt;

pub const AUDIT_ROLE_ADMIN: &str = "ADMIN";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditLog {
    pub target: String,
    pub operation: AuditOperation,
    pub actor: String,
    pub status: AuditStatus,
    pub resource: AuditResource,
    pub extra: Option<String>,
    pub thread_id: Option<String>,
    pub timestamp: chrono::DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum AuditStatus {
    Success,
    Failure,
    Unauthorized,
}

impl fmt::Display for AuditStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Success => write!(f, "SUCCESS"),
            Self::Failure => write!(f, "FAILURE"),
            Self::Unauthorized => write!(f, "UNAUTHORIZED"),
        }
    }
}

pub struct AuditLogBuilder {
    audit_log: AuditLog,
}

impl AuditLogBuilder {
    pub fn new() -> Self {
        Self {
            audit_log: AuditLog {
                target: AUDIT_ROLE_ADMIN.to_string(),
                operation: AuditOperation::Read,
                actor: String::new(),
                status: AuditStatus::Success,
                resource: AuditResource::empty(),
                extra: None,
                thread_id: None,
                timestamp: Utc::now(),
            },
        }
    }

    pub fn operation(mut self, operation: AuditOperation) -> Self {
        self.audit_log.operation = operation;
        self
    }

    pub fn actor(mut self, actor: impl Into<String>) -> Self {
        self.audit_log.actor = actor.into();
        self
    }

    pub fn resource(mut self, resource: AuditResource) -> Self {
        self.audit_log.resource = resource;
        self
    }

    pub fn thread_id(mut self, thread_id: Option<String>) -> Self {
        self.audit_log.thread_id = thread_id;
        self
    }

    pub fn build_success(mut self) -> AuditLog {
        self.audit_log.status = AuditStatus::Success;
        self.audit_log.timestamp = Utc::now();
        self.audit_log
    }

    pub fn build_failure(mut self, error_message: impl Into<String>) -> AuditLog {
        self.audit_log.status = AuditStatus::Failure;
        self.audit_log.extra = Some(format!("audit.error={}", error_message.into()));
        self.audit_log.timestamp = Utc::now();
        self.audit_log
    }

    pub fn build_unauthorized(mut self, reason: impl Into<String>) -> AuditLog {
        self.audit_log.status = AuditStatus::Unauthorized;
        self.audit_log.extra = Some(format!("audit.reason={}", reason.into()));
        self.audit_log.timestamp = Utc::now();
        self.audit_log
    }
}

impl Default for AuditLogBuilder {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait::async_trait]
pub trait AuditLogger: Send + Sync {
    async fn log(&self, audit_log: AuditLog);
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum AuditOperation {
    Create,
    Update,
    Delete,
    Read,
    List,
}

impl fmt::Display for AuditOperation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Create => write!(f, "CREATE"),
            Self::Update => write!(f, "UPDATE"),
            Self::Delete => write!(f, "DELETE"),
            Self::Read => write!(f, "READ"),
            Self::List => write!(f, "LIST"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditResource {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub entity_id: Option<EntityId>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authority_id: Option<AuthorityId>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub action: Option<Action>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resource: Option<Resource>,
}

impl AuditResource {
    pub fn new(
        entity_id: Option<EntityId>,
        authority_id: Option<AuthorityId>,
        action: Option<Action>,
        resource: Option<Resource>,
    ) -> Self {
        Self {
            entity_id,
            authority_id,
            action,
            resource,
        }
    }

    pub fn from_record(record: &TrustRecord) -> Self {
        Self {
            entity_id: Some(record.entity_id().clone()),
            authority_id: Some(record.authority_id().clone()),
            action: Some(record.action().clone()),
            resource: Some(record.resource().clone()),
        }
    }

    pub fn empty() -> Self {
        Self {
            entity_id: None,
            authority_id: None,
            action: None,
            resource: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::domain::RecordType;

    use super::*;

    #[test]
    fn test_audit_resource_from_record() {
        use crate::domain::TrustRecordBuilder;

        let record = TrustRecordBuilder::new()
            .entity_id(EntityId::new("entity-1"))
            .authority_id(AuthorityId::new("authority-1"))
            .action(Action::new("action-1"))
            .resource(Resource::new("resource-1"))
            .recognized(true)
            .authorized(true)
            .record_type(RecordType::Authorization)
            .build()
            .unwrap();

        let resource = AuditResource::from_record(&record);

        assert_eq!(resource.entity_id.as_ref().unwrap().as_str(), "entity-1");
        assert_eq!(
            resource.authority_id.as_ref().unwrap().as_str(),
            "authority-1"
        );
        assert_eq!(resource.action.as_ref().unwrap().as_str(), "action-1");
        assert_eq!(resource.resource.as_ref().unwrap().as_str(), "resource-1");
    }
}
