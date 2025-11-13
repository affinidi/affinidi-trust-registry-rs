use crate::domain::{Action, AuthorityId, EntityId, Resource, TrustRecord};
use serde::{Deserialize, Serialize};
use std::fmt;

#[async_trait::async_trait]
pub trait AuditLogger: Send + Sync {
    async fn log_success(
        &self,
        operation: AuditOperation,
        actor_did: &str,
        resource: AuditResource,
        thread_id: Option<String>,
    );

    async fn log_failure(
        &self,
        operation: AuditOperation,
        actor_did: &str,
        resource: AuditResource,
        error_message: &str,
        thread_id: Option<String>,
    );

    async fn log_unauthorized(
        &self,
        operation: AuditOperation,
        actor_did: &str,
        resource: AuditResource,
        reason: &str,
        thread_id: Option<String>,
    );
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
