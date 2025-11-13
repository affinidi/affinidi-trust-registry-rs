use std::fmt;

use serde::{Deserialize, Serialize};

use crate::domain::*;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustRecordQuery {
    pub entity_id: EntityId,
    pub authority_id: AuthorityId,
    pub action: Action,
    pub resource: Resource,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustRecordList {
    records: Vec<TrustRecord>,
}

impl TrustRecordList {
    pub fn new(records: Vec<TrustRecord>) -> Self {
        Self { records }
    }

    pub fn records(&self) -> &[TrustRecord] {
        &self.records
    }

    pub fn into_records(self) -> Vec<TrustRecord> {
        self.records
    }
}

impl TrustRecordQuery {
    pub fn new(
        entity_id: EntityId,
        authority_id: AuthorityId,
        action: Action,
        resource: Resource,
    ) -> Self {
        Self {
            entity_id,
            authority_id,
            action,
            resource,
        }
    }

    pub fn from_ids(ids: TrustRecordIds) -> Self {
        let (entity_id, authority_id, action, resource) = ids.into_parts();
        Self {
            entity_id,
            authority_id,
            action,
            resource,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RepositoryError {
    ConnectionFailed(String),
    QueryFailed(String),
    SerializationFailed(String),
    RecordNotFound(String),
    RecordAlreadyExists(String),
    ValidationError(String),
}

impl fmt::Display for RepositoryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ConnectionFailed(msg) => write!(f, "Connection failed: {}", msg),
            Self::QueryFailed(msg) => write!(f, "Query failed: {}", msg),
            Self::SerializationFailed(msg) => write!(f, "Serialization failed: {}", msg),
            Self::RecordNotFound(msg) => write!(f, "Record not found: {}", msg),
            Self::RecordAlreadyExists(msg) => write!(f, "Record already exists: {}", msg),
            Self::ValidationError(msg) => write!(f, "Validation error: {}", msg),
        }
    }
}

impl std::error::Error for RepositoryError {}

/// Read-only repository trait for querying trust records
#[async_trait::async_trait]
pub trait TrustRecordRepository: Send + Sync {
    async fn find_by_query(
        &self,
        query: TrustRecordQuery,
    ) -> Result<Option<TrustRecord>, RepositoryError>;
}

/// Write operations for trust record administration
#[async_trait::async_trait]
pub trait TrustRecordAdminRepository: TrustRecordRepository {
    async fn create(&self, record: TrustRecord) -> Result<(), RepositoryError>;
    async fn update(&self, record: TrustRecord) -> Result<(), RepositoryError>;
    async fn delete(&self, query: TrustRecordQuery) -> Result<(), RepositoryError>;
    async fn list(&self) -> Result<TrustRecordList, RepositoryError>;
    async fn read(&self, query: TrustRecordQuery) -> Result<TrustRecord, RepositoryError>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_trust_record_creation() {
        let record = TrustRecordBuilder::new()
            .entity_id(EntityId::new("entity-123"))
            .authority_id(AuthorityId::new("authority-456"))
            .action(Action::new("action-789"))
            .resource(Resource::new("resource-112"))
            .recognized(true)
            .authorized(true)
            .build()
            .unwrap();

        assert_eq!(record.entity_id().as_str(), "entity-123");
    }

    #[test]
    fn test_builder_missing_fields() {
        let result = TrustRecordBuilder::new()
            .entity_id(EntityId::new("entity-123"))
            .build();

        assert!(result.is_err());
    }

    #[test]
    fn test_query_builder() {
        let query = TrustRecordQuery::new(
            EntityId::new("entity-123"),
            AuthorityId::new("authority-456"),
            Action::new("action-789"),
            Resource::new("resource-012"),
        );

        assert_eq!(query.entity_id.as_str(), "entity-123");
    }
}
