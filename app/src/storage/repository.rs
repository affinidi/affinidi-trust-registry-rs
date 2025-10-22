use std::{fmt, future::Future};

use serde::{Deserialize, Serialize};

use crate::domain::*;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustRecordQuery {
    pub entity_id: EntityId,
    pub authority_id: AuthorityId,
    pub assertion_id: AssertionId,
}

impl TrustRecordQuery {
    pub fn new(entity_id: EntityId, authority_id: AuthorityId, assertion_id: AssertionId) -> Self {
        Self {
            entity_id,
            authority_id,
            assertion_id,
        }
    }

    pub fn from_ids(ids: TrustRecordIds) -> Self {
        let (entity_id, authority_id, assertion_id) = ids.into_parts();
        Self {
            entity_id,
            authority_id,
            assertion_id,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RepositoryError {
    NotFound,
    ConnectionFailed(String),
    QueryFailed(String),
    SerializationFailed(String),
}

impl fmt::Display for RepositoryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotFound => write!(f, "Record not found"),
            Self::ConnectionFailed(msg) => write!(f, "Connection failed: {}", msg),
            Self::QueryFailed(msg) => write!(f, "Query failed: {}", msg),
            Self::SerializationFailed(msg) => write!(f, "Serialization failed: {}", msg),
        }
    }
}

impl std::error::Error for RepositoryError {}

pub trait TrustRecordRepository: Send + Sync {
    fn find_by_query(
        &self,
        query: TrustRecordQuery,
    ) -> impl Future<Output = Result<Option<TrustRecord>, RepositoryError>> + Send;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_trust_record_creation() {
        let record = TrustRecordBuilder::new()
            .entity_id(EntityId::new("entity-123"))
            .authority_id(AuthorityId::new("authority-456"))
            .assertion_id(AssertionId::new("assertion-789"))
            .recognized(true)
            .assertion_verified(true)
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
            AssertionId::new("assertion-789"),
        );

        assert_eq!(query.entity_id.as_str(), "entity-123");
    }
}
