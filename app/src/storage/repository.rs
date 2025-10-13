
use std::{fmt, future::Future};

use crate::domain::*;


// TODO: for TRQP all of these should be queried together but for ADMIN or audit we may need partial query
#[derive(Debug, Clone, Default)]
pub struct TrustRecordQuery {
    pub entity_id: Option<EntityId>,
    pub authority_id: Option<AuthorityId>,
    pub assertion_id: Option<AssertionId>,
}

impl TrustRecordQuery {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn entity_id(mut self, id: EntityId) -> Self {
        self.entity_id = Some(id);
        self
    }

    pub fn authority_id(mut self, id: AuthorityId) -> Self {
        self.authority_id = Some(id);
        self
    }

    pub fn assertion_id(mut self, id: AssertionId) -> Self {
        self.assertion_id = Some(id);
        self
    }
}


#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RepositoryError {
    NotFound,
    DuplicateKey,
    ConnectionFailed(String),
    QueryFailed(String),
    SerializationFailed(String),
}

impl fmt::Display for RepositoryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotFound => write!(f, "Record not found"),
            Self::DuplicateKey => write!(f, "Duplicate key violation"),
            Self::ConnectionFailed(msg) => write!(f, "Connection failed: {}", msg),
            Self::QueryFailed(msg) => write!(f, "Query failed: {}", msg),
            Self::SerializationFailed(msg) => write!(f, "Serialization failed: {}", msg),
        }
    }
}

impl std::error::Error for RepositoryError {}


pub trait TrustRecordRepository: Send + Sync {
    
    fn save(&self, record: TrustRecord) -> impl Future<Output = Result<(), RepositoryError>> + Send;

    
    fn find_by_ids(
        &self,
        entity_id: &EntityId,
        authority_id: &AuthorityId,
        assertion_id: &AssertionId,
    ) -> impl Future<Output = Result<Option<TrustRecord>, RepositoryError>> + Send;

    
    fn find_by_query(
        &self,
        query: TrustRecordQuery,
    ) -> impl Future<Output = Result<Vec<TrustRecord>, RepositoryError>> + Send;

    
    fn find_by_entity(
        &self,
        entity_id: &EntityId,
    ) -> impl Future<Output = Result<Vec<TrustRecord>, RepositoryError>> + Send;

    
    fn find_by_authority(
        &self,
        authority_id: &AuthorityId,
    ) -> impl Future<Output = Result<Vec<TrustRecord>, RepositoryError>> + Send;

    
    fn delete(
        &self,
        entity_id: &EntityId,
        authority_id: &AuthorityId,
        assertion_id: &AssertionId,
    ) -> impl Future<Output = Result<bool, RepositoryError>> + Send;

    fn count(&self) -> impl Future<Output = Result<usize, RepositoryError>> + Send;
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
            .time_requested(Timestamp::from_millis(1000))
            .time_evaluated(Timestamp::from_millis(1500))
            .message("Verification successful")
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
        let query = TrustRecordQuery::new()
            .entity_id(EntityId::new("entity-123"));

        assert_eq!(query.entity_id.as_ref().unwrap().as_str(), "entity-123");
    }
}