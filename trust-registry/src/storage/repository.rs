use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::domain::key::TrustRecordKey;
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
    /// Stored values a listing found but could not decode. Never serialised:
    /// it holds other records' storage keys.
    #[serde(skip)]
    unreadable: Vec<UnreadableRecord>,
}

/// A stored value a listing could not decode, known only by its storage key.
///
/// The adapter logs it at `error`. A caller filtering the listing decides
/// with [`Self::could_match`] whether it must fail rather than answer without
/// it. The storage key is for logs only: it may name another authority's
/// record, so it must not reach a client.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnreadableRecord {
    storage_key: String,
}

impl UnreadableRecord {
    pub fn new(storage_key: impl Into<String>) -> Self {
        Self {
            storage_key: storage_key.into(),
        }
    }

    pub fn storage_key(&self) -> &str {
        &self.storage_key
    }

    /// Whether the record stored here could satisfy `matches`: true when any
    /// identifier tuple its key can stand for does, or when the key does not
    /// decode at all, so nothing about it can be ruled out.
    pub fn could_match(&self, matches: impl Fn(&TrustRecordKey) -> bool) -> bool {
        let candidates = TrustRecordKey::candidates_for_storage_key(&self.storage_key);
        candidates.is_empty() || candidates.iter().any(matches)
    }
}

/// Log a stored value a listing could not decode and note it as unreadable.
pub(crate) fn skip_unreadable(
    storage_key: String,
    error: &RepositoryError,
    unreadable: &mut Vec<UnreadableRecord>,
) {
    tracing::error!(
        storage_key = %storage_key,
        %error,
        "stored trust record does not decode; leaving it out of the listing"
    );
    unreadable.push(UnreadableRecord::new(storage_key));
}

impl TrustRecordList {
    pub fn new(records: Vec<TrustRecord>) -> Self {
        Self {
            records,
            unreadable: Vec::new(),
        }
    }

    /// A listing that also reports the stored values it could not decode.
    pub fn with_unreadable(records: Vec<TrustRecord>, unreadable: Vec<UnreadableRecord>) -> Self {
        Self {
            records,
            unreadable,
        }
    }

    /// The stored values this listing skipped because they did not decode.
    pub fn unreadable(&self) -> &[UnreadableRecord] {
        &self.unreadable
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

/// Errors a repository reports.
///
/// Every adapter reports the same condition with the same variant and the same
/// message, so a client's reject reason does not depend on the backend:
///
/// - a strict create of a key that holds a record: [`Self::RecordAlreadyExists`]
///   carrying the record's storage key ([`TrustRecordKey::sk`]), built with
///   [`RepositoryError::already_exists`];
/// - an update, delete or read of a key that holds none: [`Self::RecordNotFound`]
///   carrying the storage key, built with [`RepositoryError::not_found`];
/// - a stored record that cannot be decoded: [`Self::SerializationFailed`]
///   from a lookup of its key. A listing does not fail on it: it leaves the
///   record out, logs it, and reports it in [`TrustRecordList::unreadable`],
///   so a caller filtering the listing can fail when it might have matched;
/// - the backend unreachable (connection refused, timeout):
///   [`Self::ConnectionFailed`]; the backend answered with an error:
///   [`Self::QueryFailed`].
///
/// The conformance suite in `storage::conformance` checks this for every
/// adapter.
///
/// [`TrustRecordKey::sk`]: crate::domain::key::TrustRecordKey::sk
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum RepositoryError {
    #[error("Connection failed: {0}")]
    ConnectionFailed(String),
    #[error("Query failed: {0}")]
    QueryFailed(String),
    #[error("Serialization failed: {0}")]
    SerializationFailed(String),
    #[error("Record not found: {0}")]
    RecordNotFound(String),
    #[error("Record already exists: {0}")]
    RecordAlreadyExists(String),
    #[error("Validation error: {0}")]
    ValidationError(String),
    #[error("Lock poisoned")]
    LockPoisoned,
}

impl RepositoryError {
    /// A strict create found `key` already holding its record.
    pub fn already_exists(key: &TrustRecordKey) -> Self {
        Self::RecordAlreadyExists(key.sk())
    }

    /// No record is stored for `key`.
    pub fn not_found(key: &TrustRecordKey) -> Self {
        Self::RecordNotFound(key.sk())
    }
}

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

    /// The record `query` names, or [`RepositoryError::RecordNotFound`].
    ///
    /// The same lookup as [`TrustRecordRepository::find_by_query`], with
    /// absence as an error. Adapters do not override it, so the two can never
    /// disagree.
    async fn read(&self, query: TrustRecordQuery) -> Result<TrustRecord, RepositoryError> {
        let key = TrustRecordKey::from_query(&query);
        self.find_by_query(query)
            .await?
            .ok_or_else(|| RepositoryError::not_found(&key))
    }
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
            .record_type(RecordType::Authorization)
            .build()
            .unwrap();

        assert_eq!(record.entity_id().as_str(), "entity-123");
        assert_eq!(record.record_type().to_string(), "authorization");
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
