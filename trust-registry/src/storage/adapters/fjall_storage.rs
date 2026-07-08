//! Embedded [fjall](https://crates.io/crates/fjall) LSM key-value storage
//! adapter for the Trust Registry (feature `storage-fjall`).
//!
//! A single-node, on-disk backend with no external service — the same embedded
//! store the Affinidi mediator and VTA use. Records are keyed by the shared
//! [`TrustRecordKey`] (`TR#{authority}#{action}#{resource}#{entity}`) and stored
//! as JSON values. fjall is synchronous, so each operation runs on a blocking
//! thread via [`tokio::task::spawn_blocking`].

use fjall::{Config, Database, Keyspace, KeyspaceCreateOptions};
use tracing::{error, info};

use crate::domain::key::{TR_SK_PREFIX, TrustRecordKey};
use crate::domain::*;
use crate::storage::repository::*;

/// Keyspace (table) holding the trust records.
const KEYSPACE_NAME: &str = "trust_records";

/// fjall-backed trust record store.
pub struct FjallStorage {
    keyspace: Keyspace,
    // Keep the database handle alive for the lifetime of the store (background
    // compaction/flush threads).
    _db: Database,
}

impl FjallStorage {
    /// Open (or create) the fjall database at `path`.
    pub fn new(path: &str) -> Result<Self, Box<dyn std::error::Error>> {
        info!("Opening fjall storage at {path}");
        let db = Database::open(Config::new(std::path::Path::new(path)))?;
        let keyspace = db.keyspace(KEYSPACE_NAME, KeyspaceCreateOptions::default)?;
        Ok(Self { keyspace, _db: db })
    }

    fn serialize(record: &TrustRecord) -> Result<Vec<u8>, RepositoryError> {
        serde_json::to_vec(record).map_err(|e| {
            RepositoryError::SerializationFailed(format!("Failed to serialize record: {e}"))
        })
    }

    fn deserialize(data: &[u8]) -> Result<TrustRecord, RepositoryError> {
        serde_json::from_slice(data).map_err(|e| {
            RepositoryError::SerializationFailed(format!("Failed to deserialize record: {e}"))
        })
    }
}

fn query_error(e: impl std::fmt::Display) -> RepositoryError {
    RepositoryError::QueryFailed(e.to_string())
}

fn join_error(e: impl std::fmt::Display) -> RepositoryError {
    RepositoryError::QueryFailed(format!("fjall blocking task failed: {e}"))
}

#[async_trait::async_trait]
impl TrustRecordRepository for FjallStorage {
    async fn find_by_query(
        &self,
        query: TrustRecordQuery,
    ) -> Result<Option<TrustRecord>, RepositoryError> {
        let key = TrustRecordKey::from_query(&query).to_string();
        let ks = self.keyspace.clone();
        tokio::task::spawn_blocking(move || match ks.get(key.as_bytes()).map_err(query_error)? {
            Some(value) => Ok(Some(FjallStorage::deserialize(&value)?)),
            None => Ok(None),
        })
        .await
        .map_err(join_error)?
    }
}

#[async_trait::async_trait]
impl TrustRecordAdminRepository for FjallStorage {
    async fn create(&self, record: TrustRecord) -> Result<(), RepositoryError> {
        let key = TrustRecordKey::from_record(&record).to_string();
        let value = Self::serialize(&record)?;
        let ks = self.keyspace.clone();
        tokio::task::spawn_blocking(move || {
            if ks.contains_key(key.as_bytes()).map_err(query_error)? {
                return Err(RepositoryError::RecordAlreadyExists(key));
            }
            ks.insert(key.as_bytes(), value).map_err(query_error)?;
            Ok(())
        })
        .await
        .map_err(join_error)?
    }

    async fn update(&self, record: TrustRecord) -> Result<(), RepositoryError> {
        let key = TrustRecordKey::from_record(&record).to_string();
        let value = Self::serialize(&record)?;
        let ks = self.keyspace.clone();
        tokio::task::spawn_blocking(move || {
            if !ks.contains_key(key.as_bytes()).map_err(query_error)? {
                return Err(RepositoryError::RecordNotFound(key));
            }
            ks.insert(key.as_bytes(), value).map_err(query_error)?;
            Ok(())
        })
        .await
        .map_err(join_error)?
    }

    async fn delete(&self, query: TrustRecordQuery) -> Result<(), RepositoryError> {
        let key = TrustRecordKey::from_query(&query).to_string();
        let ks = self.keyspace.clone();
        tokio::task::spawn_blocking(move || {
            if !ks.contains_key(key.as_bytes()).map_err(query_error)? {
                return Err(RepositoryError::RecordNotFound(key));
            }
            ks.remove(key.as_bytes()).map_err(query_error)?;
            Ok(())
        })
        .await
        .map_err(join_error)?
    }

    async fn read(&self, query: TrustRecordQuery) -> Result<TrustRecord, RepositoryError> {
        let key = TrustRecordKey::from_query(&query).to_string();
        let ks = self.keyspace.clone();
        tokio::task::spawn_blocking(move || match ks.get(key.as_bytes()).map_err(query_error)? {
            Some(value) => FjallStorage::deserialize(&value),
            None => Err(RepositoryError::RecordNotFound(key)),
        })
        .await
        .map_err(join_error)?
    }

    async fn list(&self) -> Result<TrustRecordList, RepositoryError> {
        let ks = self.keyspace.clone();
        let records = tokio::task::spawn_blocking(move || {
            let mut records = Vec::new();
            for guard in ks.prefix(TR_SK_PREFIX.as_bytes()) {
                let (key, value) = guard.into_inner().map_err(query_error)?;
                match FjallStorage::deserialize(&value) {
                    Ok(record) => records.push(record),
                    Err(e) => error!(
                        "Skipping unreadable fjall record {}: {e}",
                        String::from_utf8_lossy(&key)
                    ),
                }
            }
            Ok::<_, RepositoryError>(records)
        })
        .await
        .map_err(join_error)??;
        Ok(TrustRecordList::new(records))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record() -> TrustRecord {
        TrustRecordBuilder::new()
            .entity_id(EntityId::new("did:example:entity"))
            .authority_id(AuthorityId::new("did:example:authority"))
            .action(Action::new("issue"))
            .resource(Resource::new("vc"))
            .recognized(true)
            .authorized(true)
            .record_type(RecordType::Authorization)
            .build()
            .expect("valid record")
    }

    fn query() -> TrustRecordQuery {
        TrustRecordQuery::new(
            EntityId::new("did:example:entity"),
            AuthorityId::new("did:example:authority"),
            Action::new("issue"),
            Resource::new("vc"),
        )
    }

    #[tokio::test]
    async fn create_read_update_delete_list_round_trip() {
        let dir = tempfile::tempdir().expect("tempdir");
        let fjall = FjallStorage::new(dir.path().to_str().expect("path")).expect("open");

        // create + read
        fjall.create(record()).await.expect("create");
        let read = fjall.read(query()).await.expect("read");
        assert!(read.is_authorized());

        // duplicate create fails
        assert!(matches!(
            fjall.create(record()).await,
            Err(RepositoryError::RecordAlreadyExists(_))
        ));

        // find_by_query
        assert!(fjall.find_by_query(query()).await.expect("find").is_some());

        // list
        assert_eq!(fjall.list().await.expect("list").records().len(), 1);

        // delete + confirm gone
        fjall.delete(query()).await.expect("delete");
        assert!(fjall.find_by_query(query()).await.expect("find").is_none());
        assert!(matches!(
            fjall.read(query()).await,
            Err(RepositoryError::RecordNotFound(_))
        ));

        // update missing fails
        assert!(matches!(
            fjall.update(record()).await,
            Err(RepositoryError::RecordNotFound(_))
        ));
    }
}
