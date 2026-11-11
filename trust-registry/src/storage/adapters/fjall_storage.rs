//! Embedded [fjall](https://crates.io/crates/fjall) LSM key-value storage
//! adapter for the Trust Registry (feature `storage-fjall`).
//!
//! A single-node, on-disk backend with no external service — the same embedded
//! store the Affinidi mediator and VTA use. Records are keyed by the shared
//! [`TrustRecordKey`] (`TR#{authority}#{action}#{resource}#{entity}`, each
//! identifier escaped) and stored
//! as JSON values. fjall is synchronous, so each operation runs on a blocking
//! thread via [`tokio::task::spawn_blocking`].

use fjall::{Config, Database, Keyspace, KeyspaceCreateOptions};
use tracing::{error, info};

use crate::domain::key::{TR_SK_PREFIX, TrustRecordKey, dedupe_listing, verified_record};
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

/// Read the record `key` names, from its current storage key or, for a record
/// an older release wrote, from the earlier unescaped key.
///
/// Returns the storage key it was found under together with the record.
fn lookup(
    ks: &Keyspace,
    key: &TrustRecordKey,
) -> Result<Option<(String, TrustRecord)>, RepositoryError> {
    let current = key.sk();
    let candidates = std::iter::once(current).chain(key.legacy_sk());
    for storage_key in candidates {
        let stored = ks
            .get(storage_key.as_bytes())
            .map_err(query_error)?
            .map(|value| FjallStorage::deserialize(&value))
            .transpose()?;
        if let Some(record) = verified_record(key, &storage_key, stored) {
            return Ok(Some((storage_key, record)));
        }
    }
    Ok(None)
}

#[async_trait::async_trait]
impl TrustRecordRepository for FjallStorage {
    async fn find_by_query(
        &self,
        query: TrustRecordQuery,
    ) -> Result<Option<TrustRecord>, RepositoryError> {
        let key = TrustRecordKey::from_query(&query);
        let ks = self.keyspace.clone();
        tokio::task::spawn_blocking(move || Ok(lookup(&ks, &key)?.map(|(_, record)| record)))
            .await
            .map_err(join_error)?
    }
}

#[async_trait::async_trait]
impl TrustRecordAdminRepository for FjallStorage {
    async fn create(&self, record: TrustRecord) -> Result<(), RepositoryError> {
        let key = TrustRecordKey::from_record(&record);
        let value = Self::serialize(&record)?;
        let ks = self.keyspace.clone();
        tokio::task::spawn_blocking(move || {
            let storage_key = key.sk();
            if ks
                .contains_key(storage_key.as_bytes())
                .map_err(query_error)?
                || lookup(&ks, &key)?.is_some()
            {
                return Err(RepositoryError::RecordAlreadyExists(storage_key));
            }
            ks.insert(storage_key.as_bytes(), value)
                .map_err(query_error)?;
            Ok(())
        })
        .await
        .map_err(join_error)?
    }

    async fn update(&self, record: TrustRecord) -> Result<(), RepositoryError> {
        let key = TrustRecordKey::from_record(&record);
        let value = Self::serialize(&record)?;
        let ks = self.keyspace.clone();
        tokio::task::spawn_blocking(move || {
            let storage_key = key.sk();
            let Some((found_under, _)) = lookup(&ks, &key)? else {
                return Err(RepositoryError::RecordNotFound(storage_key));
            };
            // Write the current key first: if the process stops before the
            // earlier key is removed, both copies exist and the current one
            // wins on read and in listings.
            ks.insert(storage_key.as_bytes(), value)
                .map_err(query_error)?;
            if found_under != storage_key {
                ks.remove(found_under.as_bytes()).map_err(query_error)?;
            }
            Ok(())
        })
        .await
        .map_err(join_error)?
    }

    async fn delete(&self, query: TrustRecordQuery) -> Result<(), RepositoryError> {
        let key = TrustRecordKey::from_query(&query);
        let ks = self.keyspace.clone();
        tokio::task::spawn_blocking(move || {
            let storage_key = key.sk();
            let legacy_copy = match key.legacy_sk() {
                Some(legacy) => {
                    let stored = ks
                        .get(legacy.as_bytes())
                        .map_err(query_error)?
                        .map(|value| FjallStorage::deserialize(&value))
                        .transpose()?;
                    verified_record(&key, &legacy, stored).map(|_| legacy)
                }
                None => None,
            };
            let current_copy = ks
                .contains_key(storage_key.as_bytes())
                .map_err(query_error)?;
            if legacy_copy.is_none() && !current_copy {
                return Err(RepositoryError::RecordNotFound(storage_key));
            }
            // The earlier key goes first: if the process stops in between, the
            // record is still present under its current key and a retried
            // delete removes it. The other order would leave the old copy to
            // be read back.
            if let Some(legacy) = legacy_copy {
                ks.remove(legacy.as_bytes()).map_err(query_error)?;
            }
            ks.remove(storage_key.as_bytes()).map_err(query_error)?;
            Ok(())
        })
        .await
        .map_err(join_error)?
    }

    async fn read(&self, query: TrustRecordQuery) -> Result<TrustRecord, RepositoryError> {
        let key = TrustRecordKey::from_query(&query);
        let ks = self.keyspace.clone();
        tokio::task::spawn_blocking(move || match lookup(&ks, &key)? {
            Some((_, record)) => Ok(record),
            None => Err(RepositoryError::RecordNotFound(key.sk())),
        })
        .await
        .map_err(join_error)?
    }

    async fn list(&self) -> Result<TrustRecordList, RepositoryError> {
        let ks = self.keyspace.clone();
        let entries = tokio::task::spawn_blocking(move || {
            let mut entries = Vec::new();
            for guard in ks.prefix(TR_SK_PREFIX.as_bytes()) {
                let (key, value) = guard.into_inner().map_err(query_error)?;
                let key = String::from_utf8_lossy(&key).into_owned();
                match FjallStorage::deserialize(&value) {
                    Ok(record) => entries.push((key, record)),
                    Err(e) => error!("Skipping unreadable fjall record {key}: {e}"),
                }
            }
            Ok::<_, RepositoryError>(entries)
        })
        .await
        .map_err(join_error)??;
        Ok(TrustRecordList::new(dedupe_listing(entries)))
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

    fn record_with(authority: &str, action: &str, resource: &str, entity: &str) -> TrustRecord {
        TrustRecordBuilder::new()
            .entity_id(EntityId::new(entity))
            .authority_id(AuthorityId::new(authority))
            .action(Action::new(action))
            .resource(Resource::new(resource))
            .recognized(true)
            .authorized(true)
            .record_type(RecordType::Authorization)
            .build()
            .expect("valid record")
    }

    fn query_for(record: &TrustRecord) -> TrustRecordQuery {
        TrustRecordQuery::new(
            record.entity_id().clone(),
            record.authority_id().clone(),
            record.action().clone(),
            record.resource().clone(),
        )
    }

    fn open() -> (tempfile::TempDir, FjallStorage) {
        let dir = tempfile::tempdir().expect("tempdir");
        let fjall = FjallStorage::new(dir.path().to_str().expect("path")).expect("open");
        (dir, fjall)
    }

    /// Store `record` the way an older release did: under the unescaped key.
    fn insert_under_earlier_key(fjall: &FjallStorage, record: &TrustRecord) -> String {
        let legacy = TrustRecordKey::from_record(record)
            .legacy_sk()
            .expect("identifiers contain '#' or '%'");
        fjall
            .keyspace
            .insert(
                legacy.as_bytes(),
                FjallStorage::serialize(record).expect("serialize"),
            )
            .expect("insert");
        legacy
    }

    #[tokio::test]
    async fn records_with_separator_in_any_identifier_stay_distinct() {
        let (_dir, fjall) = open();
        let pairs = [
            (
                record_with("did:a", "sign", "repo#main", "did:e"),
                record_with("did:a", "sign#repo", "main", "did:e"),
            ),
            (
                record_with("did:a#x", "sign", "r", "did:e"),
                record_with("did:a", "x#sign", "r", "did:e"),
            ),
            (
                record_with("did:a", "issue", "https://schema.example/vc", "did:x#k1"),
                record_with("did:a", "issue", "https://schema.example/vc#did:x", "k1"),
            ),
        ];
        for (first, second) in pairs {
            let second = second.with_authorized(false);
            fjall.create(first.clone()).await.expect("create first");
            fjall.create(second.clone()).await.expect("create second");
            assert_eq!(fjall.read(query_for(&first)).await.expect("read"), first);
            assert_eq!(fjall.read(query_for(&second)).await.expect("read"), second);
            fjall.delete(query_for(&first)).await.expect("delete first");
            assert!(
                fjall
                    .find_by_query(query_for(&first))
                    .await
                    .expect("find")
                    .is_none()
            );
            assert_eq!(fjall.read(query_for(&second)).await.expect("read"), second);
            fjall
                .delete(query_for(&second))
                .await
                .expect("delete second");
        }
        assert!(fjall.list().await.expect("list").records().is_empty());
    }

    #[tokio::test]
    async fn a_record_under_the_earlier_key_is_still_read() {
        let (_dir, fjall) = open();
        let stored = record_with("did:a", "sign", "repo#main", "did:web:host%3A8443");
        insert_under_earlier_key(&fjall, &stored);

        assert_eq!(fjall.read(query_for(&stored)).await.expect("read"), stored);
        assert_eq!(
            fjall.list().await.expect("list").records(),
            &[stored.clone()]
        );
        assert!(matches!(
            fjall.create(stored.clone()).await,
            Err(RepositoryError::RecordAlreadyExists(_))
        ));
    }

    #[tokio::test]
    async fn the_earlier_key_answers_only_for_its_own_identifiers() {
        let (_dir, fjall) = open();
        let stored = record_with("did:a", "sign", "repo#main", "did:e");
        insert_under_earlier_key(&fjall, &stored);
        let other = record_with("did:a", "sign#repo", "main", "did:e");

        assert!(
            fjall
                .find_by_query(query_for(&other))
                .await
                .expect("find")
                .is_none()
        );
        assert!(matches!(
            fjall.delete(query_for(&other)).await,
            Err(RepositoryError::RecordNotFound(_))
        ));
        assert!(matches!(
            fjall.update(other.clone()).await,
            Err(RepositoryError::RecordNotFound(_))
        ));
        fjall.create(other.clone()).await.expect("create other");
        assert_eq!(fjall.read(query_for(&other)).await.expect("read"), other);
        assert_eq!(fjall.read(query_for(&stored)).await.expect("read"), stored);
    }

    #[tokio::test]
    async fn update_moves_a_record_to_the_current_key() {
        let (_dir, fjall) = open();
        let stored = record_with("did:a", "sign", "repo#main", "did:e");
        let legacy = insert_under_earlier_key(&fjall, &stored);

        let updated = stored.clone().with_authorized(false);
        fjall.update(updated.clone()).await.expect("update");

        assert!(
            !fjall
                .keyspace
                .contains_key(legacy.as_bytes())
                .expect("contains")
        );
        let current = TrustRecordKey::from_record(&stored).sk();
        assert!(
            fjall
                .keyspace
                .contains_key(current.as_bytes())
                .expect("contains")
        );
        assert_eq!(fjall.read(query_for(&stored)).await.expect("read"), updated);
        assert_eq!(fjall.list().await.expect("list").records(), &[updated]);
    }

    #[tokio::test]
    async fn an_interrupted_move_still_reads_and_deletes_cleanly() {
        let (_dir, fjall) = open();
        let stored = record_with("did:a", "sign", "repo#main", "did:e");
        let updated = stored.clone().with_authorized(false);
        // Both copies, as left by an update that stopped before removing the
        // earlier key.
        insert_under_earlier_key(&fjall, &stored);
        let current = TrustRecordKey::from_record(&stored).sk();
        fjall
            .keyspace
            .insert(
                current.as_bytes(),
                FjallStorage::serialize(&updated).expect("serialize"),
            )
            .expect("insert");

        assert_eq!(fjall.read(query_for(&stored)).await.expect("read"), updated);
        assert_eq!(fjall.list().await.expect("list").records(), &[updated]);

        fjall.delete(query_for(&stored)).await.expect("delete");
        assert!(
            fjall
                .find_by_query(query_for(&stored))
                .await
                .expect("find")
                .is_none()
        );
        assert!(fjall.list().await.expect("list").records().is_empty());
    }

    #[tokio::test]
    async fn delete_removes_a_record_stored_under_the_earlier_key() {
        let (_dir, fjall) = open();
        let stored = record_with("did:a", "sign", "repo#main", "did:e");
        insert_under_earlier_key(&fjall, &stored);

        fjall.delete(query_for(&stored)).await.expect("delete");
        assert!(
            fjall
                .find_by_query(query_for(&stored))
                .await
                .expect("find")
                .is_none()
        );
        assert!(fjall.list().await.expect("list").records().is_empty());
    }
}
