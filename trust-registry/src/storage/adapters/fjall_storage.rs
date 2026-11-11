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

use std::sync::{Arc, Mutex};

use crate::domain::key::{TR_SK_PREFIX, TrustRecordKey, dedupe_listing};
use crate::domain::*;
use crate::storage::keyed::{
    Action as KeyedAction, KeyedReader, Op, lookup, plan_create, plan_delete, plan_update,
};
use crate::storage::repository::*;

/// Keyspace (table) holding the trust records.
const KEYSPACE_NAME: &str = "trust_records";

/// fjall-backed trust record store.
pub struct FjallStorage {
    keyspace: Keyspace,
    db: Database,
    /// Held across each write's reads and its batch, so the keys a write
    /// planned against cannot change before it lands.
    write_lock: Arc<Mutex<()>>,
}

impl FjallStorage {
    /// Open (or create) the fjall database at `path`.
    pub fn new(path: &str) -> Result<Self, Box<dyn std::error::Error>> {
        info!("Opening fjall storage at {path}");
        let db = Database::open(Config::new(std::path::Path::new(path)))?;
        let keyspace = db.keyspace(KEYSPACE_NAME, KeyspaceCreateOptions::default)?;
        Ok(Self {
            keyspace,
            db,
            write_lock: Arc::new(Mutex::new(())),
        })
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

    /// Plan a write with `plan` and apply it as one batch, under the write
    /// lock.
    async fn write<F>(&self, plan: F) -> Result<(), RepositoryError>
    where
        F: for<'a> FnOnce(
                &'a mut FjallReader,
            )
                -> futures::future::BoxFuture<'a, Result<Vec<Op>, RepositoryError>>
            + Send
            + 'static,
    {
        let keyspace = self.keyspace.clone();
        let db = self.db.clone();
        let write_lock = self.write_lock.clone();
        tokio::task::spawn_blocking(move || {
            let _guard = write_lock
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            let mut reader = FjallReader(keyspace.clone());
            let ops = futures::executor::block_on(plan(&mut reader))?;
            let mut batch = db.batch();
            for op in ops {
                match op.action {
                    KeyedAction::Put(record) => batch.insert(
                        &keyspace,
                        op.storage_key.as_bytes(),
                        FjallStorage::serialize(&record)?,
                    ),
                    KeyedAction::Delete => batch.remove(&keyspace, op.storage_key.as_bytes()),
                }
            }
            batch.commit().map_err(query_error)
        })
        .await
        .map_err(join_error)?
    }
}

/// Reads for the write planners.
pub(crate) struct FjallReader(Keyspace);

#[async_trait::async_trait]
impl KeyedReader for FjallReader {
    async fn read_at(&mut self, storage_key: &str) -> Result<Option<TrustRecord>, RepositoryError> {
        self.0
            .get(storage_key.as_bytes())
            .map_err(query_error)?
            .map(|value| FjallStorage::deserialize(&value))
            .transpose()
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
        let key = TrustRecordKey::from_query(&query);
        let mut reader = FjallReader(self.keyspace.clone());
        tokio::task::spawn_blocking(move || {
            Ok(futures::executor::block_on(lookup(&mut reader, &key))?.map(|(_, record)| record))
        })
        .await
        .map_err(join_error)?
    }
}

#[async_trait::async_trait]
impl TrustRecordAdminRepository for FjallStorage {
    async fn create(&self, record: TrustRecord) -> Result<(), RepositoryError> {
        self.write(move |reader| Box::pin(async move { plan_create(reader, &record).await }))
            .await
    }

    async fn update(&self, record: TrustRecord) -> Result<(), RepositoryError> {
        self.write(move |reader| Box::pin(async move { plan_update(reader, &record).await }))
            .await
    }

    async fn delete(&self, query: TrustRecordQuery) -> Result<(), RepositoryError> {
        let key = TrustRecordKey::from_query(&query);
        self.write(move |reader| Box::pin(async move { plan_delete(reader, &key).await }))
            .await
    }

    async fn read(&self, query: TrustRecordQuery) -> Result<TrustRecord, RepositoryError> {
        self.find_by_query(query.clone())
            .await?
            .ok_or_else(|| RepositoryError::RecordNotFound(TrustRecordKey::from_query(&query).sk()))
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

    /// A's current key is the string B was stored under by an older release.
    fn cross_pair() -> (TrustRecord, TrustRecord) {
        let a = record_with("did:a", "act", "x#y", "did:e");
        let b = record_with("did:a", "act", "x%23y", "did:e").with_authorized(false);
        assert_eq!(
            TrustRecordKey::from_record(&a).sk(),
            TrustRecordKey::from_record(&b)
                .legacy_sk()
                .expect("differs")
        );
        (a, b)
    }

    #[tokio::test]
    async fn deleting_a_missing_record_leaves_the_record_under_its_key_string() {
        let (_dir, fjall) = open();
        let (a, b) = cross_pair();
        insert_under_earlier_key(&fjall, &b);

        assert!(matches!(
            fjall.delete(query_for(&a)).await,
            Err(RepositoryError::RecordNotFound(_))
        ));
        assert_eq!(fjall.read(query_for(&b)).await.expect("read"), b);
    }

    #[tokio::test]
    async fn updating_a_missing_record_leaves_the_record_under_its_key_string() {
        let (_dir, fjall) = open();
        let (a, b) = cross_pair();
        insert_under_earlier_key(&fjall, &b);

        assert!(matches!(
            fjall.update(a.clone()).await,
            Err(RepositoryError::RecordNotFound(_))
        ));
        assert_eq!(fjall.read(query_for(&b)).await.expect("read"), b);
        assert!(
            fjall
                .find_by_query(query_for(&a))
                .await
                .expect("find")
                .is_none()
        );
    }

    #[tokio::test]
    async fn creating_a_record_moves_the_one_under_its_key_string_aside() {
        let (_dir, fjall) = open();
        let (a, b) = cross_pair();
        insert_under_earlier_key(&fjall, &b);

        fjall.create(a.clone()).await.expect("create");

        assert_eq!(fjall.read(query_for(&a)).await.expect("read"), a);
        assert_eq!(fjall.read(query_for(&b)).await.expect("read"), b);
        let b_current = TrustRecordKey::from_record(&b).sk();
        assert!(
            fjall
                .keyspace
                .contains_key(b_current.as_bytes())
                .expect("contains")
        );
        let mut listed = fjall.list().await.expect("list").into_records();
        listed.sort_by(|x, y| x.resource().as_str().cmp(y.resource().as_str()));
        assert_eq!(listed, vec![a.clone(), b.clone()]);

        fjall.delete(query_for(&a)).await.expect("delete a");
        assert_eq!(fjall.read(query_for(&b)).await.expect("read"), b);
    }

    #[tokio::test]
    async fn moving_a_record_to_its_current_key_moves_the_occupant_aside() {
        let (_dir, fjall) = open();
        // Both under their earlier keys; A's current key is the occupant's
        // earlier key.
        let (a, occupant) = cross_pair();
        let a_legacy = TrustRecordKey::from_record(&a)
            .legacy_sk()
            .expect("differs");
        insert_under_earlier_key(&fjall, &a);
        insert_under_earlier_key(&fjall, &occupant);

        let updated = a.clone().with_authorized(false);
        fjall.update(updated.clone()).await.expect("update");

        assert!(
            !fjall
                .keyspace
                .contains_key(a_legacy.as_bytes())
                .expect("contains")
        );
        assert_eq!(fjall.read(query_for(&a)).await.expect("read"), updated);
        assert_eq!(
            fjall.read(query_for(&occupant)).await.expect("read"),
            occupant
        );
    }
}
