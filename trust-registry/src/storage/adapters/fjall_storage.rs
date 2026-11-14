//! Embedded [fjall](https://crates.io/crates/fjall) LSM key-value storage
//! adapter for the Trust Registry (feature `storage-fjall`).
//!
//! A single-node, on-disk backend with no external service — the same embedded
//! store the Affinidi mediator and VTA use. Records are keyed by the shared
//! [`TrustRecordKey`] (`TR#{authority}#{action}#{resource}#{entity}`, each
//! identifier escaped) and stored
//! as JSON values. fjall is synchronous, so each operation runs on a blocking
//! thread via [`tokio::task::spawn_blocking`].
//!
//! # Durability
//!
//! Every mutation is committed as one batch with [`PersistMode::SyncAll`]: the
//! journal is `fsync`ed before `create`, `update` or `delete` returns. fjall's
//! default only flushes the journal to operating-system buffers, which survives
//! a process crash but not a host crash or power loss; an acknowledged registry
//! write (and the DIDComm message it came from, deleted from the mediator once
//! handled) must survive both (rule R1.6). Writes are rare and small, so the
//! extra `fsync` per write is the right trade.
//!
//! # Atomicity
//!
//! Each write plans against the keys it reads and commits under one lock, so
//! check-then-act cannot interleave with another write. fjall locks the
//! database directory, so only one process writes it.

use fjall::{Config, Database, Keyspace, KeyspaceCreateOptions, PersistMode, Readable};
use tracing::info;

use std::sync::{Arc, Mutex};

use crate::configs::MessageIdStoreConfig;
use crate::dedup::MessageIdStore;
use crate::dedup::fjall::FjallMessageIdStore;
use crate::domain::key::{TrustRecordKey, dedupe_listing};
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
    /// The record of accepted document identifiers in this database, opened
    /// on first request. One per database: its claims live in its memory.
    message_ids: Arc<tokio::sync::OnceCell<Arc<FjallMessageIdStore>>>,
}

impl FjallStorage {
    /// Open (or create) the fjall database at `path`.
    pub fn new(path: &str) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        info!("Opening fjall storage at {path}");
        let db = Database::open(Config::new(std::path::Path::new(path)))?;
        let keyspace = db.keyspace(KEYSPACE_NAME, KeyspaceCreateOptions::default)?;
        Ok(Self {
            keyspace,
            db,
            write_lock: Arc::new(Mutex::new(())),
            message_ids: Arc::new(tokio::sync::OnceCell::new()),
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
            let mut reader = FjallReader {
                keyspace: keyspace.clone(),
                db: db.clone(),
            };
            let ops = futures::executor::block_on(plan(&mut reader))?;
            // fsync before acknowledging; see the module docs.
            let mut batch = db.batch().durability(Some(PersistMode::SyncAll));
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

/// Reads for lookups and the write planners.
pub(crate) struct FjallReader {
    keyspace: Keyspace,
    db: Database,
}

fn decode(value: Option<fjall::UserValue>) -> Result<Option<TrustRecord>, RepositoryError> {
    value
        .map(|value| FjallStorage::deserialize(&value))
        .transpose()
}

#[async_trait::async_trait]
impl KeyedReader for FjallReader {
    async fn read_at(&mut self, storage_key: &str) -> Result<Option<TrustRecord>, RepositoryError> {
        decode(
            self.keyspace
                .get(storage_key.as_bytes())
                .map_err(query_error)?,
        )
    }

    /// Both keys from one snapshot.
    async fn read_pair(
        &mut self,
        first: &str,
        second: &str,
    ) -> Result<(Option<TrustRecord>, Option<TrustRecord>), RepositoryError> {
        let snapshot = self.db.snapshot();
        let first = snapshot
            .get(&self.keyspace, first.as_bytes())
            .map_err(query_error)?;
        let second = snapshot
            .get(&self.keyspace, second.as_bytes())
            .map_err(query_error)?;
        Ok((decode(first)?, decode(second)?))
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
        let mut reader = FjallReader {
            keyspace: self.keyspace.clone(),
            db: self.db.clone(),
        };
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

    async fn list(&self) -> Result<TrustRecordList, RepositoryError> {
        self.list_matching(&TrustRecordFilter::all()).await
    }

    /// A prefix scan of the keys the filter's leading identifiers name.
    async fn list_matching(
        &self,
        filter: &TrustRecordFilter,
    ) -> Result<TrustRecordList, RepositoryError> {
        let ks = self.keyspace.clone();
        let prefixes = filter.storage_key_prefixes();
        let (entries, unreadable) = tokio::task::spawn_blocking(move || {
            let mut entries = Vec::new();
            let mut unreadable = Vec::new();
            for prefix in prefixes {
                for guard in ks.prefix(prefix.as_bytes()) {
                    let (key, value) = guard.into_inner().map_err(query_error)?;
                    let key = String::from_utf8_lossy(&key).into_owned();
                    match FjallStorage::deserialize(&value) {
                        Ok(record) => entries.push((key, record)),
                        Err(e) => skip_unreadable(key, &e, &mut unreadable),
                    }
                }
            }
            Ok::<_, RepositoryError>((entries, unreadable))
        })
        .await
        .map_err(join_error)??;
        Ok(TrustRecordList::with_unreadable(dedupe_listing(entries), unreadable).filtered(filter))
    }

    /// The fjall record of accepted document identifiers, in this database
    /// ([`FjallMessageIdStore`]). Opened once; later calls return the same
    /// store, with the settings of the first.
    async fn message_id_store(
        &self,
        config: &MessageIdStoreConfig,
    ) -> Result<Option<Arc<dyn MessageIdStore>>, RepositoryError> {
        let db = self.db.clone();
        let config = *config;
        let store = self
            .message_ids
            .get_or_try_init(|| async move {
                tokio::task::spawn_blocking(move || FjallMessageIdStore::open(db, config))
                    .await
                    .map_err(join_error)?
                    .map(Arc::new)
                    .map_err(|e| RepositoryError::ConnectionFailed(e.to_string()))
            })
            .await?;
        Ok(Some(Arc::clone(store) as Arc<dyn MessageIdStore>))
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
            std::slice::from_ref(&stored)
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

    async fn conformance_fixture() -> Option<crate::storage::conformance::Fixture> {
        let (dir, fjall) = open();
        let writer = fjall.keyspace.clone();
        let remover = fjall.keyspace.clone();
        Some(
            crate::storage::conformance::Fixture::new(fjall)
                .with_guard(dir)
                .with_corrupter(
                    move |storage_key: String| {
                        writer
                            .insert(storage_key.as_bytes(), b"{not json".to_vec())
                            .expect("insert");
                        Box::pin(async {})
                    },
                    move |storage_key: String| {
                        remover.remove(storage_key.as_bytes()).expect("remove");
                        Box::pin(async {})
                    },
                ),
        )
    }

    crate::storage::conformance::repository_conformance_tests!(fjall, conformance_fixture().await);

    /// #194: the store the builder takes from the repository is one per
    /// database, and what it records survives the registry restarting.
    #[tokio::test]
    async fn the_repository_store_is_shared_and_survives_a_restart() {
        use crate::dedup::{Claim, StoredOutcome};
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().to_str().expect("path").to_string();
        let config = MessageIdStoreConfig::default();
        let key = "MID#did:example:a#1";
        let outcome = StoredOutcome::Rejected(
            trust_tasks_rs::TrustTask::new(
                "1".to_string(),
                "https://trusttasks.org/spec/registry/record/put/0.1"
                    .parse()
                    .expect("type uri"),
                serde_json::json!({}),
            )
            .reject_with("e".to_string(), trust_tasks_rs::RejectReason::IdConflict),
        );
        {
            let fjall = FjallStorage::new(&path).expect("open");
            let store = fjall
                .message_id_store(&config)
                .await
                .expect("opens")
                .expect("fjall has a durable store");
            let again = fjall
                .message_id_store(&config)
                .await
                .expect("opens")
                .expect("store");
            let Claim::Acquired(token) = store.claim(key, "digest").await.expect("claim") else {
                panic!("first claim is acquired");
            };
            assert!(
                matches!(again.claim(key, "digest").await, Ok(Claim::InFlight)),
                "a second request returns the same store"
            );
            store
                .complete(key, &token, &outcome)
                .await
                .expect("complete");
        }
        let fjall = FjallStorage::new(&path).expect("reopen");
        let store = fjall
            .message_id_store(&config)
            .await
            .expect("opens")
            .expect("store");
        assert!(matches!(
            store.claim(key, "digest").await,
            Ok(Claim::Replay(_))
        ));
    }
}
