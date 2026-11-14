use redis::{AsyncCommands, Client, aio::MultiplexedConnection};
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, info};

use crate::domain::key::{TR_SK_PREFIX, TrustRecordKey, dedupe_listing};
use crate::domain::*;
use crate::storage::keyed::{
    Action as KeyedAction, KeyedReader, Op, lookup, plan_create, plan_delete, plan_update,
};
use crate::storage::repository::*;

/// Redis storage adapter for Trust Registry
/// Keys are formatted as: TR#{authority}#{action}#{resource}#{entity}, each
/// identifier escaped (see `TrustRecordKey::sk`)
/// Values are JSON-serialized TrustRecord objects
///
/// Every write is atomic across registry replicas sharing one Redis: it reads
/// the keys it depends on under `WATCH` and applies its changes in one
/// `MULTI`/`EXEC`, which Redis aborts if any watched key changed; the write
/// then re-plans. So two strict creates of one key never both succeed, and an
/// update racing a delete cannot bring the record back.
#[derive(Clone)]
pub struct RedisStorage {
    /// One multiplexed connection. Every use must hold the write lock for the
    /// whole operation: writes `WATCH` keys on this connection and then
    /// `MULTI`/`EXEC`, and a command from another task in between would
    /// change what is watched or land inside the transaction.
    connection: Arc<RwLock<MultiplexedConnection>>,
}

impl RedisStorage {
    pub async fn new(redis_url: &str) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        info!(
            "Connecting to Redis at {}",
            crate::configs::storage::redact_url_credentials(redis_url)
        );
        let client = Client::open(redis_url)?;
        let connection = client.get_multiplexed_async_connection().await?;

        Ok(Self {
            connection: Arc::new(RwLock::new(connection)),
        })
    }

    fn serialize_record(record: &TrustRecord) -> Result<String, RepositoryError> {
        serde_json::to_string(record).map_err(|e| {
            RepositoryError::SerializationFailed(format!("Failed to serialize record: {e}"))
        })
    }

    fn deserialize_record(data: &str) -> Result<TrustRecord, RepositoryError> {
        serde_json::from_str(data).map_err(|e| {
            RepositoryError::SerializationFailed(format!("Failed to deserialize record: {e}"))
        })
    }
}

/// How many times a write is re-planned when a key it read changed before it
/// landed.
const MAX_WRITE_ATTEMPTS: usize = 5;

/// Reads for the planners: each key is `WATCH`ed before it is read, so the
/// `MULTI`/`EXEC` that applies the plan fails if any of them changed.
///
/// Safe on the shared multiplexed connection because every operation holds
/// the connection's write lock for its whole duration.
struct WatchingReader<'a> {
    conn: &'a mut MultiplexedConnection,
}

#[async_trait::async_trait]
impl KeyedReader for WatchingReader<'_> {
    async fn read_at(&mut self, storage_key: &str) -> Result<Option<TrustRecord>, RepositoryError> {
        redis::cmd("WATCH")
            .arg(storage_key)
            .exec_async(&mut *self.conn)
            .await
            .map_err(|e| RepositoryError::QueryFailed(format!("Redis WATCH failed: {e}")))?;
        RedisStorage::get_record(self.conn, storage_key).await
    }

    async fn read_pair(
        &mut self,
        first: &str,
        second: &str,
    ) -> Result<(Option<TrustRecord>, Option<TrustRecord>), RepositoryError> {
        redis::cmd("WATCH")
            .arg(first)
            .arg(second)
            .exec_async(&mut *self.conn)
            .await
            .map_err(|e| RepositoryError::QueryFailed(format!("Redis WATCH failed: {e}")))?;
        RedisStorage::get_pair(self.conn, first, second).await
    }
}

/// Plain reads, for lookups.
struct PlainReader<'a> {
    conn: &'a mut MultiplexedConnection,
}

#[async_trait::async_trait]
impl KeyedReader for PlainReader<'_> {
    async fn read_at(&mut self, storage_key: &str) -> Result<Option<TrustRecord>, RepositoryError> {
        RedisStorage::get_record(self.conn, storage_key).await
    }

    async fn read_pair(
        &mut self,
        first: &str,
        second: &str,
    ) -> Result<(Option<TrustRecord>, Option<TrustRecord>), RepositoryError> {
        RedisStorage::get_pair(self.conn, first, second).await
    }
}

impl RedisStorage {
    async fn get_record(
        conn: &mut MultiplexedConnection,
        storage_key: &str,
    ) -> Result<Option<TrustRecord>, RepositoryError> {
        let data: Option<String> = conn
            .get(storage_key)
            .await
            .map_err(|e| RepositoryError::QueryFailed(format!("Redis GET failed: {e}")))?;
        data.map(|data| Self::deserialize_record(&data)).transpose()
    }

    /// Both keys in one `MGET`, so they are read at one point in time.
    async fn get_pair(
        conn: &mut MultiplexedConnection,
        first: &str,
        second: &str,
    ) -> Result<(Option<TrustRecord>, Option<TrustRecord>), RepositoryError> {
        let values: Vec<Option<String>> = redis::cmd("MGET")
            .arg(first)
            .arg(second)
            .query_async(&mut *conn)
            .await
            .map_err(|e| RepositoryError::QueryFailed(format!("Redis MGET failed: {e}")))?;
        let mut values = values.into_iter();
        let mut next = || {
            values
                .next()
                .flatten()
                .map(|data| Self::deserialize_record(&data))
                .transpose()
        };
        Ok((next()?, next()?))
    }

    async fn find(&self, key: &TrustRecordKey) -> Result<Option<TrustRecord>, RepositoryError> {
        let mut conn = self.connection.write().await;
        let mut reader = PlainReader { conn: &mut conn };
        Ok(lookup(&mut reader, key).await?.map(|(_, record)| record))
    }

    /// Plan a write against `WATCH`ed keys and apply it in one
    /// `MULTI`/`EXEC`, re-planning if a watched key changed in between.
    async fn write<F>(&self, plan: F) -> Result<(), RepositoryError>
    where
        F: for<'a, 'c> Fn(
            &'a mut WatchingReader<'c>,
        )
            -> futures::future::BoxFuture<'a, Result<Vec<Op>, RepositoryError>>,
    {
        let mut conn = self.connection.write().await;
        // A write that was cancelled, or stopped on an error, after its
        // WATCHes may have left keys watched; they would abort this EXEC.
        redis::cmd("UNWATCH")
            .exec_async(&mut *conn)
            .await
            .map_err(|e| RepositoryError::QueryFailed(format!("Redis UNWATCH failed: {e}")))?;
        for _ in 0..MAX_WRITE_ATTEMPTS {
            let planned = {
                let mut reader = WatchingReader { conn: &mut conn };
                plan(&mut reader).await
            };
            let ops = match planned {
                Ok(ops) => ops,
                Err(e) => {
                    let _ = redis::cmd("UNWATCH").exec_async(&mut *conn).await;
                    return Err(e);
                }
            };
            let mut pipe = redis::pipe();
            pipe.atomic();
            for op in &ops {
                match &op.action {
                    KeyedAction::Put(record) => {
                        pipe.set(&op.storage_key, Self::serialize_record(record)?)
                            .ignore();
                    }
                    KeyedAction::Delete => {
                        pipe.del(&op.storage_key).ignore();
                    }
                }
            }
            let applied: Option<redis::Value> = pipe
                .query_async(&mut *conn)
                .await
                .map_err(|e| RepositoryError::QueryFailed(format!("Redis EXEC failed: {e}")))?;
            if applied.is_some() {
                debug!("Applied {} key operations", ops.len());
                return Ok(());
            }
        }
        Err(RepositoryError::QueryFailed(format!(
            "the keys this write depends on kept changing; gave up after {MAX_WRITE_ATTEMPTS} \
             attempts"
        )))
    }
}

#[async_trait::async_trait]
impl TrustRecordRepository for RedisStorage {
    async fn find_by_query(
        &self,
        query: TrustRecordQuery,
    ) -> Result<Option<TrustRecord>, RepositoryError> {
        let key = TrustRecordKey::from_query(&query);
        debug!("Finding record by key: {}", key);
        self.find(&key).await
    }
}

#[async_trait::async_trait]
impl TrustRecordAdminRepository for RedisStorage {
    async fn create(&self, record: TrustRecord) -> Result<(), RepositoryError> {
        let storage_key = TrustRecordKey::from_record(&record).sk();
        debug!("Creating record with key: {}", storage_key);
        self.write(|reader| {
            let record = record.clone();
            Box::pin(async move { plan_create(reader, &record).await })
        })
        .await?;
        info!("Record created successfully: {}", storage_key);
        Ok(())
    }

    async fn update(&self, record: TrustRecord) -> Result<(), RepositoryError> {
        let storage_key = TrustRecordKey::from_record(&record).sk();
        debug!("Updating record with key: {}", storage_key);
        self.write(|reader| {
            let record = record.clone();
            Box::pin(async move { plan_update(reader, &record).await })
        })
        .await?;
        info!("Record updated successfully: {}", storage_key);
        Ok(())
    }

    async fn delete(&self, query: TrustRecordQuery) -> Result<(), RepositoryError> {
        let key = TrustRecordKey::from_query(&query);
        debug!("Deleting record with key: {}", key);
        self.write(|reader| {
            let key = key.clone();
            Box::pin(async move { plan_delete(reader, &key).await })
        })
        .await?;
        info!("Record deleted successfully: {}", key);
        Ok(())
    }

    async fn list(&self) -> Result<TrustRecordList, RepositoryError> {
        debug!("Listing all records");

        let mut conn = self.connection.write().await;
        let mut entries = Vec::new();
        let mut unreadable = Vec::new();

        // Use SCAN instead of KEYS to avoid blocking Redis
        // SCAN is O(1) per call and iterates incrementally
        let mut cursor: u64 = 0;
        loop {
            let pattern = format!("{}*", TR_SK_PREFIX);
            let (new_cursor, keys): (u64, Vec<String>) = redis::cmd("SCAN")
                .arg(cursor)
                .arg("MATCH")
                .arg(&pattern)
                .arg("COUNT")
                .arg(100)
                .query_async(&mut *conn)
                .await
                .map_err(|e| RepositoryError::QueryFailed(format!("Redis SCAN failed: {e}")))?;

            for key in keys {
                let data: Option<String> = conn
                    .get(&key)
                    .await
                    .map_err(|e| RepositoryError::QueryFailed(format!("Redis GET failed: {e}")))?;

                if let Some(data) = data {
                    match Self::deserialize_record(&data) {
                        Ok(record) => entries.push((key, record)),
                        Err(e) => skip_unreadable(key, &e, &mut unreadable),
                    }
                }
            }

            if new_cursor == 0 {
                break;
            }
            cursor = new_cursor;
        }

        let records = dedupe_listing(entries);
        info!("Listed {} records", records.len());
        Ok(TrustRecordList::with_unreadable(records, unreadable))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serial_test::serial;
    use std::str::FromStr;

    fn create_test_record(
        entity: &str,
        authority: &str,
        action: &str,
        resource: &str,
        recognized: bool,
        authorized: bool,
        record_type: &str,
    ) -> TrustRecord {
        TrustRecordBuilder::new()
            .entity_id(EntityId::new(entity))
            .authority_id(AuthorityId::new(authority))
            .action(Action::new(action))
            .resource(Resource::new(resource))
            .recognized(recognized)
            .authorized(authorized)
            .record_type(RecordType::from_str(record_type).unwrap())
            .build()
            .unwrap()
    }

    /// The Redis named by `TR_TEST_REDIS_URL`, or `None` (the test is
    /// skipped, loudly) when it is unset. Each test deletes only the keys it
    /// wrote, but point it at a dedicated database (`redis://host:6379/15`).
    async fn get_test_storage() -> Option<RedisStorage> {
        let url = crate::storage::conformance::redis_test_url()?;
        Some(
            RedisStorage::new(&url)
                .await
                .expect("TR_TEST_REDIS_URL is set but Redis is unreachable"),
        )
    }

    async fn conformance_fixture() -> Option<crate::storage::conformance::Fixture> {
        let storage = get_test_storage().await?;
        // A second connection, as a second registry replica would hold.
        let peer = get_test_storage().await?;
        let writer = storage.clone();
        let remover = storage.clone();
        Some(
            crate::storage::conformance::Fixture::new(storage)
                .with_peer(peer)
                .with_corrupter(
                    move |storage_key: String| {
                        let storage = writer.clone();
                        Box::pin(async move {
                            let mut conn = storage.connection.write().await;
                            let result: redis::RedisResult<()> =
                                conn.set(&storage_key, "{not json").await;
                            result.expect("Redis SET");
                        })
                    },
                    move |storage_key: String| {
                        let storage = remover.clone();
                        Box::pin(async move {
                            let mut conn = storage.connection.write().await;
                            let _: Result<(), _> = conn.del(&storage_key).await;
                        })
                    },
                ),
        )
    }

    // Every Redis test here runs in the `redis` serial group, the suite's
    // included: they share one database, and one test's planted or leftover
    // keys must not be visible to another's listing mid-run.
    crate::storage::conformance::repository_conformance_tests!(redis, conformance_fixture().await);

    async fn cleanup_test_data(storage: &RedisStorage, records: &[TrustRecord]) {
        let mut conn = storage.connection.write().await;
        for record in records {
            let key = TrustRecordKey::from_record(record);
            let _: Result<(), _> = conn.del(key.sk()).await;
            if let Some(legacy) = key.legacy_sk() {
                let _: Result<(), _> = conn.del(&legacy).await;
            }
        }
    }

    #[tokio::test]
    #[serial(redis)]
    async fn test_create_and_read_record() {
        let Some(storage) = get_test_storage().await else {
            return;
        };

        let record = create_test_record(
            "did:example:entity1",
            "did:example:authority1",
            "issue",
            "VerifiableCredential",
            true,
            true,
            "authorization",
        );
        cleanup_test_data(&storage, std::slice::from_ref(&record)).await;

        storage.create(record.clone()).await.unwrap();

        let query = TrustRecordQuery::new(
            EntityId::new("did:example:entity1"),
            AuthorityId::new("did:example:authority1"),
            Action::new("issue"),
            Resource::new("VerifiableCredential"),
        );

        let retrieved = storage.read(query).await.unwrap();
        assert_eq!(retrieved.entity_id().as_str(), "did:example:entity1");
        assert!(retrieved.is_authorized());
        assert!(retrieved.is_recognized());

        cleanup_test_data(&storage, &[record]).await;
    }

    #[tokio::test]
    #[serial(redis)]
    async fn test_create_duplicate_fails() {
        let Some(storage) = get_test_storage().await else {
            return;
        };

        let record = create_test_record(
            "did:example:entity1",
            "did:example:authority1",
            "issue",
            "VerifiableCredential",
            true,
            true,
            "authorization",
        );
        cleanup_test_data(&storage, std::slice::from_ref(&record)).await;

        storage.create(record.clone()).await.unwrap();
        let result = storage.create(record.clone()).await;
        assert!(result.is_err());
        assert!(matches!(
            result,
            Err(RepositoryError::RecordAlreadyExists(_))
        ));

        cleanup_test_data(&storage, &[record]).await;
    }

    #[tokio::test]
    #[serial(redis)]
    async fn test_update_record() {
        let Some(storage) = get_test_storage().await else {
            return;
        };

        let record = create_test_record(
            "did:example:entity1",
            "did:example:authority1",
            "issue",
            "VerifiableCredential",
            true,
            true,
            "authorization",
        );
        cleanup_test_data(&storage, std::slice::from_ref(&record)).await;

        storage.create(record.clone()).await.unwrap();

        let updated_record = create_test_record(
            "did:example:entity1",
            "did:example:authority1",
            "issue",
            "VerifiableCredential",
            false,
            false,
            "authorization",
        );

        storage.update(updated_record).await.unwrap();

        let query = TrustRecordQuery::new(
            EntityId::new("did:example:entity1"),
            AuthorityId::new("did:example:authority1"),
            Action::new("issue"),
            Resource::new("VerifiableCredential"),
        );

        let retrieved = storage.read(query).await.unwrap();
        assert!(!retrieved.is_authorized());
        assert!(!retrieved.is_recognized());

        cleanup_test_data(&storage, &[record]).await;
    }

    #[tokio::test]
    #[serial(redis)]
    async fn test_delete_record() {
        let Some(storage) = get_test_storage().await else {
            return;
        };

        let record = create_test_record(
            "did:example:entity1",
            "did:example:authority1",
            "issue",
            "VerifiableCredential",
            true,
            true,
            "authorization",
        );
        cleanup_test_data(&storage, std::slice::from_ref(&record)).await;

        storage.create(record.clone()).await.unwrap();

        let query = TrustRecordQuery::new(
            EntityId::new("did:example:entity1"),
            AuthorityId::new("did:example:authority1"),
            Action::new("issue"),
            Resource::new("VerifiableCredential"),
        );

        storage.delete(query.clone()).await.unwrap();

        let result = storage.read(query).await;
        assert!(result.is_err());
        assert!(matches!(result, Err(RepositoryError::RecordNotFound(_))));
    }

    #[tokio::test]
    #[serial(redis)]
    async fn test_list_records() {
        let Some(storage) = get_test_storage().await else {
            return;
        };

        let record1 = create_test_record(
            "did:example:entity1",
            "did:example:authority1",
            "issue",
            "VerifiableCredential",
            true,
            true,
            "authorization",
        );

        let record2 = create_test_record(
            "did:example:entity2",
            "did:example:authority2",
            "verify",
            "DriverLicense",
            true,
            false,
            "recognition",
        );
        cleanup_test_data(&storage, &[record1.clone(), record2.clone()]).await;

        storage.create(record1.clone()).await.unwrap();
        storage.create(record2.clone()).await.unwrap();

        // The database may hold other records; this test's two must be there.
        let list = storage.list().await.unwrap();
        assert!(list.records().contains(&record1));
        assert!(list.records().contains(&record2));

        cleanup_test_data(&storage, &[record1, record2]).await;
    }

    #[tokio::test]
    #[serial(redis)]
    async fn test_find_by_query() {
        let Some(storage) = get_test_storage().await else {
            return;
        };

        let record = create_test_record(
            "did:example:entity1",
            "did:example:authority1",
            "issue",
            "VerifiableCredential",
            true,
            true,
            "authorization",
        );
        cleanup_test_data(&storage, std::slice::from_ref(&record)).await;

        storage.create(record.clone()).await.unwrap();

        let query = TrustRecordQuery::new(
            EntityId::new("did:example:entity1"),
            AuthorityId::new("did:example:authority1"),
            Action::new("issue"),
            Resource::new("VerifiableCredential"),
        );

        let result = storage.find_by_query(query).await.unwrap();
        assert!(result.is_some());
        assert_eq!(result.unwrap().entity_id().as_str(), "did:example:entity1");

        cleanup_test_data(&storage, &[record]).await;
    }

    fn query_for(record: &TrustRecord) -> TrustRecordQuery {
        TrustRecordQuery::new(
            record.entity_id().clone(),
            record.authority_id().clone(),
            record.action().clone(),
            record.resource().clone(),
        )
    }

    /// Store `record` the way an older release did: under the unescaped key.
    async fn insert_under_earlier_key(storage: &RedisStorage, record: &TrustRecord) -> String {
        let legacy = TrustRecordKey::from_record(record)
            .legacy_sk()
            .expect("identifiers contain '#' or '%'");
        let mut conn = storage.connection.write().await;
        let _: () = conn
            .set(&legacy, RedisStorage::serialize_record(record).unwrap())
            .await
            .unwrap();
        legacy
    }

    #[tokio::test]
    #[serial(redis)]
    async fn test_records_with_separator_in_identifiers_stay_distinct() {
        let Some(storage) = get_test_storage().await else {
            return;
        };
        let first = create_test_record(
            "did:example:e",
            "did:example:a",
            "sign",
            "repo#main",
            true,
            true,
            "authorization",
        );
        let second = create_test_record(
            "did:example:e",
            "did:example:a",
            "sign#repo",
            "main",
            true,
            false,
            "authorization",
        );
        cleanup_test_data(&storage, &[first.clone(), second.clone()]).await;

        storage.create(first.clone()).await.unwrap();
        storage.create(second.clone()).await.unwrap();
        assert_eq!(storage.read(query_for(&first)).await.unwrap(), first);
        assert_eq!(storage.read(query_for(&second)).await.unwrap(), second);
        storage.delete(query_for(&first)).await.unwrap();
        assert!(
            storage
                .find_by_query(query_for(&first))
                .await
                .unwrap()
                .is_none()
        );
        assert_eq!(storage.read(query_for(&second)).await.unwrap(), second);

        cleanup_test_data(&storage, &[first, second]).await;
    }

    #[tokio::test]
    #[serial(redis)]
    async fn test_record_under_earlier_key_is_read_updated_and_deleted() {
        let Some(storage) = get_test_storage().await else {
            return;
        };
        let stored = create_test_record(
            "did:example:e",
            "did:example:a",
            "sign",
            "repo#main",
            true,
            true,
            "authorization",
        );
        let other = create_test_record(
            "did:example:e",
            "did:example:a",
            "sign#repo",
            "main",
            true,
            true,
            "authorization",
        );
        cleanup_test_data(&storage, &[stored.clone(), other.clone()]).await;
        let legacy = insert_under_earlier_key(&storage, &stored).await;

        assert_eq!(storage.read(query_for(&stored)).await.unwrap(), stored);
        assert!(
            storage
                .find_by_query(query_for(&other))
                .await
                .unwrap()
                .is_none()
        );
        assert!(matches!(
            storage.delete(query_for(&other)).await,
            Err(RepositoryError::RecordNotFound(_))
        ));
        assert!(matches!(
            storage.create(stored.clone()).await,
            Err(RepositoryError::RecordAlreadyExists(_))
        ));

        let updated = stored.clone().with_authorized(false);
        storage.update(updated.clone()).await.unwrap();
        {
            let mut conn = storage.connection.write().await;
            let legacy_left: bool = conn.exists(&legacy).await.unwrap();
            assert!(
                !legacy_left,
                "update leaves the record under its current key only"
            );
        }
        assert_eq!(storage.read(query_for(&stored)).await.unwrap(), updated);

        storage.delete(query_for(&stored)).await.unwrap();
        assert!(
            storage
                .find_by_query(query_for(&stored))
                .await
                .unwrap()
                .is_none()
        );

        cleanup_test_data(&storage, &[stored, other]).await;
    }

    /// A's current key is the string B was stored under by an older release.
    fn cross_pair() -> (TrustRecord, TrustRecord) {
        let a = create_test_record(
            "did:example:e",
            "did:example:a",
            "act",
            "x#y",
            true,
            true,
            "authorization",
        );
        let b = create_test_record(
            "did:example:e",
            "did:example:a",
            "act",
            "x%23y",
            true,
            false,
            "authorization",
        );
        assert_eq!(
            TrustRecordKey::from_record(&a).sk(),
            TrustRecordKey::from_record(&b)
                .legacy_sk()
                .expect("differs")
        );
        (a, b)
    }

    #[tokio::test]
    #[serial(redis)]
    async fn test_missing_record_writes_leave_the_record_under_its_key_string() {
        let Some(storage) = get_test_storage().await else {
            return;
        };
        let (a, b) = cross_pair();
        cleanup_test_data(&storage, &[a.clone(), b.clone()]).await;
        insert_under_earlier_key(&storage, &b).await;

        assert!(matches!(
            storage.delete(query_for(&a)).await,
            Err(RepositoryError::RecordNotFound(_))
        ));
        assert_eq!(storage.read(query_for(&b)).await.unwrap(), b);
        assert!(matches!(
            storage.update(a.clone()).await,
            Err(RepositoryError::RecordNotFound(_))
        ));
        assert_eq!(storage.read(query_for(&b)).await.unwrap(), b);
        assert!(
            storage
                .find_by_query(query_for(&a))
                .await
                .unwrap()
                .is_none()
        );

        cleanup_test_data(&storage, &[a, b]).await;
    }

    #[tokio::test]
    #[serial(redis)]
    async fn test_create_moves_the_record_under_its_key_string_aside() {
        let Some(storage) = get_test_storage().await else {
            return;
        };
        let (a, b) = cross_pair();
        cleanup_test_data(&storage, &[a.clone(), b.clone()]).await;
        insert_under_earlier_key(&storage, &b).await;

        storage.create(a.clone()).await.unwrap();

        assert_eq!(storage.read(query_for(&a)).await.unwrap(), a);
        assert_eq!(storage.read(query_for(&b)).await.unwrap(), b);
        {
            let mut conn = storage.connection.write().await;
            let moved: bool = conn
                .exists(TrustRecordKey::from_record(&b).sk())
                .await
                .unwrap();
            assert!(moved, "B now lives under its own current key");
        }
        storage.delete(query_for(&a)).await.unwrap();
        assert_eq!(storage.read(query_for(&b)).await.unwrap(), b);

        cleanup_test_data(&storage, &[a, b]).await;
    }
}
