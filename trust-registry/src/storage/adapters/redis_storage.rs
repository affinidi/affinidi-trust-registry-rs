use redis::aio::{
    ConnectionLike, ConnectionManager, ConnectionManagerConfig, MultiplexedConnection,
};
use redis::{AsyncCommands, AsyncConnectionConfig, Client};
use std::sync::Arc;
use std::time::Duration;
use tracing::{debug, info};

use crate::configs::MessageIdStoreConfig;
use crate::dedup::MessageIdStore;
use crate::dedup::redis::RedisMessageIdStore;
use crate::domain::key::{TrustRecordKey, dedupe_listing};
use crate::domain::*;
use crate::storage::keyed::{
    Action as KeyedAction, KeyedReader, Op, lookup, plan_create, plan_delete, plan_update,
};
use crate::storage::repository::*;

/// How long connecting to Redis may take, for the shared connection and for
/// each write's own.
pub const CONNECTION_TIMEOUT: Duration = Duration::from_secs(5);

/// How long one command may wait for its answer. Above the `redis` crate's
/// 500 ms default, so one `MGET` of a large page on a slow link does not fail
/// a listing part-way.
pub const RESPONSE_TIMEOUT: Duration = Duration::from_secs(5);

/// Keys asked for per `SCAN` step of a listing, and so the most values one
/// `MGET` fetches.
const SCAN_PAGE: usize = 500;

/// Redis storage adapter for Trust Registry
/// Keys are formatted as: TR#{authority}#{action}#{resource}#{entity}, each
/// identifier escaped (see `TrustRecordKey::sk`)
/// Values are JSON-serialized TrustRecord objects
///
/// Reads share one auto-reconnecting [`ConnectionManager`], cloned per
/// operation, so they run concurrently over its multiplexed connection, and a
/// dropped connection (a Redis restart, a failover, an idle reset) is
/// re-established instead of failing every later command.
///
/// Every write is atomic across registry replicas sharing one Redis: it reads
/// the keys it depends on under `WATCH` and applies its changes in one
/// `MULTI`/`EXEC`, which Redis aborts if any watched key changed; the write
/// then re-plans. So two strict creates of one key never both succeed, and an
/// update racing a delete cannot bring the record back. `WATCH` belongs to a
/// connection, so each write opens a connection of its own for its duration:
/// a command from another task on a shared connection would change what is
/// watched or land inside the transaction. Writes are rare (administration);
/// the connection set-up is their price.
#[derive(Clone)]
pub struct RedisStorage {
    client: Client,
    /// Shared by reads and by the record of accepted documents; cloned per
    /// operation.
    connection: ConnectionManager,
}

impl RedisStorage {
    pub async fn new(redis_url: &str) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        info!(
            "Connecting to Redis at {}",
            crate::configs::storage::redact_url_credentials(redis_url)
        );
        let client = Client::open(redis_url)?;
        let connection = client
            .get_connection_manager_with_config(
                ConnectionManagerConfig::new()
                    .set_connection_timeout(Some(CONNECTION_TIMEOUT))
                    .set_response_timeout(Some(RESPONSE_TIMEOUT)),
            )
            .await?;

        Ok(Self { client, connection })
    }

    /// A connection of its own for one write.
    async fn write_connection(&self) -> Result<MultiplexedConnection, RepositoryError> {
        self.client
            .get_multiplexed_async_connection_with_config(
                &AsyncConnectionConfig::new()
                    .set_connection_timeout(Some(CONNECTION_TIMEOUT))
                    .set_response_timeout(Some(RESPONSE_TIMEOUT)),
            )
            .await
            .map_err(|e| RepositoryError::ConnectionFailed(format!("Redis connect failed: {e}")))
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
/// On the write's own connection, which nothing else uses.
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
struct PlainReader {
    conn: ConnectionManager,
}

#[async_trait::async_trait]
impl KeyedReader for PlainReader {
    async fn read_at(&mut self, storage_key: &str) -> Result<Option<TrustRecord>, RepositoryError> {
        RedisStorage::get_record(&mut self.conn, storage_key).await
    }

    async fn read_pair(
        &mut self,
        first: &str,
        second: &str,
    ) -> Result<(Option<TrustRecord>, Option<TrustRecord>), RepositoryError> {
        RedisStorage::get_pair(&mut self.conn, first, second).await
    }
}

/// Escape the glob characters `SCAN MATCH` interprets, so a key prefix
/// matches only itself.
fn glob_escape(prefix: &str) -> String {
    let mut escaped = String::with_capacity(prefix.len() + 4);
    for character in prefix.chars() {
        if matches!(character, '*' | '?' | '[' | ']' | '\\') {
            escaped.push('\\');
        }
        escaped.push(character);
    }
    escaped
}

impl RedisStorage {
    async fn get_record<C: ConnectionLike + Send + Sync>(
        conn: &mut C,
        storage_key: &str,
    ) -> Result<Option<TrustRecord>, RepositoryError> {
        let data: Option<String> = conn
            .get(storage_key)
            .await
            .map_err(|e| RepositoryError::QueryFailed(format!("Redis GET failed: {e}")))?;
        data.map(|data| Self::deserialize_record(&data)).transpose()
    }

    /// Both keys in one `MGET`, so they are read at one point in time.
    async fn get_pair<C: ConnectionLike + Send + Sync>(
        conn: &mut C,
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
        let mut reader = PlainReader {
            conn: self.connection.clone(),
        };
        Ok(lookup(&mut reader, key).await?.map(|(_, record)| record))
    }

    /// Plan a write against `WATCH`ed keys and apply it in one
    /// `MULTI`/`EXEC`, re-planning if a watched key changed in between. Runs
    /// on a connection of its own, dropped afterwards (with any `WATCH` a
    /// failed or cancelled write left).
    async fn write<F>(&self, plan: F) -> Result<(), RepositoryError>
    where
        F: for<'a, 'c> Fn(
            &'a mut WatchingReader<'c>,
        )
            -> futures::future::BoxFuture<'a, Result<Vec<Op>, RepositoryError>>,
    {
        let mut conn = self.write_connection().await?;
        for _ in 0..MAX_WRITE_ATTEMPTS {
            let ops = {
                let mut reader = WatchingReader { conn: &mut conn };
                plan(&mut reader).await?
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
                .query_async(&mut conn)
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

    /// Every record under `prefixes`: one `SCAN MATCH <prefix>*` per prefix,
    /// each step's keys fetched with one `MGET`.
    async fn scan(&self, prefixes: &[String]) -> Result<TrustRecordList, RepositoryError> {
        let mut conn = self.connection.clone();
        let mut entries = Vec::new();
        let mut unreadable = Vec::new();

        for prefix in prefixes {
            let pattern = format!("{}*", glob_escape(prefix));
            // SCAN is O(1) per call and iterates incrementally, unlike KEYS.
            let mut cursor: u64 = 0;
            loop {
                let (next_cursor, keys): (u64, Vec<String>) = redis::cmd("SCAN")
                    .arg(cursor)
                    .arg("MATCH")
                    .arg(&pattern)
                    .arg("COUNT")
                    .arg(SCAN_PAGE)
                    .query_async(&mut conn)
                    .await
                    .map_err(|e| RepositoryError::QueryFailed(format!("Redis SCAN failed: {e}")))?;

                if !keys.is_empty() {
                    let values: Vec<Option<String>> = redis::cmd("MGET")
                        .arg(&keys)
                        .query_async(&mut conn)
                        .await
                        .map_err(|e| {
                            RepositoryError::QueryFailed(format!("Redis MGET failed: {e}"))
                        })?;
                    for (key, data) in keys.into_iter().zip(values) {
                        // Deleted between the SCAN and the MGET.
                        let Some(data) = data else { continue };
                        match Self::deserialize_record(&data) {
                            Ok(record) => entries.push((key, record)),
                            Err(e) => skip_unreadable(key, &e, &mut unreadable),
                        }
                    }
                }

                if next_cursor == 0 {
                    break;
                }
                cursor = next_cursor;
            }
        }

        // SCAN may return a key more than once; the listing keeps one copy.
        unreadable.sort_by(|a: &UnreadableRecord, b| a.storage_key().cmp(b.storage_key()));
        unreadable.dedup();
        Ok(TrustRecordList::with_unreadable(
            dedupe_listing(entries),
            unreadable,
        ))
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
        let list = self.list_matching(&TrustRecordFilter::all()).await?;
        info!("Listed {} records", list.records().len());
        Ok(list)
    }

    /// Scans only the keys under the filter's leading identifiers
    /// ([`TrustRecordFilter::storage_key_prefixes`]).
    async fn list_matching(
        &self,
        filter: &TrustRecordFilter,
    ) -> Result<TrustRecordList, RepositoryError> {
        Ok(self
            .scan(&filter.storage_key_prefixes())
            .await?
            .filtered(filter))
    }

    /// The Redis record of accepted document identifiers
    /// ([`RedisMessageIdStore`]), over this storage's connection.
    async fn message_id_store(
        &self,
        config: &MessageIdStoreConfig,
    ) -> Result<Option<Arc<dyn MessageIdStore>>, RepositoryError> {
        Ok(Some(Arc::new(RedisMessageIdStore::new(
            self.connection.clone(),
            *config,
        ))))
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
                            let mut conn = storage.connection.clone();
                            let result: redis::RedisResult<()> =
                                conn.set(&storage_key, "{not json").await;
                            result.expect("Redis SET");
                        })
                    },
                    move |storage_key: String| {
                        let storage = remover.clone();
                        Box::pin(async move {
                            let mut conn = storage.connection.clone();
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
        let mut conn = storage.connection.clone();
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
        let mut conn = storage.connection.clone();
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
            let mut conn = storage.connection.clone();
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
            let mut conn = storage.connection.clone();
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

    #[test]
    fn glob_characters_in_a_prefix_match_only_themselves() {
        assert_eq!(glob_escape("TR#a*b?[c]\\d#"), "TR#a\\*b\\?\\[c\\]\\\\d#");
        assert_eq!(glob_escape("TR#did:example:a#"), "TR#did:example:a#");
    }

    /// #212: a dropped connection is re-established. With the single
    /// `MultiplexedConnection` the registry used before, every command after
    /// the drop failed until the process was restarted.
    #[tokio::test]
    #[serial(redis)]
    async fn reads_recover_after_the_connection_is_dropped() {
        let Some(storage) = get_test_storage().await else {
            return;
        };
        let record = create_test_record(
            "did:example:reconnect",
            "did:example:authority-reconnect",
            "issue",
            "vc",
            true,
            true,
            "authorization",
        );
        cleanup_test_data(&storage, std::slice::from_ref(&record)).await;
        storage.create(record.clone()).await.unwrap();

        let mut conn = storage.connection.clone();
        let id: i64 = redis::cmd("CLIENT")
            .arg("ID")
            .query_async(&mut conn)
            .await
            .unwrap();
        let mut killer = storage.write_connection().await.unwrap();
        let killed: i64 = redis::cmd("CLIENT")
            .arg("KILL")
            .arg("ID")
            .arg(id)
            .query_async(&mut killer)
            .await
            .unwrap();
        assert_eq!(killed, 1);

        // The command that finds the connection gone may fail; the ones after
        // it run on a new connection.
        let mut recovered = false;
        for _ in 0..50 {
            if let Ok(Some(found)) = storage.find_by_query(query_for(&record)).await {
                assert_eq!(found, record);
                recovered = true;
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }
        assert!(recovered, "reads work again after the connection dropped");

        cleanup_test_data(&storage, &[record]).await;
    }

    /// Reads share the connection concurrently, while a listing runs and
    /// while a write holds a connection of its own.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    #[serial(redis)]
    async fn reads_run_concurrently_with_a_listing_and_writes() {
        let Some(storage) = get_test_storage().await else {
            return;
        };
        let record = create_test_record(
            "did:example:concurrent",
            "did:example:authority-concurrent",
            "issue",
            "vc",
            true,
            true,
            "authorization",
        );
        cleanup_test_data(&storage, std::slice::from_ref(&record)).await;
        storage.create(record.clone()).await.unwrap();

        let mut tasks = Vec::new();
        for index in 0..32 {
            let storage = storage.clone();
            let record = record.clone();
            tasks.push(tokio::spawn(async move {
                match index % 8 {
                    0 => {
                        storage.list().await.unwrap();
                    }
                    1 => {
                        storage.update(record.clone()).await.unwrap();
                    }
                    _ => {
                        assert_eq!(
                            storage.find_by_query(query_for(&record)).await.unwrap(),
                            Some(record)
                        );
                    }
                }
            }));
        }
        for task in tasks {
            task.await.unwrap();
        }

        cleanup_test_data(&storage, &[record]).await;
    }
}
