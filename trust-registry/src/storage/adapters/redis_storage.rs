use redis::{AsyncCommands, Client, aio::MultiplexedConnection};
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, error, info};

use crate::domain::*;
use crate::storage::repository::*;

/// Redis storage adapter for Trust Registry
/// Keys are formatted as: entity_id|authority_id|action|resource
/// Values are JSON-serialized TrustRecord objects
#[derive(Clone)]
pub struct RedisStorage {
    connection: Arc<RwLock<MultiplexedConnection>>,
}

impl RedisStorage {
    pub async fn new(redis_url: &str) -> Result<Self, Box<dyn std::error::Error>> {
        info!("Connecting to Redis at {}", redis_url);
        let client = Client::open(redis_url)?;
        let connection = client.get_multiplexed_async_connection().await?;

        Ok(Self {
            connection: Arc::new(RwLock::new(connection)),
        })
    }

    fn generate_key(
        entity_id: &EntityId,
        authority_id: &AuthorityId,
        action: &Action,
        resource: &Resource,
    ) -> String {
        format!(
            "{}|{}|{}|{}",
            entity_id.as_str(),
            authority_id.as_str(),
            action.as_str(),
            resource.as_str()
        )
    }

    fn key_from_record(record: &TrustRecord) -> String {
        Self::generate_key(
            record.entity_id(),
            record.authority_id(),
            record.action(),
            record.resource(),
        )
    }

    fn key_from_query(query: &TrustRecordQuery) -> String {
        Self::generate_key(
            &query.entity_id,
            &query.authority_id,
            &query.action,
            &query.resource,
        )
    }

    fn serialize_record(record: &TrustRecord) -> Result<String, RepositoryError> {
        serde_json::to_string(record).map_err(|e| {
            RepositoryError::SerializationFailed(format!("Failed to serialize record: {}", e))
        })
    }

    fn deserialize_record(data: &str) -> Result<TrustRecord, RepositoryError> {
        serde_json::from_str(data).map_err(|e| {
            RepositoryError::SerializationFailed(format!("Failed to deserialize record: {}", e))
        })
    }
}

#[async_trait::async_trait]
impl TrustRecordRepository for RedisStorage {
    async fn find_by_query(
        &self,
        query: TrustRecordQuery,
    ) -> Result<Option<TrustRecord>, RepositoryError> {
        let key = Self::key_from_query(&query);
        debug!("Finding record by key: {}", key);

        let mut conn = self.connection.write().await;
        let result: Option<String> = conn
            .get(&key)
            .await
            .map_err(|e| RepositoryError::QueryFailed(format!("Redis GET failed: {}", e)))?;

        match result {
            Some(data) => {
                let record = Self::deserialize_record(&data)?;
                Ok(Some(record))
            }
            None => Ok(None),
        }
    }
}

#[async_trait::async_trait]
impl TrustRecordAdminRepository for RedisStorage {
    async fn create(&self, record: TrustRecord) -> Result<(), RepositoryError> {
        let key = Self::key_from_record(&record);
        debug!("Creating record with key: {}", key);

        let mut conn = self.connection.write().await;

        let exists: bool = conn
            .exists(&key)
            .await
            .map_err(|e| RepositoryError::QueryFailed(format!("Redis EXISTS failed: {}", e)))?;

        if exists {
            return Err(RepositoryError::RecordAlreadyExists(format!(
                "Record already exists: {}|{}|{}|{}",
                record.entity_id(),
                record.authority_id(),
                record.action(),
                record.resource()
            )));
        }

        let value = Self::serialize_record(&record)?;

        let _: () = conn
            .set(&key, value)
            .await
            .map_err(|e| RepositoryError::QueryFailed(format!("Redis SET failed: {}", e)))?;

        info!("Record created successfully: {}", key);
        Ok(())
    }

    async fn update(&self, record: TrustRecord) -> Result<(), RepositoryError> {
        let key = Self::key_from_record(&record);
        debug!("Updating record with key: {}", key);

        let mut conn = self.connection.write().await;

        let exists: bool = conn
            .exists(&key)
            .await
            .map_err(|e| RepositoryError::QueryFailed(format!("Redis EXISTS failed: {}", e)))?;

        if !exists {
            return Err(RepositoryError::RecordNotFound(format!(
                "Record not found: {}|{}|{}|{}",
                record.entity_id(),
                record.authority_id(),
                record.action(),
                record.resource()
            )));
        }

        let value = Self::serialize_record(&record)?;

        let _: () = conn
            .set(&key, value)
            .await
            .map_err(|e| RepositoryError::QueryFailed(format!("Redis SET failed: {}", e)))?;

        info!("Record updated successfully: {}", key);
        Ok(())
    }

    async fn delete(&self, query: TrustRecordQuery) -> Result<(), RepositoryError> {
        let key = Self::key_from_query(&query);
        debug!("Deleting record with key: {}", key);

        let mut conn = self.connection.write().await;

        let deleted: i32 = conn
            .del(&key)
            .await
            .map_err(|e| RepositoryError::QueryFailed(format!("Redis DEL failed: {}", e)))?;

        if deleted == 0 {
            return Err(RepositoryError::RecordNotFound(format!(
                "Record not found: {}|{}|{}|{}",
                query.entity_id, query.authority_id, query.action, query.resource
            )));
        }

        info!("Record deleted successfully: {}", key);
        Ok(())
    }

    async fn list(&self) -> Result<TrustRecordList, RepositoryError> {
        debug!("Listing all records");

        let mut conn = self.connection.write().await;

        let keys: Vec<String> = conn
            .keys("*|*|*|*")
            .await
            .map_err(|e| RepositoryError::QueryFailed(format!("Redis KEYS failed: {}", e)))?;

        let mut records = Vec::new();

        for key in keys {
            let data: Option<String> = conn
                .get(&key)
                .await
                .map_err(|e| RepositoryError::QueryFailed(format!("Redis GET failed: {}", e)))?;

            if let Some(data) = data {
                match Self::deserialize_record(&data) {
                    Ok(record) => records.push(record),
                    Err(e) => {
                        error!("Failed to deserialize record for key {}: {}", key, e);
                    }
                }
            }
        }

        info!("Listed {} records", records.len());
        Ok(TrustRecordList::new(records))
    }

    async fn read(&self, query: TrustRecordQuery) -> Result<TrustRecord, RepositoryError> {
        let key = Self::key_from_query(&query);
        debug!("Reading record with key: {}", key);

        let mut conn = self.connection.write().await;

        let data: Option<String> = conn
            .get(&key)
            .await
            .map_err(|e| RepositoryError::QueryFailed(format!("Redis GET failed: {}", e)))?;

        match data {
            Some(data) => {
                let record = Self::deserialize_record(&data)?;
                Ok(record)
            }
            None => Err(RepositoryError::RecordNotFound(format!(
                "Record not found: {}|{}|{}|{}",
                query.entity_id, query.authority_id, query.action, query.resource
            ))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
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

    async fn get_test_storage() -> Option<RedisStorage> {
        match RedisStorage::new("redis://127.0.0.1:6379").await {
            Ok(storage) => Some(storage),
            Err(_) => {
                println!("Redis not available, skipping test");
                None
            }
        }
    }

    async fn cleanup_test_data(storage: &RedisStorage) {
        let mut conn = storage.connection.write().await;
        let _: Result<(), _> = redis::cmd("FLUSHDB").query_async(&mut *conn).await;
    }

    #[tokio::test]
    async fn test_create_and_read_record() {
        let Some(storage) = get_test_storage().await else {
            return;
        };
        cleanup_test_data(&storage).await;

        let record = create_test_record(
            "did:example:entity1",
            "did:example:authority1",
            "issue",
            "VerifiableCredential",
            true,
            true,
            "assertion",
        );

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

        cleanup_test_data(&storage).await;
    }

    #[tokio::test]
    async fn test_create_duplicate_fails() {
        let Some(storage) = get_test_storage().await else {
            return;
        };
        cleanup_test_data(&storage).await;

        let record = create_test_record(
            "did:example:entity1",
            "did:example:authority1",
            "issue",
            "VerifiableCredential",
            true,
            true,
            "assertion",
        );

        storage.create(record.clone()).await.unwrap();
        let result = storage.create(record).await;
        assert!(result.is_err());
        assert!(matches!(
            result,
            Err(RepositoryError::RecordAlreadyExists(_))
        ));

        cleanup_test_data(&storage).await;
    }

    #[tokio::test]
    async fn test_update_record() {
        let Some(storage) = get_test_storage().await else {
            return;
        };
        cleanup_test_data(&storage).await;

        let mut record = create_test_record(
            "did:example:entity1",
            "did:example:authority1",
            "issue",
            "VerifiableCredential",
            true,
            true,
            "assertion",
        );

        storage.create(record.clone()).await.unwrap();

        record = create_test_record(
            "did:example:entity1",
            "did:example:authority1",
            "issue",
            "VerifiableCredential",
            false,
            false,
            "assertion",
        );

        storage.update(record).await.unwrap();

        let query = TrustRecordQuery::new(
            EntityId::new("did:example:entity1"),
            AuthorityId::new("did:example:authority1"),
            Action::new("issue"),
            Resource::new("VerifiableCredential"),
        );

        let retrieved = storage.read(query).await.unwrap();
        assert!(!retrieved.is_authorized());
        assert!(!retrieved.is_recognized());

        cleanup_test_data(&storage).await;
    }

    #[tokio::test]
    async fn test_delete_record() {
        let Some(storage) = get_test_storage().await else {
            return;
        };
        cleanup_test_data(&storage).await;

        let record = create_test_record(
            "did:example:entity1",
            "did:example:authority1",
            "issue",
            "VerifiableCredential",
            true,
            true,
            "assertion",
        );

        storage.create(record).await.unwrap();

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

        cleanup_test_data(&storage).await;
    }

    #[tokio::test]
    async fn test_list_records() {
        let Some(storage) = get_test_storage().await else {
            return;
        };
        cleanup_test_data(&storage).await;

        let record1 = create_test_record(
            "did:example:entity1",
            "did:example:authority1",
            "issue",
            "VerifiableCredential",
            true,
            true,
            "assertion",
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

        storage.create(record1).await.unwrap();
        storage.create(record2).await.unwrap();

        let list = storage.list().await.unwrap();
        assert_eq!(list.records().len(), 2);

        cleanup_test_data(&storage).await;
    }

    #[tokio::test]
    async fn test_find_by_query() {
        let Some(storage) = get_test_storage().await else {
            return;
        };
        cleanup_test_data(&storage).await;

        let record = create_test_record(
            "did:example:entity1",
            "did:example:authority1",
            "issue",
            "VerifiableCredential",
            true,
            true,
            "assertion",
        );

        storage.create(record).await.unwrap();

        let query = TrustRecordQuery::new(
            EntityId::new("did:example:entity1"),
            AuthorityId::new("did:example:authority1"),
            Action::new("issue"),
            Resource::new("VerifiableCredential"),
        );

        let result = storage.find_by_query(query).await.unwrap();
        assert!(result.is_some());
        assert_eq!(result.unwrap().entity_id().as_str(), "did:example:entity1");

        cleanup_test_data(&storage).await;
    }
}
