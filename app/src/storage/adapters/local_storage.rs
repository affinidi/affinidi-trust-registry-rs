use std::collections::HashMap;
use std::sync::{Arc, RwLock};

use crate::domain::*;
use crate::storage::repository::*;


#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct RecordKey {
    entity_id: EntityId,
    authority_id: AuthorityId,
    assertion_id: AssertionId,
}

impl RecordKey {
    fn new(entity_id: EntityId, authority_id: AuthorityId, assertion_id: AssertionId) -> Self {
        Self {
            entity_id,
            authority_id,
            assertion_id,
        }
    }

    fn from_record(record: &TrustRecord) -> Self {
        Self {
            entity_id: record.entity_id().clone(),
            authority_id: record.authority_id().clone(),
            assertion_id: record.assertion_id().clone(),
        }
    }
}


#[derive(Clone)]
pub struct LocalStorage {
    records: Arc<RwLock<HashMap<RecordKey, TrustRecord>>>,
}

impl LocalStorage {
    
    pub fn new() -> Self {
        Self {
            records: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    
    pub fn with_records(records: Vec<TrustRecord>) -> Self {
        let storage = Self::new();
        for record in records {
            let key = RecordKey::from_record(&record);
            storage
                .records
                .write()
                .unwrap()
                .insert(key, record);
        }
        storage
    }

    
    pub fn clear(&self) {
        self.records.write().unwrap().clear();
    }

    
    fn matches_query(record: &TrustRecord, query: &TrustRecordQuery) -> bool {
        if let Some(ref entity_id) = query.entity_id {
            if record.entity_id() != entity_id {
                return false;
            }
        }

        if let Some(ref authority_id) = query.authority_id {
            if record.authority_id() != authority_id {
                return false;
            }
        }

        if let Some(ref assertion_id) = query.assertion_id {
            if record.assertion_id() != assertion_id {
                return false;
            }
        }
        true
    }
}

impl Default for LocalStorage {
    fn default() -> Self {
        Self::new()
    }
}

impl TrustRecordRepository for LocalStorage {
    async fn save(&self, record: TrustRecord) -> Result<(), RepositoryError> {
        let key = RecordKey::from_record(&record);
        let mut records = self.records.write().unwrap();
        
        if records.contains_key(&key) {
            return Err(RepositoryError::DuplicateKey);
        }
        
        records.insert(key, record);
        Ok(())
    }

    async fn find_by_ids(
        &self,
        entity_id: &EntityId,
        authority_id: &AuthorityId,
        assertion_id: &AssertionId,
    ) -> Result<Option<TrustRecord>, RepositoryError> {
        let key = RecordKey::new(
            entity_id.clone(),
            authority_id.clone(),
            assertion_id.clone(),
        );
        let records = self.records.read().unwrap();
        Ok(records.get(&key).cloned())
    }

    async fn find_by_query(
        &self,
        query: TrustRecordQuery,
    ) -> Result<Vec<TrustRecord>, RepositoryError> {
        let records = self.records.read().unwrap();
        let results: Vec<TrustRecord> = records
            .values()
            .filter(|record| Self::matches_query(record, &query))
            .cloned()
            .collect();
        Ok(results)
    }

    async fn find_by_entity(
        &self,
        entity_id: &EntityId,
    ) -> Result<Vec<TrustRecord>, RepositoryError> {
        let records = self.records.read().unwrap();
        let results: Vec<TrustRecord> = records
            .values()
            .filter(|record| record.entity_id() == entity_id)
            .cloned()
            .collect();
        Ok(results)
    }

    async fn find_by_authority(
        &self,
        authority_id: &AuthorityId,
    ) -> Result<Vec<TrustRecord>, RepositoryError> {
        let records = self.records.read().unwrap();
        let results: Vec<TrustRecord> = records
            .values()
            .filter(|record| record.authority_id() == authority_id)
            .cloned()
            .collect();
        Ok(results)
    }

    async fn delete(
        &self,
        entity_id: &EntityId,
        authority_id: &AuthorityId,
        assertion_id: &AssertionId,
    ) -> Result<bool, RepositoryError> {
        let key = RecordKey::new(
            entity_id.clone(),
            authority_id.clone(),
            assertion_id.clone(),
        );
        let mut records = self.records.write().unwrap();
        Ok(records.remove(&key).is_some())
    }

    async fn count(&self) -> Result<usize, RepositoryError> {
        let records = self.records.read().unwrap();
        Ok(records.len())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_record(
        entity: &str,
        authority: &str,
        assertion: &str,
        recognized: bool,
        verified: bool,
    ) -> TrustRecord {
        TrustRecordBuilder::new()
            .entity_id(EntityId::new(entity))
            .authority_id(AuthorityId::new(authority))
            .assertion_id(AssertionId::new(assertion))
            .recognized(recognized)
            .time_requested(Timestamp::now())
            .time_evaluated(Timestamp::now())
            .message("Test message")
            .assertion_verified(verified)
            .build()
            .unwrap()
    }

    #[tokio::test]
    async fn test_save_and_find() {
        let storage = LocalStorage::new();
        let record = create_test_record("e1", "a1", "as1", true, true);

        storage.save(record.clone()).await.unwrap();

        let found = storage
            .find_by_ids(
                &EntityId::new("e1"),
                &AuthorityId::new("a1"),
                &AssertionId::new("as1"),
            )
            .await
            .unwrap();

        assert!(found.is_some());
        assert_eq!(found.unwrap().entity_id().as_str(), "e1");
    }

    #[tokio::test]
    async fn test_duplicate_key() {
        let storage = LocalStorage::new();
        let record1 = create_test_record("e1", "a1", "as1", true, true);
        let record2 = create_test_record("e1", "a1", "as1", false, false);

        storage.save(record1).await.unwrap();
        let result = storage.save(record2).await;

        assert!(matches!(result, Err(RepositoryError::DuplicateKey)));
    }

    #[tokio::test]
    async fn test_find_by_entity() {
        let storage = LocalStorage::new();
        storage.save(create_test_record("e1", "a1", "as1", true, true)).await.unwrap();
        storage.save(create_test_record("e1", "a2", "as2", true, true)).await.unwrap();
        storage.save(create_test_record("e2", "a1", "as3", true, true)).await.unwrap();

        let results = storage.find_by_entity(&EntityId::new("e1")).await.unwrap();

        assert_eq!(results.len(), 2);
    }

    #[tokio::test]
    async fn test_find_by_authority() {
        let storage = LocalStorage::new();
        storage.save(create_test_record("e1", "a1", "as1", true, true)).await.unwrap();
        storage.save(create_test_record("e2", "a1", "as2", true, true)).await.unwrap();
        storage.save(create_test_record("e3", "a2", "as3", true, true)).await.unwrap();

        let results = storage.find_by_authority(&AuthorityId::new("a1")).await.unwrap();

        assert_eq!(results.len(), 2);
    }

    #[tokio::test]
    async fn test_delete() {
        let storage = LocalStorage::new();
        let record = create_test_record("e1", "a1", "as1", true, true);
        storage.save(record).await.unwrap();

        let deleted = storage
            .delete(
                &EntityId::new("e1"),
                &AuthorityId::new("a1"),
                &AssertionId::new("as1"),
            )
            .await
            .unwrap();

        assert!(deleted);

        let found = storage
            .find_by_ids(
                &EntityId::new("e1"),
                &AuthorityId::new("a1"),
                &AssertionId::new("as1"),
            )
            .await
            .unwrap();

        assert!(found.is_none());
    }

    #[tokio::test]
    async fn test_count() {
        let storage = LocalStorage::new();
        storage.save(create_test_record("e1", "a1", "as1", true, true)).await.unwrap();
        storage.save(create_test_record("e2", "a2", "as2", true, true)).await.unwrap();

        let count = storage.count().await.unwrap();

        assert_eq!(count, 2);
    }

    #[tokio::test]
    async fn test_clear() {
        let storage = LocalStorage::new();
        storage.save(create_test_record("e1", "a1", "as1", true, true)).await.unwrap();
        storage.save(create_test_record("e2", "a2", "as2", true, true)).await.unwrap();

        storage.clear();

        let count = storage.count().await.unwrap();
        assert_eq!(count, 0);
    }
}