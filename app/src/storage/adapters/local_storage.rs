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

    pub async fn save(&self, record: TrustRecord) -> Result<(), Box<dyn std::error::Error>> {
        let key = RecordKey::from_record(&record);
        let mut records = self.records.write().unwrap();
        if records.contains_key(&key) {
            return Err(anyhow::anyhow!("Record with the same keys already exists").into());
        }
        records.insert(key, record);
        Ok(())
    }

    pub fn with_records(records: Vec<TrustRecord>) -> Self {
        let storage = Self::new();
        for record in records {
            let key = RecordKey::from_record(&record);
            storage.records.write().unwrap().insert(key, record);
        }
        storage
    }

    pub fn clear(&self) {
        self.records.write().unwrap().clear();
    }

    fn matches_query(record: &TrustRecord, query: &TrustRecordQuery) -> bool {
        record.entity_id() == &query.entity_id
            && record.authority_id() == &query.authority_id
            && record.assertion_id() == &query.assertion_id
    }
}

impl Default for LocalStorage {
    fn default() -> Self {
        Self::new()
    }
}

impl TrustRecordRepository for LocalStorage {
    async fn find_by_query(
        &self,
        query: TrustRecordQuery,
    ) -> Result<Option<TrustRecord>, RepositoryError> {
        let records = self.records.read().unwrap();
        let result = records
            .values()
            .cloned()
            .find(|record| Self::matches_query(record, &query));
        Ok(result)
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
            .assertion_verified(verified)
            .build()
            .unwrap()
    }

    #[tokio::test]
    async fn test_find_by_query_filters_records() {
        let storage = LocalStorage::with_records(vec![
            create_test_record("entity-1", "authority-1", "assertion-1", true, true),
            create_test_record("entity-2", "authority-2", "assertion-2", false, false),
        ]);

        let query = TrustRecordQuery::new(
            EntityId::new("entity-1"),
            AuthorityId::new("authority-1"),
            AssertionId::new("assertion-1"),
        );

        let result = storage.find_by_query(query).await.unwrap();

        assert!(result.is_some());
        assert_eq!(result.unwrap().assertion_id().as_str(), "assertion-1");
    }
}
