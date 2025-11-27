use std::collections::HashMap;
use std::sync::{Arc, RwLock};

use crate::domain::*;
use crate::storage::repository::*;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct RecordKey {
    entity_id: EntityId,
    authority_id: AuthorityId,
    action: Action,
    resource: Resource,
}

impl RecordKey {
    fn from_record(record: &TrustRecord) -> Self {
        Self {
            entity_id: record.entity_id().clone(),
            authority_id: record.authority_id().clone(),
            action: record.action().clone(),
            resource: record.resource().clone(),
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
            && record.action() == &query.action
            && record.resource() == &query.resource
    }
}

impl Default for LocalStorage {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait::async_trait]
impl TrustRecordRepository for LocalStorage {
    async fn find_by_query(
        &self,
        query: TrustRecordQuery,
    ) -> Result<Option<TrustRecord>, RepositoryError> {
        let records = self.records.read().unwrap();
        let result = records
            .values().find(|&record| Self::matches_query(record, &query)).cloned();
        Ok(result)
    }
}

#[async_trait::async_trait]
impl TrustRecordAdminRepository for LocalStorage {
    async fn create(&self, record: TrustRecord) -> Result<(), RepositoryError> {
        let key = RecordKey::from_record(&record);
        let mut records = self.records.write().unwrap();
        if records.contains_key(&key) {
            return Err(RepositoryError::RecordAlreadyExists(format!(
                "Record already exists: {}|{}|{}|{}",
                record.entity_id(),
                record.authority_id(),
                record.action(),
                record.resource()
            )));
        }
        records.insert(key, record);
        Ok(())
    }

    async fn update(&self, record: TrustRecord) -> Result<(), RepositoryError> {
        let key = RecordKey::from_record(&record);
        let mut records = self.records.write().unwrap();
        if !records.contains_key(&key) {
            return Err(RepositoryError::RecordNotFound(format!(
                "Record not found: {}|{}|{}|{}",
                record.entity_id(),
                record.authority_id(),
                record.action(),
                record.resource()
            )));
        }
        records.insert(key, record);
        Ok(())
    }

    async fn delete(&self, query: TrustRecordQuery) -> Result<(), RepositoryError> {
        let key = RecordKey {
            entity_id: query.entity_id.clone(),
            authority_id: query.authority_id.clone(),
            action: query.action.clone(),
            resource: query.resource.clone(),
        };
        let mut records = self.records.write().unwrap();
        if records.remove(&key).is_none() {
            return Err(RepositoryError::RecordNotFound(format!(
                "Record not found: {}|{}|{}|{}",
                query.entity_id, query.authority_id, query.action, query.resource
            )));
        }
        Ok(())
    }

    async fn list(&self) -> Result<TrustRecordList, RepositoryError> {
        let records = self.records.read().unwrap();
        let records_vec: Vec<TrustRecord> = records.values().cloned().collect();
        Ok(TrustRecordList::new(records_vec))
    }

    async fn read(&self, query: TrustRecordQuery) -> Result<TrustRecord, RepositoryError> {
        let records = self.records.read().unwrap();
        let result = records
            .values().find(|&record| Self::matches_query(record, &query)).cloned();

        result.ok_or_else(|| {
            RepositoryError::RecordNotFound(format!(
                "Record not found: {}|{}|{}|{}",
                query.entity_id, query.authority_id, query.action, query.resource
            ))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_record(
        entity: &str,
        authority: &str,
        action: &str,
        resource: &str,
        recognized: bool,
        verified: bool,
    ) -> TrustRecord {
        TrustRecordBuilder::new()
            .entity_id(EntityId::new(entity))
            .authority_id(AuthorityId::new(authority))
            .action(Action::new(action))
            .resource(Resource::new(resource))
            .recognized(recognized)
            .authorized(verified)
            .build()
            .unwrap()
    }

    #[tokio::test]
    async fn test_find_by_query_filters_records() {
        let storage = LocalStorage::with_records(vec![
            create_test_record(
                "entity-1",
                "authority-1",
                "action-1",
                "resource-1",
                true,
                true,
            ),
            create_test_record(
                "entity-2",
                "authority-2",
                "action-2",
                "resource-2",
                false,
                false,
            ),
        ]);

        let query = TrustRecordQuery::new(
            EntityId::new("entity-1"),
            AuthorityId::new("authority-1"),
            Action::new("action-1"),
            Resource::new("resource-1"),
        );

        let result = storage.find_by_query(query).await.unwrap();
        assert!(result.is_some());
        let record = result.unwrap();
        assert_eq!(record.action().as_str(), "action-1");
        assert_eq!(record.resource().as_str(), "resource-1");
    }
}
