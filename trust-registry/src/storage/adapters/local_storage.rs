use std::collections::HashMap;
use std::collections::hash_map::Entry;
use std::sync::{Arc, RwLock};

use crate::domain::key::TrustRecordKey;
use crate::domain::*;
use crate::storage::repository::*;

#[derive(Clone)]
pub struct LocalStorage {
    records: Arc<RwLock<HashMap<TrustRecordKey, TrustRecord>>>,
}

impl LocalStorage {
    pub fn new() -> Self {
        Self {
            records: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    pub async fn save(&self, record: TrustRecord) -> Result<(), RepositoryError> {
        let key = TrustRecordKey::from_record(&record);
        let mut records = self
            .records
            .write()
            .map_err(|_| RepositoryError::LockPoisoned)?;

        match records.entry(key.clone()) {
            Entry::Occupied(e) => Err(RepositoryError::RecordAlreadyExists(e.key().to_string())),
            Entry::Vacant(_) => {
                records.insert(key, record);
                Ok(())
            }
        }
    }

    pub fn with_records(records: Vec<TrustRecord>) -> Result<Self, RepositoryError> {
        let storage = Self::new();
        for record in records {
            let key = TrustRecordKey::from_record(&record);
            storage
                .records
                .write()
                .map_err(|_| RepositoryError::LockPoisoned)?
                .insert(key, record);
        }
        Ok(storage)
    }

    pub fn clear(&self) -> Result<(), RepositoryError> {
        self.records
            .write()
            .map_err(|_| RepositoryError::LockPoisoned)?
            .clear();
        Ok(())
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
        let records = self
            .records
            .read()
            .map_err(|_| RepositoryError::LockPoisoned)?;
        let result = records
            .values()
            .find(|&record| Self::matches_query(record, &query))
            .cloned();
        Ok(result)
    }
}

#[async_trait::async_trait]
impl TrustRecordAdminRepository for LocalStorage {
    async fn create(&self, record: TrustRecord) -> Result<(), RepositoryError> {
        let key = TrustRecordKey::from_record(&record);
        let mut records = self
            .records
            .write()
            .map_err(|_| RepositoryError::LockPoisoned)?;
        if records.contains_key(&key) {
            return Err(RepositoryError::RecordAlreadyExists(format!(
                "Record already exists: {}#{}#{}#{}",
                record.authority_id(),
                record.action(),
                record.resource(),
                record.entity_id()
            )));
        }
        records.insert(key, record);
        Ok(())
    }

    async fn update(&self, record: TrustRecord) -> Result<(), RepositoryError> {
        let key = TrustRecordKey::from_record(&record);
        let mut records = self
            .records
            .write()
            .map_err(|_| RepositoryError::LockPoisoned)?;
        if !records.contains_key(&key) {
            return Err(RepositoryError::RecordNotFound(format!(
                "Record not found: {}#{}#{}#{}",
                record.authority_id(),
                record.action(),
                record.resource(),
                record.entity_id()
            )));
        }
        records.insert(key, record);
        Ok(())
    }

    async fn delete(&self, query: TrustRecordQuery) -> Result<(), RepositoryError> {
        let key = TrustRecordKey::from_query(&query);
        let mut records = self
            .records
            .write()
            .map_err(|_| RepositoryError::LockPoisoned)?;
        if records.remove(&key).is_none() {
            return Err(RepositoryError::RecordNotFound(format!(
                "Record not found: {}#{}#{}#{}",
                query.authority_id, query.action, query.resource, query.entity_id
            )));
        }
        Ok(())
    }

    async fn list(&self) -> Result<TrustRecordList, RepositoryError> {
        let records = self
            .records
            .read()
            .map_err(|_| RepositoryError::LockPoisoned)?;
        let records_vec: Vec<TrustRecord> = records.values().cloned().collect();
        Ok(TrustRecordList::new(records_vec))
    }

    async fn read(&self, query: TrustRecordQuery) -> Result<TrustRecord, RepositoryError> {
        let records = self
            .records
            .read()
            .map_err(|_| RepositoryError::LockPoisoned)?;
        let result = records
            .values()
            .find(|&record| Self::matches_query(record, &query))
            .cloned();

        result.ok_or_else(|| {
            RepositoryError::RecordNotFound(format!(
                "Record not found: {}#{}#{}#{}",
                query.authority_id, query.action, query.resource, query.entity_id
            ))
        })
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use super::*;

    fn create_test_record(
        entity: &str,
        authority: &str,
        action: &str,
        resource: &str,
        recognized: bool,
        verified: bool,
        record_type: &str,
    ) -> TrustRecord {
        TrustRecordBuilder::new()
            .entity_id(EntityId::new(entity))
            .authority_id(AuthorityId::new(authority))
            .action(Action::new(action))
            .resource(Resource::new(resource))
            .recognized(recognized)
            .authorized(verified)
            .record_type(RecordType::from_str(record_type).unwrap())
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
                "authorization",
            ),
            create_test_record(
                "entity-2",
                "authority-2",
                "action-2",
                "resource-2",
                false,
                false,
                "recognition",
            ),
        ])
        .unwrap();

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
