use crate::domain::*;
use crate::storage::repository::*;
use anyhow::anyhow;
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as base64;
use serde_json::Value;
use std::{
    collections::HashMap,
    path::{Path, PathBuf},
    sync::{Arc, RwLock},
    time::{Duration, SystemTime},
};

use serde::{Deserialize, Serialize};
use tokio::time::sleep;
use tracing::{error, info};

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
pub struct FileStorage {
    file_path: PathBuf,
    update_interval: Duration,
    records: Arc<RwLock<HashMap<RecordKey, TrustRecord>>>,
    last_modified: Arc<RwLock<Option<SystemTime>>>,
}

impl FileStorage {
    pub async fn try_new<P: Into<PathBuf>>(
        file_path: P,
        update_interval_sec: u64,
    ) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let file_path = file_path.into();
        let update_interval = Duration::from_secs(update_interval_sec);

        let records = Arc::new(RwLock::new(HashMap::new()));
        let last_modified = Arc::new(RwLock::new(None));

        let (initial_records, modified) = Self::load_if_modified(&file_path, None)
            .await?
            .ok_or_else(|| {
                anyhow!("unable to load trust records from {}", file_path.display())
                    .into_boxed_dyn_error()
            })?;

        {
            let mut guard = records.write().unwrap();
            *guard = initial_records;
        }
        {
            let mut guard = last_modified.write().unwrap();
            *guard = Some(modified);
        }

        let storage = Self {
            file_path: file_path.clone(),
            update_interval,
            records: Arc::clone(&records),
            last_modified: Arc::clone(&last_modified),
        };

        storage.spawn_sync_task();

        Ok(storage)
    }

    fn spawn_sync_task(&self) {
        let file_path = self.file_path.clone();
        let update_interval = self.update_interval;
        let records = Arc::clone(&self.records);
        let last_modified = Arc::clone(&self.last_modified);

        tokio::spawn(async move {
            loop {
                sleep(update_interval).await;

                info!(path = %file_path.display(), "Syncing trust records from file");

                let previous = { last_modified.read().unwrap().clone() };

                match Self::load_if_modified(&file_path, previous).await {
                    Ok(Some((new_records, modified))) => {
                        {
                            let mut guard = records.write().unwrap();
                            *guard = new_records;
                        }
                        {
                            let mut guard = last_modified.write().unwrap();
                            *guard = Some(modified);
                        }
                    }
                    Ok(None) => {}
                    Err(err) => {
                        error!(
                            error = %err,
                            path = %file_path.display(),
                            "Failed to sync trust records from file"
                        );
                    }
                }
            }
        });
    }

    async fn load_if_modified(
        path: &Path,
        last_seen: Option<SystemTime>,
    ) -> Result<
        Option<(HashMap<RecordKey, TrustRecord>, SystemTime)>,
        Box<dyn std::error::Error + Send + Sync>,
    > {
        let metadata = tokio::fs::metadata(path).await?;
        let modified = metadata.modified()?;

        if let Some(previous) = last_seen {
            if modified <= previous {
                info!(
                    path = %path.display(),
                    "No changes detected in trust records file"
                );
                return Ok(None);
            }
        }

        info!(
            path = %path.display(),
            "Changes detected in trust records file, reloading"
        );
        let contents = tokio::fs::read_to_string(path).await?.trim().to_string();

        let records = Self::parse_csv(&contents)?;

        Ok(Some((records, modified)))
    }

    fn parse_csv(
        contents: &str,
    ) -> Result<HashMap<RecordKey, TrustRecord>, Box<dyn std::error::Error + Send + Sync>> {
        let mut reader = csv::ReaderBuilder::new()
            .has_headers(true)
            .trim(csv::Trim::All)
            .from_reader(contents.as_bytes());

        let mut records = HashMap::new();

        for result in reader.deserialize::<TrustRecordCsvRow>() {
            let row = result?;
            let record = row.into_record()?;
            let key = RecordKey::from_record(&record);
            records.insert(key, record);
        }

        Ok(records)
    }

    fn matches_query(record: &TrustRecord, query: &TrustRecordQuery) -> bool {
        record.entity_id() == &query.entity_id
            && record.authority_id() == &query.authority_id
            && record.action() == &query.action
            && record.resource() == &query.resource
    }

    async fn write_to_file(&self) -> Result<(), RepositoryError> {
        let records_clone = {
            let records = self.records.read().unwrap();
            records.values().cloned().collect::<Vec<_>>()
        };

        let mut csv_records = Vec::new();
        for record in records_clone.iter() {
            csv_records.push(TrustRecordCsvRow::from_record(record));
        }

        let mut wtr = csv::Writer::from_writer(vec![]);
        for row in csv_records {
            wtr.serialize(&row)
                .map_err(|e| RepositoryError::SerializationFailed(e.to_string()))?;
        }

        let csv_data = wtr
            .into_inner()
            .map_err(|e| RepositoryError::SerializationFailed(e.to_string()))?;

        tokio::fs::write(&self.file_path, csv_data)
            .await
            .map_err(|e| {
                RepositoryError::QueryFailed(format!("Failed to write CSV file: {}", e))
            })?;

        // Update last_modified to prevent reload
        let metadata = tokio::fs::metadata(&self.file_path).await.map_err(|e| {
            RepositoryError::QueryFailed(format!("Failed to get file metadata: {}", e))
        })?;
        let modified = metadata.modified().map_err(|e| {
            RepositoryError::QueryFailed(format!("Failed to get modified time: {}", e))
        })?;

        let mut guard = self.last_modified.write().unwrap();
        *guard = Some(modified);

        Ok(())
    }
}

#[async_trait::async_trait]
impl TrustRecordRepository for FileStorage {
    async fn find_by_query(
        &self,
        query: TrustRecordQuery,
    ) -> Result<Option<TrustRecord>, RepositoryError> {
        let records = Arc::clone(&self.records);

        let guard = records.read().unwrap();
        let result = guard
            .values()
            .cloned()
            .find(|record| FileStorage::matches_query(record, &query));

        Ok(result)
    }
}

#[async_trait::async_trait]
impl TrustRecordAdminRepository for FileStorage {
    async fn create(&self, record: TrustRecord) -> Result<(), RepositoryError> {
        let key = RecordKey::from_record(&record);
        {
            let mut records = self.records.write().unwrap();
            if records.contains_key(&key) {
                return Err(RepositoryError::RecordAlreadyExists(format!(
                    "Record already exists: {}|{}|{}|{}",
                    record.entity_id(),
                    record.authority_id(),
                    record.action(),
                    record.resource(),
                )));
            }
            records.insert(key, record);
        }
        self.write_to_file().await
    }

    async fn update(&self, record: TrustRecord) -> Result<(), RepositoryError> {
        let key = RecordKey::from_record(&record);
        {
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
        }
        self.write_to_file().await
    }

    async fn delete(&self, query: TrustRecordQuery) -> Result<(), RepositoryError> {
        let key = RecordKey {
            entity_id: query.entity_id.clone(),
            authority_id: query.authority_id.clone(),
            action: query.action.clone(),
            resource: query.resource.clone(),
        };
        {
            let mut records = self.records.write().unwrap();
            if records.remove(&key).is_none() {
                return Err(RepositoryError::RecordNotFound(format!(
                    "Record not found: {}|{}|{}|{}",
                    query.entity_id, query.authority_id, query.action, query.resource
                )));
            }
        }
        self.write_to_file().await
    }

    async fn list(&self) -> Result<TrustRecordList, RepositoryError> {
        let records = self.records.read().unwrap();
        let records_vec: Vec<TrustRecord> = records.values().cloned().collect();
        Ok(TrustRecordList::new(records_vec))
    }

    async fn read(&self, query: TrustRecordQuery) -> Result<TrustRecord, RepositoryError> {
        let records = self.records.read().unwrap();
        let result = records
            .values()
            .cloned()
            .find(|record| FileStorage::matches_query(record, &query));

        result.ok_or_else(|| {
            RepositoryError::RecordNotFound(format!(
                "Record not found: {}|{}|{}|{}",
                query.entity_id, query.authority_id, query.action, query.resource
            ))
        })
    }
}

#[derive(Debug, Deserialize, Serialize)]
struct TrustRecordCsvRow {
    entity_id: String,
    authority_id: String,
    action: String,
    resource: String,
    recognized: bool,
    authorized: bool,
    context: Option<String>,
}

impl TrustRecordCsvRow {
    fn parse_context(ctx: Option<String>) -> Option<Value> {
        let record_context: Option<Value> = if let Some(c) = ctx {
            base64
                .decode(&c)
                .ok()
                .and_then(|db| String::from_utf8(db).ok())
                .and_then(|s| serde_json::from_str(&s).ok())
        } else {
            None
        };

        record_context
    }

    fn from_record(record: &TrustRecord) -> Self {
        let context = if record.context().as_value().is_object()
            || record.context().as_value().is_array()
        {
            let json_str = serde_json::to_string(record.context().as_value()).unwrap_or_default();
            let encoded = base64.encode(json_str.as_bytes());
            Some(encoded)
        } else {
            None
        };

        Self {
            entity_id: record.entity_id().to_string(),
            authority_id: record.authority_id().to_string(),
            action: record.action().to_string(),
            resource: record.resource().to_string(),
            recognized: record.is_recognized(),
            authorized: record.is_authorized(),
            context,
        }
    }

    fn into_record(self) -> Result<TrustRecord, Box<dyn std::error::Error + Send + Sync>> {
        let ctx = TrustRecordCsvRow::parse_context(self.context);
        let mut builder = TrustRecordBuilder::new()
            .entity_id(EntityId::new(self.entity_id))
            .authority_id(AuthorityId::new(self.authority_id))
            .action(Action::new(self.action))
            .resource(Resource::new(self.resource))
            .recognized(self.recognized)
            .authorized(self.authorized);

        if let Some(c) = ctx {
            builder = builder.context(Context::new(c));
        }

        builder
            .build()
            .map_err(|err| anyhow!("invalid trust record: {err}").into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;
    use tokio::time::{Duration, sleep};

    fn csv_header() -> String {
        String::from("entity_id,authority_id,action,resource,recognized,authorized,context\n")
    }

    fn sample_csv(records: &[(&str, &str, &str, &str)]) -> String {
        let mut csv = String::new();
        for (entity, authority, action, resource) in records {
            csv.push_str(&format!(
                "{entity},{authority},{action},{resource},true,true,e30=\n"
            ));
        }
        csv
    }

    #[tokio::test]
    async fn fails_when_initial_load_fails() {
        let result = FileStorage::try_new("/does/not/exist.csv", 1).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn finds_records_from_initial_load() {
        let mut file = NamedTempFile::new().unwrap();
        write!(file, "{}", csv_header()).unwrap();
        write!(file, "{}", sample_csv(&[("e1", "a1", "ac1", "r1")])).unwrap();

        let storage = FileStorage::try_new(file.path(), 1).await.unwrap();

        let query = TrustRecordQuery::new(
            EntityId::new("e1"),
            AuthorityId::new("a1"),
            Action::new("ac1"),
            Resource::new("r1"),
        );

        let result = storage.find_by_query(query).await.unwrap();
        assert!(result.is_some());
    }

    #[tokio::test]
    async fn reloads_when_file_changes() {
        let mut file = NamedTempFile::new().unwrap();
        write!(file, "{}", csv_header()).unwrap();
        write!(file, "{}", sample_csv(&[("e1", "a1", "ac1", "r1")])).unwrap();
        file.flush().unwrap();

        let storage = FileStorage::try_new(file.path(), 1).await.unwrap();

        write!(
            file.as_file_mut(),
            "{}",
            sample_csv(&[("e2", "a2", "ac2", "r2")])
        )
        .unwrap();
        file.flush().unwrap();

        // Wait for sync task to detect and process changes
        // Using a reasonable buffer for slow CI machines
        sleep(Duration::from_millis(2000)).await;

        let query = TrustRecordQuery::new(
            EntityId::new("e2"),
            AuthorityId::new("a2"),
            Action::new("ac2"),
            Resource::new("r2"),
        );

        let result = storage.find_by_query(query).await.unwrap();
        assert!(result.is_some());
        assert_eq!(result.unwrap().entity_id().as_str(), "e2");
    }
}
