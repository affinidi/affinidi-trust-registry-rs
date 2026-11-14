//! CSV file storage: the trust records live in one CSV file, held in memory
//! and written back on every mutation.
//!
//! # Write guarantees
//!
//! - **Serialised.** One lock covers each mutation from reading the file to
//!   publishing the result in memory, and the reload task takes the same lock,
//!   so two writes cannot reorder on disk and a reload cannot interleave with
//!   a write.
//! - **Atomic and durable.** The new contents go to a temporary file in the
//!   same directory, which is `fsync`ed and renamed over the target; on Unix
//!   the directory is then `fsync`ed. A crash leaves the old file or the new
//!   one, never a truncated one, and a mutation returns only once its file is
//!   on stable storage (rule R1.6).
//! - **Memory follows the file.** A mutation is applied to a copy of the
//!   records and published in memory only after the file write succeeds, so a
//!   failed write leaves memory unchanged.
//! - **Operator edits are kept.** Before applying a mutation, and every
//!   `update_interval`, the file is re-read and compared by content digest
//!   with what this process last loaded or wrote; a changed file is loaded
//!   first. A file that no longer parses is not overwritten: the mutation
//!   fails until it is fixed, and the reload keeps the current records.
//!
//! The file is still a single-writer store: two registry processes writing the
//! same file are not coordinated. Use Redis, DynamoDB or fjall for that.
//!
//! Rows are written sorted by storage key, always with the header row.

use crate::domain::{key::TrustRecordKey, *};
use crate::storage::repository::*;
use anyhow::anyhow;
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as base64;
use chrono::{DateTime, Utc};
use serde_json::Value;
use std::{
    collections::HashMap,
    io::Write as _,
    path::{Path, PathBuf},
    str::FromStr,
    sync::Arc,
    time::Duration,
};
use tokio_util::sync::{CancellationToken, DropGuard};

use serde::{Deserialize, Serialize};
use tokio::sync::{Mutex, RwLock};
use tokio::time::sleep;
use tracing::{debug, error, info};

type Records = HashMap<TrustRecordKey, TrustRecord>;
type BoxError = Box<dyn std::error::Error + Send + Sync>;

/// The CSV columns, in file order.
const HEADER: [&str; 10] = [
    "entity_id",
    "authority_id",
    "action",
    "resource",
    "recognized",
    "authorized",
    "context",
    "record_type",
    "valid_from",
    "valid_until",
];

#[derive(Clone)]
pub struct FileStorage {
    inner: Arc<Inner>,
    /// Stops the reload task when the last clone is dropped.
    _shutdown: Arc<DropGuard>,
}

struct Inner {
    file_path: PathBuf,
    records: RwLock<Records>,
    /// Held across every mutation and every reload.
    sync: Mutex<FileState>,
}

/// What this process last loaded from, or wrote to, the file.
struct FileState {
    digest: String,
}

/// Whether a file with no content at all is accepted as zero records.
#[derive(Clone, Copy, PartialEq, Eq)]
enum EmptyFile {
    /// At startup: a fresh deployment may start from an empty file.
    Allowed,
    /// Afterwards: every file this process writes has a header, so an empty
    /// one is a truncated or half-written edit, not an intent to delete every
    /// record.
    Refused,
}

impl FileStorage {
    pub async fn try_new<P: Into<PathBuf>>(
        file_path: P,
        update_interval_sec: u64,
    ) -> Result<Self, BoxError> {
        let file_path = file_path.into();
        // A zero interval would make the sync task re-read the file in a
        // tight loop.
        if update_interval_sec == 0 {
            return Err(anyhow!("the CSV update interval must be at least one second").into());
        }
        let contents = tokio::fs::read(&file_path)
            .await
            .map_err(|e| anyhow!("unable to read trust records from {file_path:?}: {e}"))?;
        let records = Self::parse(&contents, EmptyFile::Allowed).map_err(|e| {
            anyhow!(
                "unable to load trust records from {}: {e}",
                file_path.display()
            )
        })?;

        let inner = Arc::new(Inner {
            file_path,
            records: RwLock::new(records),
            sync: Mutex::new(FileState {
                digest: sha256::digest(contents.as_slice()),
            }),
        });
        let shutdown = CancellationToken::new();
        Self::spawn_sync_task(
            Arc::clone(&inner),
            Duration::from_secs(update_interval_sec),
            shutdown.clone(),
        );

        Ok(Self {
            inner,
            _shutdown: Arc::new(shutdown.drop_guard()),
        })
    }

    fn spawn_sync_task(inner: Arc<Inner>, update_interval: Duration, shutdown: CancellationToken) {
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = shutdown.cancelled() => {
                        info!(path = %inner.file_path.display(), "CSV sync task shutting down");
                        break;
                    }
                    _ = sleep(update_interval) => {
                        let mut state = inner.sync.lock().await;
                        if let Err(err) = inner.load_if_changed(&mut state).await {
                            error!(
                                error = %err,
                                path = %inner.file_path.display(),
                                "Failed to sync trust records from file; keeping the current records"
                            );
                        }
                    }
                }
            }
        });
    }

    fn parse(contents: &[u8], empty: EmptyFile) -> Result<Records, BoxError> {
        let contents = std::str::from_utf8(contents)?.trim();
        if contents.is_empty() && empty == EmptyFile::Refused {
            return Err("the file is empty (not even a header row)".into());
        }
        let mut reader = csv::ReaderBuilder::new()
            .has_headers(true)
            .trim(csv::Trim::All)
            .from_reader(contents.as_bytes());

        let mut records = HashMap::new();

        for (index, result) in reader.deserialize::<TrustRecordCsvRow>().enumerate() {
            // Line 1 is the header.
            let line = index + 2;
            let record = result
                .map_err(BoxError::from)
                .and_then(TrustRecordCsvRow::into_record)
                .map_err(|e| format!("row {line}: {e}"))?;
            let key = TrustRecordKey::from_record(&record);
            records.insert(key, record);
        }

        Ok(records)
    }

    fn encode(records: &Records) -> Result<Vec<u8>, RepositoryError> {
        let serialization = |e: csv::Error| RepositoryError::SerializationFailed(e.to_string());
        let mut sorted: Vec<(String, &TrustRecord)> = records
            .iter()
            .map(|(key, record)| (key.sk(), record))
            .collect();
        sorted.sort_by(|a, b| a.0.cmp(&b.0));

        let mut writer = csv::WriterBuilder::new()
            .has_headers(false)
            .from_writer(vec![]);
        writer.write_record(HEADER).map_err(serialization)?;
        for (_, record) in sorted {
            writer
                .serialize(TrustRecordCsvRow::from_record(record)?)
                .map_err(serialization)?;
        }
        writer
            .into_inner()
            .map_err(|e| RepositoryError::SerializationFailed(e.to_string()))
    }

    /// Apply `change` to a copy of the records, write the result to the file,
    /// and publish it in memory only once the file is durable.
    async fn mutate(
        &self,
        change: impl FnOnce(&mut Records) -> Result<(), RepositoryError>,
    ) -> Result<(), RepositoryError> {
        let inner = &self.inner;
        let mut state = inner.sync.lock().await;
        // Pick up an operator's edit first, so this write does not discard it.
        inner.load_if_changed(&mut state).await.map_err(|e| {
            RepositoryError::QueryFailed(format!(
                "could not re-read {} before writing it, so it was not overwritten: {e}",
                inner.file_path.display()
            ))
        })?;

        let mut next = inner.records.read().await.clone();
        change(&mut next)?;
        let contents = Self::encode(&next)?;

        let path = inner.file_path.clone();
        let written = contents.clone();
        tokio::task::spawn_blocking(move || write_atomically(&path, &written))
            .await
            .map_err(|e| RepositoryError::QueryFailed(format!("CSV write task failed: {e}")))?
            .map_err(|e| {
                RepositoryError::QueryFailed(format!(
                    "Failed to write {}: {e}",
                    inner.file_path.display()
                ))
            })?;

        state.digest = sha256::digest(contents.as_slice());
        *inner.records.write().await = next;
        Ok(())
    }
}

impl Inner {
    /// Reload the file if its contents differ from what this process last
    /// loaded or wrote. The caller holds `sync`.
    async fn load_if_changed(&self, state: &mut FileState) -> Result<(), BoxError> {
        let contents = tokio::fs::read(&self.file_path).await?;
        let digest = sha256::digest(contents.as_slice());
        if digest == state.digest {
            debug!(path = %self.file_path.display(), "No changes detected in trust records file");
            return Ok(());
        }
        info!(
            path = %self.file_path.display(),
            "Changes detected in trust records file, reloading"
        );
        let records = FileStorage::parse(&contents, EmptyFile::Refused)?;
        *self.records.write().await = records;
        state.digest = digest;
        Ok(())
    }
}

/// Replace `path` with `contents` so that a reader, or a crash, sees the old
/// file or the new one and nothing in between.
fn write_atomically(path: &Path, contents: &[u8]) -> std::io::Result<()> {
    let dir = match path.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent,
        _ => Path::new("."),
    };
    let file_name = path.file_name().ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("{} is not a file path", path.display()),
        )
    })?;
    let temporary = dir.join(format!(
        ".{}.{}.tmp",
        file_name.to_string_lossy(),
        uuid::Uuid::new_v4()
    ));

    let written = (|| {
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temporary)?;
        // Keep the permissions the operator gave the file.
        if let Ok(metadata) = std::fs::metadata(path) {
            file.set_permissions(metadata.permissions())?;
        }
        file.write_all(contents)?;
        file.sync_all()?;
        drop(file);
        std::fs::rename(&temporary, path)
    })();
    if written.is_err() {
        let _ = std::fs::remove_file(&temporary);
        return written;
    }
    // Make the rename itself durable. If this fails the new contents are
    // already in place but may not survive a power loss, so the write is
    // reported as failed and memory keeps the old records. That is safe: the
    // stored digest is still the old file's, so the next write or reload sees
    // the file as changed and loads it, and memory and file agree again. A
    // caller that retries (say, a redelivered create) then finds the record
    // and gets `RecordAlreadyExists` rather than a duplicate.
    #[cfg(unix)]
    std::fs::File::open(dir)?.sync_all()?;
    Ok(())
}

#[async_trait::async_trait]
impl TrustRecordRepository for FileStorage {
    async fn find_by_query(
        &self,
        query: TrustRecordQuery,
    ) -> Result<Option<TrustRecord>, RepositoryError> {
        let records = self.inner.records.read().await;
        Ok(records.get(&TrustRecordKey::from_query(&query)).cloned())
    }
}

#[async_trait::async_trait]
impl TrustRecordAdminRepository for FileStorage {
    async fn create(&self, record: TrustRecord) -> Result<(), RepositoryError> {
        self.mutate(|records| {
            let key = TrustRecordKey::from_record(&record);
            if records.contains_key(&key) {
                return Err(RepositoryError::already_exists(&key));
            }
            records.insert(key, record);
            Ok(())
        })
        .await
    }

    async fn update(&self, record: TrustRecord) -> Result<(), RepositoryError> {
        self.mutate(|records| {
            let key = TrustRecordKey::from_record(&record);
            if !records.contains_key(&key) {
                return Err(RepositoryError::not_found(&key));
            }
            records.insert(key, record);
            Ok(())
        })
        .await
    }

    async fn delete(&self, query: TrustRecordQuery) -> Result<(), RepositoryError> {
        self.mutate(|records| {
            let key = TrustRecordKey::from_query(&query);
            if records.remove(&key).is_none() {
                return Err(RepositoryError::not_found(&key));
            }
            Ok(())
        })
        .await
    }

    async fn list(&self) -> Result<TrustRecordList, RepositoryError> {
        let records = self.inner.records.read().await;
        Ok(TrustRecordList::new(records.values().cloned().collect()))
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
    /// Base64 of the context's JSON. An empty cell is an empty context.
    context: Option<String>,
    record_type: String,
    /// RFC 3339; an empty cell or a missing column means no lower bound, so
    /// files written before these columns existed still load.
    #[serde(default)]
    valid_from: Option<DateTime<Utc>>,
    /// RFC 3339; empty or missing means no upper bound.
    #[serde(default)]
    valid_until: Option<DateTime<Utc>>,
}

impl TrustRecordCsvRow {
    /// Decode a context cell. A cell that is not base64 of JSON fails the
    /// row: silently treating it as an empty context would change what the
    /// record authorizes.
    fn parse_context(ctx: Option<String>) -> Result<Option<Value>, BoxError> {
        let Some(cell) = ctx else {
            return Ok(None);
        };
        let bytes = base64
            .decode(cell.as_bytes())
            .map_err(|e| format!("context is not valid base64: {e}"))?;
        let value = serde_json::from_slice(&bytes)
            .map_err(|e| format!("context is not valid JSON: {e}"))?;
        Ok(Some(value))
    }

    fn from_record(record: &TrustRecord) -> Result<Self, RepositoryError> {
        let json = serde_json::to_string(record.context().as_value())
            .map_err(|e| RepositoryError::SerializationFailed(e.to_string()))?;

        Ok(Self {
            entity_id: record.entity_id().to_string(),
            authority_id: record.authority_id().to_string(),
            action: record.action().to_string(),
            resource: record.resource().to_string(),
            recognized: record.is_recognized(),
            authorized: record.is_authorized(),
            context: Some(base64.encode(json.as_bytes())),
            record_type: record.record_type().to_string(),
            valid_from: record.valid_from(),
            valid_until: record.valid_until(),
        })
    }

    fn into_record(self) -> Result<TrustRecord, BoxError> {
        let ctx = TrustRecordCsvRow::parse_context(self.context)?;
        let mut builder = TrustRecordBuilder::new()
            .entity_id(EntityId::new(self.entity_id))
            .authority_id(AuthorityId::new(self.authority_id))
            .action(Action::new(self.action))
            .resource(Resource::new(self.resource))
            .recognized(self.recognized)
            .authorized(self.authorized)
            .record_type(RecordType::from_str(&self.record_type)?)
            .valid_from(self.valid_from)
            .valid_until(self.valid_until);

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
        String::from(
            "entity_id,authority_id,action,resource,recognized,authorized,context,record_type\n",
        )
    }

    fn sample_csv(records: &[(&str, &str, &str, &str, &str)]) -> String {
        let mut csv = String::new();
        for (entity, authority, action, resource, record_type) in records {
            csv.push_str(&format!(
                "{entity},{authority},{action},{resource},true,true,e30=,{record_type}\n"
            ));
        }
        csv
    }

    #[tokio::test]
    async fn fails_when_initial_load_fails() {
        let result = FileStorage::try_new("/does/not/exist.csv", 1).await;
        assert!(result.is_err());
    }

    /// The validity columns are optional: an empty cell is no bound, and a
    /// file without the columns at all (every test above) still loads.
    #[tokio::test]
    async fn reads_the_optional_validity_columns() {
        let mut file = NamedTempFile::new().unwrap();
        write!(
            file,
            "entity_id,authority_id,action,resource,recognized,authorized,context,record_type,valid_from,valid_until\n\
             e1,a1,ac1,r1,true,true,e30=,authorization,,2027-01-01T00:00:00Z\n\
             e2,a1,ac1,r1,true,true,e30=,authorization,,\n"
        )
        .unwrap();
        let storage = FileStorage::try_new(file.path(), 1).await.unwrap();
        let find = |e: &str| {
            storage.find_by_query(TrustRecordQuery::new(
                EntityId::new(e),
                AuthorityId::new("a1"),
                Action::new("ac1"),
                Resource::new("r1"),
            ))
        };
        let bounded = find("e1").await.unwrap().unwrap();
        assert_eq!(bounded.valid_from(), None);
        assert_eq!(
            bounded.valid_until().map(|t| t.to_rfc3339()),
            Some("2027-01-01T00:00:00+00:00".to_string())
        );
        let open = find("e2").await.unwrap().unwrap();
        assert_eq!((open.valid_from(), open.valid_until()), (None, None));
    }

    #[tokio::test]
    async fn finds_records_from_initial_load() {
        let mut file = NamedTempFile::new().unwrap();
        write!(file, "{}", csv_header()).unwrap();
        write!(
            file,
            "{}",
            sample_csv(&[("e1", "a1", "ac1", "r1", "authorization")])
        )
        .unwrap();

        let storage = FileStorage::try_new(file.path(), 1).await.unwrap();

        let query = TrustRecordQuery::new(
            EntityId::new("e1"),
            AuthorityId::new("a1"),
            Action::new("ac1"),
            Resource::new("r1"),
        );

        let result = storage.find_by_query(query).await.unwrap();
        assert!(result.is_some());
        let record = result.unwrap();
        assert_eq!(*record.record_type(), RecordType::Authorization);
    }

    #[tokio::test]
    async fn reloads_when_file_changes() {
        let mut file = NamedTempFile::new().unwrap();
        write!(file, "{}", csv_header()).unwrap();
        write!(
            file,
            "{}",
            sample_csv(&[("e1", "a1", "ac1", "r1", "recognition")])
        )
        .unwrap();
        file.flush().unwrap();

        let storage = FileStorage::try_new(file.path(), 1).await.unwrap();
        // Dropping a clone must not stop the reload task.
        drop(storage.clone());

        sleep(Duration::from_secs(1)).await;
        write!(
            file.as_file_mut(),
            "{}",
            sample_csv(&[("e2", "a2", "ac2", "r2", "recognition")])
        )
        .unwrap();
        file.flush().unwrap();

        // Wait for sync task to detect and process changes
        // Using a reasonable buffer for slow CI machines
        sleep(Duration::from_secs(2)).await;

        let query = TrustRecordQuery::new(
            EntityId::new("e2"),
            AuthorityId::new("a2"),
            Action::new("ac2"),
            Resource::new("r2"),
        );

        let result = storage.find_by_query(query).await.unwrap();

        assert!(result.is_some());
        assert_eq!(result.clone().unwrap().entity_id().as_str(), "e2");
        assert_eq!(*result.unwrap().record_type(), RecordType::Recognition);
    }

    fn record(entity: &str) -> TrustRecord {
        TrustRecordBuilder::new()
            .entity_id(EntityId::new(entity))
            .authority_id(AuthorityId::new("did:example:authority"))
            .action(Action::new("issue"))
            .resource(Resource::new("vc"))
            .recognized(true)
            .authorized(true)
            .record_type(RecordType::Authorization)
            .build()
            .unwrap()
    }

    fn query(entity: &str) -> TrustRecordQuery {
        TrustRecordQuery::new(
            EntityId::new(entity),
            AuthorityId::new("did:example:authority"),
            Action::new("issue"),
            Resource::new("vc"),
        )
    }

    /// A registry file holding only the header row, in its own directory.
    fn empty_registry() -> (tempfile::TempDir, PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("records.csv");
        std::fs::write(&path, format!("{}\n", HEADER.join(","))).unwrap();
        (dir, path)
    }

    async fn conformance_fixture() -> Option<crate::storage::conformance::Fixture> {
        let (dir, path) = empty_registry();
        let storage = FileStorage::try_new(&path, 3600).await.unwrap();
        Some(crate::storage::conformance::Fixture::new(storage).with_guard(dir))
    }

    crate::storage::conformance::repository_conformance_tests!(csv, conformance_fixture().await);

    /// Concurrent writes all reach the file: a fresh load sees every one.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn concurrent_creates_all_reach_the_file() {
        let (_dir, path) = empty_registry();
        let storage = FileStorage::try_new(&path, 3600).await.unwrap();
        let writers: Vec<_> = (0..32)
            .map(|i| {
                let storage = storage.clone();
                tokio::spawn(async move { storage.create(record(&format!("e{i:02}"))).await })
            })
            .collect();
        for writer in writers {
            writer.await.unwrap().unwrap();
        }

        let reloaded = FileStorage::try_new(&path, 3600).await.unwrap();
        assert_eq!(reloaded.list().await.unwrap().records().len(), 32);
        for i in 0..32 {
            assert!(
                reloaded
                    .find_by_query(query(&format!("e{i:02}")))
                    .await
                    .unwrap()
                    .is_some()
            );
        }
    }

    /// A write that cannot reach the disk is reported and leaves memory as it
    /// was, so memory never holds a change the file does not.
    #[tokio::test]
    async fn a_failed_write_leaves_memory_unchanged() {
        let (dir, path) = empty_registry();
        let storage = FileStorage::try_new(&path, 3600).await.unwrap();
        storage.create(record("kept")).await.unwrap();
        // The directory is gone, so the file can be neither read nor
        // replaced.
        std::fs::remove_dir_all(dir.path()).unwrap();

        let result = storage.create(record("lost")).await;
        assert!(
            matches!(result, Err(RepositoryError::QueryFailed(_))),
            "{result:?}"
        );
        assert!(
            storage
                .find_by_query(query("lost"))
                .await
                .unwrap()
                .is_none()
        );
        assert!(
            storage
                .find_by_query(query("kept"))
                .await
                .unwrap()
                .is_some()
        );
        assert!(storage.delete(query("kept")).await.is_err());
        assert!(
            storage
                .find_by_query(query("kept"))
                .await
                .unwrap()
                .is_some()
        );
    }

    /// The temporary-file-and-rename write reports a failure and leaves the
    /// target as it was.
    #[test]
    fn an_atomic_write_that_fails_leaves_the_target_alone() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("records.csv");
        std::fs::write(&path, "old").unwrap();
        write_atomically(&path, b"new").unwrap();
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "new");

        let missing = dir.path().join("gone").join("records.csv");
        assert!(write_atomically(&missing, b"new").is_err());
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "new");
        // No temporary file is left behind.
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 1);
    }

    /// The reload task does not replace what this process just wrote.
    #[tokio::test]
    async fn the_reload_keeps_this_process_writes() {
        let (_dir, path) = empty_registry();
        let storage = FileStorage::try_new(&path, 1).await.unwrap();
        storage.create(record("e1")).await.unwrap();
        sleep(Duration::from_millis(2500)).await;
        storage.create(record("e2")).await.unwrap();
        sleep(Duration::from_millis(1500)).await;
        assert_eq!(storage.list().await.unwrap().records().len(), 2);
    }

    /// An operator's edit made since the last reload is loaded before the
    /// next write rather than overwritten by it.
    #[tokio::test]
    async fn a_write_keeps_an_operator_edit_made_since_the_last_reload() {
        let (_dir, path) = empty_registry();
        let storage = FileStorage::try_new(&path, 3600).await.unwrap();
        storage.create(record("e1")).await.unwrap();

        let mut edited = std::fs::read_to_string(&path).unwrap();
        edited.push_str("operator,did:example:authority,issue,vc,true,true,e30=,authorization,,\n");
        std::fs::write(&path, edited).unwrap();

        storage.create(record("e2")).await.unwrap();
        let reloaded = FileStorage::try_new(&path, 3600).await.unwrap();
        for entity in ["e1", "operator", "e2"] {
            assert!(
                reloaded
                    .find_by_query(query(entity))
                    .await
                    .unwrap()
                    .is_some(),
                "{entity} lost"
            );
        }
    }

    /// A file an operator broke is neither loaded nor overwritten: writes fail
    /// until it is fixed, and reads keep answering from the last good state.
    #[tokio::test]
    async fn a_broken_edit_is_not_overwritten() {
        let (_dir, path) = empty_registry();
        let storage = FileStorage::try_new(&path, 1).await.unwrap();
        storage.create(record("e1")).await.unwrap();

        let broken = format!(
            "{}\ne1,did:example:authority,issue,vc,maybe,true,e30=,authorization,,\n",
            HEADER.join(",")
        );
        std::fs::write(&path, &broken).unwrap();

        let result = storage.create(record("e2")).await;
        assert!(
            matches!(result, Err(RepositoryError::QueryFailed(_))),
            "{result:?}"
        );
        assert_eq!(std::fs::read_to_string(&path).unwrap(), broken);
        sleep(Duration::from_millis(1500)).await;
        assert!(storage.find_by_query(query("e1")).await.unwrap().is_some());
    }

    /// A file emptied after startup is not taken to mean "no records".
    #[tokio::test]
    async fn an_emptied_file_does_not_empty_the_registry() {
        let (_dir, path) = empty_registry();
        let storage = FileStorage::try_new(&path, 1).await.unwrap();
        storage.create(record("e1")).await.unwrap();
        std::fs::write(&path, "").unwrap();
        sleep(Duration::from_millis(2500)).await;
        assert!(storage.find_by_query(query("e1")).await.unwrap().is_some());
        assert!(storage.create(record("e2")).await.is_err());
    }

    /// The file always has its header and its rows in key order, even with no
    /// records left.
    #[tokio::test]
    async fn the_file_keeps_its_header_and_a_stable_order() {
        let (_dir, path) = empty_registry();
        let storage = FileStorage::try_new(&path, 3600).await.unwrap();
        for entity in ["e3", "e1", "e2"] {
            storage.create(record(entity)).await.unwrap();
        }
        let contents = std::fs::read_to_string(&path).unwrap();
        let mut lines = contents.lines();
        assert_eq!(lines.next(), Some(HEADER.join(",").as_str()));
        let entities: Vec<_> = lines
            .map(|line| line.split(',').next().unwrap().to_string())
            .collect();
        assert_eq!(entities, ["e1", "e2", "e3"]);

        for entity in ["e1", "e2", "e3"] {
            storage.delete(query(entity)).await.unwrap();
        }
        assert_eq!(
            std::fs::read_to_string(&path).unwrap().trim(),
            HEADER.join(",")
        );
        assert!(FileStorage::try_new(&path, 3600).await.is_ok());
    }

    /// A context cell that does not decode fails the load instead of
    /// silently becoming an empty context.
    #[tokio::test]
    async fn an_undecodable_context_fails_the_load() {
        for cell in ["not-base64!", "bm90IGpzb24="] {
            let (_dir, path) = empty_registry();
            std::fs::write(
                &path,
                format!(
                    "{}\ne1,a1,ac1,r1,true,true,{cell},authorization,,\n",
                    HEADER.join(",")
                ),
            )
            .unwrap();
            let result = FileStorage::try_new(&path, 3600).await;
            assert!(result.is_err(), "{cell} loaded");
        }
    }
}
