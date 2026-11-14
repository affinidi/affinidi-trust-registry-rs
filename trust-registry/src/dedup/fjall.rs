//! The record of accepted document identifiers in the fjall record database
//! (feature `storage-fjall`).
//!
//! fjall locks its database directory, so one process owns it: the record is
//! kept in memory, as [`MemoryMessageIdStore`](super::MemoryMessageIdStore)
//! keeps it, and every **outcome** is also written to the `message_ids`
//! keyspace of the record database, `fsync`ed before `complete` returns
//! (rule R1.6: the reply that follows must not outlive the record of it).
//! On open the outcomes still inside their retention are loaded back, so a
//! redelivery after a restart replays instead of executing again.
//!
//! In-flight claims are not written: after a restart no claimant from the
//! previous run can still be executing (the directory lock guarantees this
//! process is the only one), so a redelivered document is executed at once
//! rather than after the lease. Expired outcomes are removed from disk as they
//! are evicted, and any left over are dropped on open.

use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use fjall::{Database, Keyspace, KeyspaceCreateOptions, PersistMode};
use serde::{Deserialize, Serialize};

use super::{Claim, ClaimToken, DedupError, Inner, MessageIdStore, StoredOutcome, chrono_duration};
use crate::configs::MessageIdStoreConfig;

/// Keyspace (table) holding the outcomes, beside the records'.
pub const KEYSPACE_NAME: &str = "message_ids";

/// One outcome as written to disk.
#[derive(Serialize, Deserialize)]
struct Persisted {
    digest: String,
    expires_at: DateTime<Utc>,
    outcome: StoredOutcome,
}

struct Shared {
    config: MessageIdStoreConfig,
    db: Database,
    keyspace: Keyspace,
    inner: Mutex<Inner>,
}

impl Shared {
    fn lock(&self) -> std::sync::MutexGuard<'_, Inner> {
        self.inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// Remove expired outcomes from disk. A removal that fails is logged: the
    /// entry is dropped from memory either way, and an expired one left on
    /// disk is dropped on the next open.
    fn forget(&self, expired: Vec<String>) {
        for key in expired {
            if let Err(e) = self.keyspace.remove(key.as_bytes()) {
                tracing::warn!("Failed to remove expired dedup entry {key}: {e}");
            }
        }
    }
}

/// The fjall-backed [`MessageIdStore`]. Built by
/// [`FjallStorage`](crate::storage::adapters::fjall_storage::FjallStorage)
/// over its own database; one per database.
pub struct FjallMessageIdStore {
    shared: Arc<Shared>,
}

fn unavailable(e: impl std::fmt::Display) -> DedupError {
    DedupError::Unavailable(e.to_string())
}

impl FjallMessageIdStore {
    /// Open the store in `db`, loading the outcomes still inside their
    /// retention. Blocking: call it from a blocking context.
    pub fn open(db: Database, config: MessageIdStoreConfig) -> Result<Self, DedupError> {
        let keyspace = db
            .keyspace(KEYSPACE_NAME, KeyspaceCreateOptions::default)
            .map_err(unavailable)?;
        let now = Utc::now();
        let mut live = Vec::new();
        let mut stale = Vec::new();
        for guard in keyspace.iter() {
            let (key, value) = guard.into_inner().map_err(unavailable)?;
            let key = String::from_utf8_lossy(&key).into_owned();
            match serde_json::from_slice::<Persisted>(&value) {
                Ok(persisted) if persisted.expires_at > now => live.push((key, persisted)),
                Ok(_) => stale.push(key),
                Err(e) => {
                    // Kept out of the record: without its digest a redelivery
                    // cannot be matched to it. It is removed so it is not
                    // reported again on every start.
                    tracing::error!("Dropping undecodable dedup entry {key}: {e}");
                    stale.push(key);
                }
            }
        }
        // `Inner` expires outcomes in the order they were added.
        live.sort_by_key(|(_, persisted)| persisted.expires_at);
        let mut inner = Inner::default();
        let restored = live.len();
        for (key, persisted) in live {
            inner.restore(
                &key,
                persisted.digest,
                persisted.outcome,
                persisted.expires_at,
            );
        }
        let shared = Shared {
            config,
            db,
            keyspace,
            inner: Mutex::new(inner),
        };
        shared.forget(stale);
        tracing::info!("Opened the fjall record of accepted documents: {restored} outcomes kept");
        Ok(Self {
            shared: Arc::new(shared),
        })
    }

    async fn blocking<T, F>(&self, work: F) -> Result<T, DedupError>
    where
        T: Send + 'static,
        F: FnOnce(&Shared) -> Result<T, DedupError> + Send + 'static,
    {
        let shared = Arc::clone(&self.shared);
        tokio::task::spawn_blocking(move || work(&shared))
            .await
            .map_err(|e| unavailable(format!("fjall blocking task failed: {e}")))?
    }
}

#[async_trait]
impl MessageIdStore for FjallMessageIdStore {
    async fn claim(&self, key: &str, digest: &str) -> Result<Claim, DedupError> {
        let key = key.to_string();
        let digest = digest.to_string();
        self.blocking(move |shared| {
            let now = Utc::now();
            let mut inner = shared.lock();
            let expired = inner.evict_expired(now, shared.config.in_flight_lease);
            let claim = inner.claim(&key, &digest, now, &shared.config);
            drop(inner);
            shared.forget(expired);
            claim
        })
        .await
    }

    async fn complete(
        &self,
        key: &str,
        token: &ClaimToken,
        outcome: &StoredOutcome,
    ) -> Result<(), DedupError> {
        let key = key.to_string();
        let token = token.clone();
        let outcome = outcome.clone();
        self.blocking(move |shared| {
            let expires_at = Utc::now() + chrono_duration(shared.config.retention);
            // Held across the write, so the claim cannot change between the
            // check and the record of the outcome.
            let mut inner = shared.lock();
            let Some(digest) = inner.held_by(&key, &token) else {
                return Err(DedupError::ClaimLost(format!(
                    "{key} is no longer held by this claim"
                )));
            };
            let persisted = Persisted {
                digest,
                expires_at,
                outcome,
            };
            let value = serde_json::to_vec(&persisted).map_err(unavailable)?;
            // On disk first, and fsynced: the reply sent after this returns
            // must not outlive the record of it.
            let mut batch = shared.db.batch().durability(Some(PersistMode::SyncAll));
            batch.insert(&shared.keyspace, key.as_bytes(), value);
            batch.commit().map_err(unavailable)?;
            inner
                .complete(&key, &token, &persisted.outcome, expires_at)
                .map(|_| ())
        })
        .await
    }

    async fn release(&self, key: &str, token: &ClaimToken) -> Result<(), DedupError> {
        self.shared.lock().release(key, token);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;
    use crate::dedup::conformance::StoreFixture;

    /// The database at one path, opened on demand and closed by `restart`.
    struct Holder {
        path: std::path::PathBuf,
        db: Mutex<Option<Database>>,
    }

    impl Holder {
        fn db(&self) -> Database {
            let mut db = self.db.lock().unwrap();
            db.get_or_insert_with(|| {
                Database::open(fjall::Config::new(&self.path)).expect("open fjall")
            })
            .clone()
        }
    }

    fn fixture() -> StoreFixture {
        let dir = tempfile::tempdir().expect("tempdir");
        let holder = Arc::new(Holder {
            path: dir.path().to_path_buf(),
            db: Mutex::new(None),
        });
        let make = Arc::clone(&holder);
        let restart = Arc::clone(&holder);
        StoreFixture::new(move |config| {
            let holder = Arc::clone(&make);
            Box::pin(async move {
                let db = holder.db();
                Arc::new(
                    tokio::task::spawn_blocking(move || FjallMessageIdStore::open(db, config))
                        .await
                        .expect("open task")
                        .expect("open store"),
                ) as Arc<dyn MessageIdStore>
            })
        })
        .with_restart(move || {
            let holder = Arc::clone(&restart);
            Box::pin(async move {
                holder.db.lock().unwrap().take();
            })
        })
        .with_guard(dir)
    }

    crate::dedup::conformance::message_id_store_conformance_tests!(fjall_dedup, Some(fixture()));

    /// After a restart no claimant of the previous run is executing, so a
    /// document claimed but not completed is executed at once, not after the
    /// lease.
    #[tokio::test]
    async fn an_unresolved_claim_does_not_survive_a_restart() {
        let dir = tempfile::tempdir().expect("tempdir");
        let key = "MID#did:example:a#1";
        {
            let db = Database::open(fjall::Config::new(dir.path())).expect("open");
            let store = FjallMessageIdStore::open(db, MessageIdStoreConfig::default()).unwrap();
            assert!(matches!(
                store.claim(key, "digest").await.unwrap(),
                Claim::Acquired(_)
            ));
        }
        let db = Database::open(fjall::Config::new(dir.path())).expect("reopen");
        let store = FjallMessageIdStore::open(db, MessageIdStoreConfig::default()).unwrap();
        assert!(matches!(
            store.claim(key, "digest").await.unwrap(),
            Claim::Acquired(_)
        ));
    }
}
