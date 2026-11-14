//! A small fjall-backed key-value substrate for the messaging layer's durable
//! state: the TSP relationship store.
//!
//! This is deliberately **independent of the trust-record storage backend**: a
//! registry can keep its records in DynamoDB or Redis and still needs a local,
//! embedded place to persist its TSP relationships across a restart (Rev 3
//! §7.2.2). So the messaging store opens its own fjall
//! database at a configured path rather than reusing `storage::adapters::fjall`.
//!
//! fjall is synchronous, so every operation runs on a blocking thread via
//! [`tokio::task::spawn_blocking`] — the same pattern as
//! `storage::adapters::fjall_storage`.

use fjall::{Config, Database, Keyspace, KeyspaceCreateOptions};

/// One fjall keyspace exposing async raw-byte get/put/delete/scan operations.
///
/// Cheap to clone (a fjall `Keyspace` is a shared handle). Every clone keeps
/// the database open, so all of them must be dropped for it to close.
#[derive(Clone)]
pub struct KvKeyspace {
    ks: Keyspace,
}

impl KvKeyspace {
    pub async fn get(&self, key: Vec<u8>) -> Result<Option<Vec<u8>>, String> {
        let ks = self.ks.clone();
        tokio::task::spawn_blocking(move || {
            ks.get(&key)
                .map(|opt| opt.map(|v| v.to_vec()))
                .map_err(|e| e.to_string())
        })
        .await
        .map_err(|e| format!("fjall blocking task failed: {e}"))?
    }

    pub async fn put(&self, key: Vec<u8>, value: Vec<u8>) -> Result<(), String> {
        let ks = self.ks.clone();
        tokio::task::spawn_blocking(move || ks.insert(&key, &value).map_err(|e| e.to_string()))
            .await
            .map_err(|e| format!("fjall blocking task failed: {e}"))?
    }

    pub async fn delete(&self, key: Vec<u8>) -> Result<(), String> {
        let ks = self.ks.clone();
        tokio::task::spawn_blocking(move || ks.remove(&key).map_err(|e| e.to_string()))
            .await
            .map_err(|e| format!("fjall blocking task failed: {e}"))?
    }

    /// Every key that starts with `prefix`, without reading the values.
    pub async fn scan_keys_prefix(&self, prefix: Vec<u8>) -> Result<Vec<Vec<u8>>, String> {
        let ks = self.ks.clone();
        tokio::task::spawn_blocking(move || {
            let mut out = Vec::new();
            for guard in ks.prefix(&prefix) {
                out.push(guard.key().map_err(|e| e.to_string())?.to_vec());
            }
            Ok::<_, String>(out)
        })
        .await
        .map_err(|e| format!("fjall blocking task failed: {e}"))?
    }

    /// Every `(key, value)` whose key starts with `prefix`, decoded to owned
    /// bytes. Used by the relationship store's recovery sweep.
    pub async fn scan_prefix(&self, prefix: Vec<u8>) -> Result<Vec<(Vec<u8>, Vec<u8>)>, String> {
        let ks = self.ks.clone();
        tokio::task::spawn_blocking(move || {
            let mut out = Vec::new();
            for guard in ks.prefix(&prefix) {
                let (k, v) = guard.into_inner().map_err(|e| e.to_string())?;
                out.push((k.to_vec(), v.to_vec()));
            }
            Ok::<_, String>(out)
        })
        .await
        .map_err(|e| format!("fjall blocking task failed: {e}"))?
    }
}

/// The messaging layer's durable store: one fjall database with a keyspace for
/// TSP relationships.
///
/// A database written by an earlier version also holds an `outbox` keyspace;
/// nothing reads it any more, and it is left as it is.
pub struct MessagingStore {
    // Keep the database handle alive for the lifetime of the store (background
    // compaction/flush threads).
    _db: Database,
    pub relationships: KvKeyspace,
}

impl MessagingStore {
    /// Open (or create) the messaging database at `path`.
    pub fn open(path: &str) -> Result<Self, String> {
        let db = Database::open(Config::new(std::path::Path::new(path)))
            .map_err(|e| format!("open messaging store at {path}: {e}"))?;
        let relationships = KvKeyspace {
            ks: db
                .keyspace("relationships", KeyspaceCreateOptions::default)
                .map_err(|e| format!("open relationships keyspace: {e}"))?,
        };
        Ok(Self {
            _db: db,
            relationships,
        })
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;

    /// The store is single-opener: a registry rebuilt in the same process can
    /// open it again only once every handle on the first one has been
    /// dropped, which is why the receive path stops everything that holds it
    /// before it returns.
    #[test]
    fn the_store_opens_again_only_once_every_handle_is_dropped() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("store");
        let path = path.to_str().unwrap();

        let first = MessagingStore::open(path).unwrap();
        let held = first.relationships.clone();
        assert!(
            MessagingStore::open(path).is_err(),
            "a second open of a live store succeeded"
        );
        drop(first);
        assert!(
            MessagingStore::open(path).is_err(),
            "a keyspace handle no longer keeps the store open"
        );
        drop(held);
        MessagingStore::open(path).expect("reopen once every handle is dropped");
    }
}
