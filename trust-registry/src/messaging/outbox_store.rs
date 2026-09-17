//! Durable [`OutboxStore`] for the D1 delivery layer, backed by the messaging
//! layer's `outbox` keyspace.
//!
//! The delivery layer's `Guaranteed` sends are written to a durable outbox so a
//! process restart does not lose delivery-critical work (the layer's
//! `InMemoryOutboxStore` is dev-only). The registry answers most requests
//! synchronously over TSP, so this is dormant until a guaranteed send is
//! enqueued — but it is wired for restart resilience and future use, mirroring
//! `vta-service`'s outbox.
//!
//! Schema:
//! - Key:   `outbox:{idempotency_key}`
//! - Value: JSON-serialised delivery [`OutboxEntry`]
//!
//! The scanning reads ([`OutboxStore::due`], [`OutboxStore::awaiting_confirmation`])
//! prefix-scan the keyspace and filter in memory, replicating the reference
//! `InMemoryOutboxStore` semantics — including the per-`ordering_key` FIFO head
//! gate in `due`. Ported from `vti-common::outbox_store`.

use std::collections::HashMap;

use affinidi_messaging_delivery::{OutboxEntry, OutboxError, OutboxState, OutboxStore};
use async_trait::async_trait;

use crate::messaging::kv::KvKeyspace;

const PREFIX: &str = "outbox:";

fn outbox_key(idempotency_key: &str) -> Vec<u8> {
    format!("{PREFIX}{idempotency_key}").into_bytes()
}

fn backend(e: String) -> OutboxError {
    OutboxError::Backend(e)
}

/// A durable [`OutboxStore`] over the messaging store's `outbox` keyspace.
pub struct FjallOutboxStore {
    ks: KvKeyspace,
}

impl FjallOutboxStore {
    pub fn new(ks: KvKeyspace) -> Self {
        Self { ks }
    }

    /// Every persisted entry, decoded — the basis for the scanning reads.
    async fn all(&self) -> Result<Vec<OutboxEntry>, OutboxError> {
        let raw = self
            .ks
            .scan_prefix(PREFIX.as_bytes().to_vec())
            .await
            .map_err(backend)?;
        let mut out = Vec::with_capacity(raw.len());
        for (_key, value) in raw {
            let entry = serde_json::from_slice(&value)
                .map_err(|e| OutboxError::Backend(format!("outbox decode: {e}")))?;
            out.push(entry);
        }
        Ok(out)
    }
}

#[async_trait]
impl OutboxStore for FjallOutboxStore {
    async fn put(&self, entry: OutboxEntry) -> Result<(), OutboxError> {
        match entry.state {
            OutboxState::Unconfirmed | OutboxState::Failed => tracing::warn!(
                key = %entry.idempotency_key,
                dest = %entry.dest_did,
                state = ?entry.state,
                attempts = entry.attempts,
                deliver_by_ms = entry.deliver_by_ms,
                "outbox: durable send settled without confirmed delivery"
            ),
            _ => tracing::info!(
                key = %entry.idempotency_key,
                dest = %entry.dest_did,
                state = ?entry.state,
                attempts = entry.attempts,
                next_attempt_at_ms = entry.next_attempt_at_ms,
                deliver_by_ms = entry.deliver_by_ms,
                "outbox: durable send state"
            ),
        }
        let value = serde_json::to_vec(&entry)
            .map_err(|e| OutboxError::Backend(format!("outbox encode: {e}")))?;
        self.ks
            .put(outbox_key(&entry.idempotency_key), value)
            .await
            .map_err(backend)
    }

    async fn get(&self, idempotency_key: &str) -> Result<Option<OutboxEntry>, OutboxError> {
        match self
            .ks
            .get(outbox_key(idempotency_key))
            .await
            .map_err(backend)?
        {
            Some(value) => {
                Ok(Some(serde_json::from_slice(&value).map_err(|e| {
                    OutboxError::Backend(format!("outbox decode: {e}"))
                })?))
            }
            None => Ok(None),
        }
    }

    async fn due(&self, now_ms: u64) -> Result<Vec<OutboxEntry>, OutboxError> {
        let entries = self.all().await?;

        // Per ordering-key FIFO head: the earliest-enqueued NON-TERMINAL entry
        // for each key gates the rest. Entries with no ordering key are
        // independent. (Mirrors `InMemoryOutboxStore::due`.)
        let mut head_created_at: HashMap<&str, u64> = HashMap::new();
        for e in &entries {
            if e.state.is_terminal() {
                continue;
            }
            if let Some(key) = &e.ordering_key {
                let head = head_created_at
                    .entry(key.as_str())
                    .or_insert(e.created_at_ms);
                if e.created_at_ms < *head {
                    *head = e.created_at_ms;
                }
            }
        }

        let mut due: Vec<OutboxEntry> = entries
            .iter()
            .filter(|e| e.state == OutboxState::Queued && e.next_attempt_at_ms <= now_ms)
            .filter(|e| match &e.ordering_key {
                Some(key) => head_created_at.get(key.as_str()) == Some(&e.created_at_ms),
                None => true,
            })
            .cloned()
            .collect();

        due.sort_by(|a, b| {
            a.created_at_ms
                .cmp(&b.created_at_ms)
                .then_with(|| a.idempotency_key.cmp(&b.idempotency_key))
        });
        Ok(due)
    }

    async fn awaiting_confirmation(&self) -> Result<Vec<OutboxEntry>, OutboxError> {
        Ok(self
            .all()
            .await?
            .into_iter()
            .filter(|e| e.state == OutboxState::Sent)
            .collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::messaging::kv::MessagingStore;
    use tempfile::TempDir;

    fn fresh() -> (TempDir, KvKeyspace) {
        let dir = tempfile::tempdir().unwrap();
        let store = MessagingStore::open(dir.path().to_str().unwrap()).unwrap();
        let ks = store.outbox.clone();
        (dir, ks)
    }

    fn entry(key: &str, created: u64) -> OutboxEntry {
        OutboxEntry::new(
            key,
            "did:example:bob",
            vec![1, 2, 3],
            created,
            created + 60_000,
        )
    }

    #[tokio::test]
    async fn put_get_roundtrip() {
        let (_dir, ks) = fresh();
        let store = FjallOutboxStore::new(ks);
        store.put(entry("k1", 1_000)).await.unwrap();

        let got = store.get("k1").await.unwrap().unwrap();
        assert_eq!(got.idempotency_key, "k1");
        assert_eq!(got.dest_did, "did:example:bob");
        assert_eq!(got.packed, vec![1, 2, 3]);
        assert_eq!(got.state, OutboxState::Queued);
        assert!(store.get("missing").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn due_returns_queued_eligible_entries_oldest_first() {
        let (_dir, ks) = fresh();
        let store = FjallOutboxStore::new(ks);
        store.put(entry("b", 2_000)).await.unwrap();
        store.put(entry("a", 1_000)).await.unwrap();
        let mut later = entry("c", 3_000);
        later.next_attempt_at_ms = 10_000;
        store.put(later).await.unwrap();

        let due = store.due(5_000).await.unwrap();
        let keys: Vec<_> = due.iter().map(|e| e.idempotency_key.as_str()).collect();
        assert_eq!(keys, vec!["a", "b"]);
    }

    #[tokio::test]
    async fn due_honors_per_ordering_key_fifo_head() {
        let (_dir, ks) = fresh();
        let store = FjallOutboxStore::new(ks);
        store
            .put(entry("head", 1_000).with_ordering_key("ord"))
            .await
            .unwrap();
        store
            .put(entry("tail", 2_000).with_ordering_key("ord"))
            .await
            .unwrap();

        let due = store.due(5_000).await.unwrap();
        let keys: Vec<_> = due.iter().map(|e| e.idempotency_key.as_str()).collect();
        assert_eq!(keys, vec!["head"]);
    }

    #[tokio::test]
    async fn awaiting_confirmation_returns_only_sent() {
        let (_dir, ks) = fresh();
        let store = FjallOutboxStore::new(ks);
        store.put(entry("queued", 1_000)).await.unwrap();
        let mut sent = entry("sent", 1_000);
        sent.state = OutboxState::Sent;
        store.put(sent).await.unwrap();

        let awaiting = store.awaiting_confirmation().await.unwrap();
        let keys: Vec<_> = awaiting
            .iter()
            .map(|e| e.idempotency_key.as_str())
            .collect();
        assert_eq!(keys, vec!["sent"]);
    }
}
