//! Durable TSP relationship store, backed by the messaging layer's `relationships`
//! keyspace.
//!
//! Rev 3 §7.2.2 has an endpoint silently drop application traffic from a VID it
//! holds no relationship with. The SDK's default relationship store is in-memory
//! and wiped on restart, so a restarted registry forgets every peer and their
//! traffic vanishes until each re-handshakes. Persisting the state makes a
//! restart transparent.
//!
//! [`FjallRelationshipKv`] adapts the keyspace's byte interface to the SDK's
//! [`RelationshipKv`]; the SDK's [`PersistentRelationshipStore`] layers the
//! record encoding, per-facet keys and defaults on top — this adapter owns no
//! key layout of its own.
//!
//! This mirrors `vta-service::messaging::tsp_relationship_store`, adapted to the
//! registry's fjall substrate.

use std::sync::Arc;
use std::time::Duration;

use affinidi_messaging_sdk::errors::ATMError;
use affinidi_messaging_sdk::{EvictionPolicy, PersistentRelationshipStore, RelationshipKv};
use async_trait::async_trait;
use tracing::{info, warn};

use crate::messaging::kv::KvKeyspace;

/// A [`RelationshipKv`] over the messaging store's `relationships` keyspace.
/// Get / put / delete / scan map straight onto the keyspace's raw byte
/// operations; the SDK owns the key layout and serialisation.
pub struct FjallRelationshipKv {
    keyspace: KvKeyspace,
}

impl FjallRelationshipKv {
    pub fn new(keyspace: KvKeyspace) -> Self {
        Self { keyspace }
    }
}

#[async_trait]
impl RelationshipKv for FjallRelationshipKv {
    async fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>, ATMError> {
        self.keyspace
            .get(key.to_vec())
            .await
            .map_err(|e| ATMError::SDKError(format!("relationships keyspace get: {e}")))
    }

    async fn put(&self, key: &[u8], value: &[u8]) -> Result<(), ATMError> {
        self.keyspace
            .put(key.to_vec(), value.to_vec())
            .await
            .map_err(|e| ATMError::SDKError(format!("relationships keyspace put: {e}")))
    }

    async fn delete(&self, key: &[u8]) -> Result<(), ATMError> {
        self.keyspace
            .delete(key.to_vec())
            .await
            .map_err(|e| ATMError::SDKError(format!("relationships keyspace delete: {e}")))
    }

    async fn scan_prefix(&self, prefix: &[u8]) -> Result<Vec<(Vec<u8>, Vec<u8>)>, ATMError> {
        self.keyspace
            .scan_prefix(prefix.to_vec())
            .await
            .map_err(|e| ATMError::SDKError(format!("relationships keyspace scan: {e}")))
    }
}

/// The concrete durable relationship store the registry hands to the ATM and the
/// maintenance loop (`evict_idle` / `established_relationships` live on
/// [`PersistentRelationshipStore`], not the `RelationshipStore` trait the ATM
/// takes).
pub type RegistryRelationshipStore = PersistentRelationshipStore<FjallRelationshipKv>;

/// How often the idle-eviction sweep runs.
const SWEEP_INTERVAL: Duration = Duration::from_secs(6 * 60 * 60);

/// Background maintenance for the durable TSP relationship store.
///
/// On boot it logs how many relationships survived the restart; then it
/// periodically evicts idle ones (7-day default). Spawn this **once**, at
/// startup — it holds the store and does not depend on the mediator socket, so
/// tying it to the connect path would leak one sweep task per reconnect.
pub async fn maintenance_loop(store: Arc<RegistryRelationshipStore>) {
    match store.established_relationships().await {
        Ok(established) => info!(
            count = established.len(),
            "TSP relationships restored from the durable store"
        ),
        Err(e) => warn!(error = %e, "could not enumerate restored TSP relationships"),
    }

    let policy = EvictionPolicy::default();
    let mut ticker = tokio::time::interval(SWEEP_INTERVAL);
    loop {
        ticker.tick().await;
        let Some(now_ms) = unix_millis() else {
            continue;
        };
        match store.evict_idle(now_ms, &policy).await {
            Ok(evicted) if !evicted.is_empty() => {
                info!(count = evicted.len(), "evicted idle TSP relationships")
            }
            Ok(_) => {}
            Err(e) => warn!(error = %e, "TSP relationship eviction sweep failed"),
        }
    }
}

fn unix_millis() -> Option<u64> {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()
        .map(|d| d.as_millis() as u64)
}
