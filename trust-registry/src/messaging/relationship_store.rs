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
//!
//! The store is bounded, since any VID TSP authenticates can form a
//! relationship ([`super::tsp_inbound`]):
//!
//! - **by size**: [`FjallRelationshipKv`] holds at most
//!   [`RelationshipLimits::max_relationships`] relationships' records and
//!   refuses a new record beyond that, so a relationship with a new peer is not
//!   recorded while the store is full. Existing relationships keep working;
//! - **by age**: every relationship is stamped active when it is accepted and
//!   on each application message, and the maintenance loop evicts one idle for
//!   [`RelationshipLimits::idle_ttl`]. A relationship restored from an older
//!   store with no stamp is stamped at startup, so it ages from then.

use std::sync::Arc;
use std::time::Duration;

use affinidi_messaging_sdk::errors::ATMError;
use affinidi_messaging_sdk::{EvictionPolicy, PersistentRelationshipStore, RelationshipKv};
use async_trait::async_trait;
use tokio::sync::Mutex;
use tracing::{info, warn};

use crate::messaging::kv::KvKeyspace;

/// Records the SDK keeps per relationship: state, thread digests, reply path,
/// peer capability and last activity.
pub const RECORDS_PER_RELATIONSHIP: usize = 5;

/// Default for [`RelationshipLimits::max_relationships`].
pub const DEFAULT_MAX_RELATIONSHIPS: usize = 10_000;

/// Default for [`RelationshipLimits::idle_ttl`]: seven days, the SDK's default.
pub const DEFAULT_IDLE_TTL: Duration = Duration::from_secs(7 * 24 * 60 * 60);

/// The longest the idle-eviction sweep waits between runs.
const MAX_SWEEP_INTERVAL: Duration = Duration::from_secs(6 * 60 * 60);

/// The shortest idle period, and so the most frequent sweep, accepted.
const MIN_IDLE_TTL: Duration = Duration::from_secs(60);

/// How large the TSP relationship store may grow and how long an idle
/// relationship is kept.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RelationshipLimits {
    /// The most relationships the store holds records for.
    pub max_relationships: usize,
    /// How long a relationship with no activity is kept.
    pub idle_ttl: Duration,
}

impl Default for RelationshipLimits {
    fn default() -> Self {
        Self {
            max_relationships: DEFAULT_MAX_RELATIONSHIPS,
            idle_ttl: DEFAULT_IDLE_TTL,
        }
    }
}

impl RelationshipLimits {
    /// Read `TR_TSP_MAX_RELATIONSHIPS` and `TR_TSP_RELATIONSHIP_IDLE_SECS`; each
    /// takes its default when unset. A value that is not a positive whole
    /// number, or an idle period under a minute, is an error rather than a
    /// silent default, so a typo cannot lift the bound.
    pub fn from_env() -> Result<Self, String> {
        Self::parse(
            std::env::var("TR_TSP_MAX_RELATIONSHIPS").ok().as_deref(),
            std::env::var("TR_TSP_RELATIONSHIP_IDLE_SECS")
                .ok()
                .as_deref(),
        )
    }

    fn parse(max_relationships: Option<&str>, idle_secs: Option<&str>) -> Result<Self, String> {
        let positive = |name: &str, raw: &str| {
            raw.trim()
                .parse::<u64>()
                .ok()
                .filter(|value| *value > 0)
                .ok_or_else(|| format!("{name} must be a positive whole number, not {raw:?}"))
        };
        let mut limits = Self::default();
        if let Some(raw) = max_relationships {
            limits.max_relationships = usize::try_from(positive("TR_TSP_MAX_RELATIONSHIPS", raw)?)
                .map_err(|_| format!("TR_TSP_MAX_RELATIONSHIPS is out of range: {raw}"))?;
        }
        if let Some(raw) = idle_secs {
            limits.idle_ttl = Duration::from_secs(positive("TR_TSP_RELATIONSHIP_IDLE_SECS", raw)?);
            if limits.idle_ttl < MIN_IDLE_TTL {
                return Err(format!(
                    "TR_TSP_RELATIONSHIP_IDLE_SECS must be at least {}",
                    MIN_IDLE_TTL.as_secs()
                ));
            }
        }
        Ok(limits)
    }

    /// The eviction policy the maintenance loop applies.
    pub fn eviction_policy(&self) -> EvictionPolicy {
        EvictionPolicy { ttl: self.idle_ttl }
    }

    /// How often the maintenance loop sweeps: at most every half idle period,
    /// so a relationship is evicted no later than one and a half periods after
    /// its last activity.
    pub fn sweep_interval(&self) -> Duration {
        (self.idle_ttl / 2).clamp(MIN_IDLE_TTL / 2, MAX_SWEEP_INTERVAL)
    }
}

/// A [`RelationshipKv`] over the messaging store's `relationships` keyspace.
/// Get / put / delete / scan map straight onto the keyspace's raw byte
/// operations; the SDK owns the key layout and serialisation.
///
/// Bounded: it holds at most `max_relationships` ×
/// [`RECORDS_PER_RELATIONSHIP`] records, and refuses to add a record beyond
/// that. Replacing or deleting a record is always allowed.
pub struct FjallRelationshipKv {
    keyspace: KvKeyspace,
    max_records: usize,
    /// How many records the keyspace holds. Held across each put and delete,
    /// so the count and the keyspace move together.
    records: Mutex<usize>,
}

impl FjallRelationshipKv {
    /// Open the store over `keyspace`, counting the records it already holds.
    pub async fn open(keyspace: KvKeyspace, max_relationships: usize) -> Result<Self, String> {
        let records = keyspace.scan_prefix(Vec::new()).await?.len();
        let max_records = max_relationships.saturating_mul(RECORDS_PER_RELATIONSHIP);
        if records >= max_records {
            warn!(
                records,
                max_records,
                "the TSP relationship store is full: no relationship with a new peer is \
                 recorded until idle ones are evicted"
            );
        }
        Ok(Self {
            keyspace,
            max_records,
            records: Mutex::new(records),
        })
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
        let mut records = self.records.lock().await;
        let exists = self.get(key).await?.is_some();
        if !exists && *records >= self.max_records {
            warn!(
                max_records = self.max_records,
                "the TSP relationship store is full; not recording a new relationship"
            );
            return Err(ATMError::SDKError(format!(
                "the TSP relationship store is full ({} records)",
                self.max_records
            )));
        }
        self.keyspace
            .put(key.to_vec(), value.to_vec())
            .await
            .map_err(|e| ATMError::SDKError(format!("relationships keyspace put: {e}")))?;
        if !exists {
            *records += 1;
        }
        Ok(())
    }

    async fn delete(&self, key: &[u8]) -> Result<(), ATMError> {
        let mut records = self.records.lock().await;
        if self.get(key).await?.is_none() {
            return Ok(());
        }
        self.keyspace
            .delete(key.to_vec())
            .await
            .map_err(|e| ATMError::SDKError(format!("relationships keyspace delete: {e}")))?;
        *records = records.saturating_sub(1);
        Ok(())
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

/// Stamp the relationship between `our_vid` and `their_vid` as active now, so
/// it ages from this moment. A failed stamp only means the relationship may be
/// evicted sooner, so it is logged rather than surfaced.
pub async fn mark_active(store: &RegistryRelationshipStore, our_vid: &str, their_vid: &str) {
    let Some(now_ms) = unix_millis() else {
        return;
    };
    if let Err(e) = store.touch(our_vid, their_vid, now_ms).await {
        warn!(peer = their_vid, error = %e, "could not stamp TSP relationship activity");
    }
}

/// Background maintenance for the durable TSP relationship store.
///
/// On boot it logs how many relationships survived the restart and stamps any
/// that carry no activity stamp (recorded before stamping existed), so they
/// age out like the rest; then it periodically evicts those idle for
/// `limits.idle_ttl`. Spawn this **once**, at startup — it holds the store and
/// does not depend on the mediator socket, so tying it to the connect path
/// would leak one sweep task per reconnect.
pub async fn maintenance_loop(store: Arc<RegistryRelationshipStore>, limits: RelationshipLimits) {
    match store.established_relationships().await {
        Ok(established) => {
            info!(
                count = established.len(),
                "TSP relationships restored from the durable store"
            );
            stamp_unstamped(&store, &established).await;
        }
        Err(e) => warn!(error = %e, "could not enumerate restored TSP relationships"),
    }

    let policy = limits.eviction_policy();
    let mut ticker = tokio::time::interval(limits.sweep_interval());
    loop {
        ticker.tick().await;
        sweep(&store, &policy).await;
    }
}

async fn stamp_unstamped(store: &RegistryRelationshipStore, pairs: &[(String, String)]) {
    for (our, their) in pairs {
        match store.last_active(our, their).await {
            Ok(Some(_)) => {}
            Ok(None) => mark_active(store, our, their).await,
            Err(e) => warn!(peer = %their, error = %e, "could not read TSP relationship activity"),
        }
    }
}

async fn sweep(store: &RegistryRelationshipStore, policy: &EvictionPolicy) {
    let Some(now_ms) = unix_millis() else {
        return;
    };
    match store.evict_idle(now_ms, policy).await {
        Ok(evicted) if !evicted.is_empty() => {
            info!(count = evicted.len(), "evicted idle TSP relationships")
        }
        Ok(_) => {}
        Err(e) => warn!(error = %e, "TSP relationship eviction sweep failed"),
    }
}

fn unix_millis() -> Option<u64> {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()
        .map(|d| d.as_millis() as u64)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;
    use crate::messaging::kv::MessagingStore;
    use affinidi_messaging_sdk::RelationshipStore;
    use affinidi_messaging_sdk::protocols::tsp::RelationshipState;
    use tempfile::TempDir;

    const US: &str = "did:example:registry";

    async fn store(
        max_relationships: usize,
    ) -> (TempDir, MessagingStore, RegistryRelationshipStore) {
        let dir = tempfile::tempdir().unwrap();
        let messaging = MessagingStore::open(dir.path().to_str().unwrap()).unwrap();
        let kv = FjallRelationshipKv::open(messaging.relationships.clone(), max_relationships)
            .await
            .unwrap();
        (dir, messaging, PersistentRelationshipStore::new(kv))
    }

    fn peer(n: usize) -> String {
        format!("did:example:peer-{n}")
    }

    /// Record a relationship the way the transport does for an accepted
    /// invite: its state, then its activity stamp.
    async fn form(store: &RegistryRelationshipStore, their: &str) -> Result<(), ATMError> {
        store
            .set(US, their, RelationshipState::Bidirectional)
            .await?;
        store.touch(US, their, 1).await
    }

    async fn records(messaging: &MessagingStore) -> usize {
        messaging
            .relationships
            .scan_prefix(Vec::new())
            .await
            .unwrap()
            .len()
    }

    /// Fill a store bounded to one relationship: five records.
    async fn fill(store: &RegistryRelationshipStore) {
        for n in 0..2 {
            form(store, &peer(n)).await.unwrap();
        }
        store
            .set_reply_path(US, &peer(0), vec!["did:example:hop".into()])
            .await
            .unwrap();
    }

    /// A full store records no new relationship and does not grow, but the
    /// relationships it holds can still be updated.
    #[tokio::test]
    async fn a_full_store_records_no_new_relationship() {
        let (_dir, messaging, store) = store(1).await;
        fill(&store).await;
        let full = records(&messaging).await;
        assert_eq!(full, RECORDS_PER_RELATIONSHIP);

        assert!(form(&store, &peer(2)).await.is_err());
        assert_eq!(records(&messaging).await, full, "the store did not grow");
        assert_eq!(
            store.get(US, &peer(2)).await.unwrap(),
            RelationshipState::None
        );

        store.touch(US, &peer(0), 2).await.expect("an update fits");
        assert_eq!(store.last_active(US, &peer(0)).await.unwrap(), Some(2));
    }

    #[tokio::test]
    async fn forgetting_a_relationship_makes_room() {
        let (_dir, _messaging, store) = store(1).await;
        fill(&store).await;
        assert!(form(&store, &peer(2)).await.is_err());

        store.forget(US, &peer(0)).await.unwrap();
        form(&store, &peer(2)).await.expect("room after forgetting");
    }

    /// The count of records survives a restart, so a full store stays full.
    #[tokio::test]
    async fn the_bound_holds_across_a_reopen() {
        let dir = tempfile::tempdir().unwrap();
        {
            let messaging = MessagingStore::open(dir.path().to_str().unwrap()).unwrap();
            let kv = FjallRelationshipKv::open(messaging.relationships.clone(), 1)
                .await
                .unwrap();
            fill(&PersistentRelationshipStore::new(kv)).await;
        }
        let messaging = MessagingStore::open(dir.path().to_str().unwrap()).unwrap();
        let kv = FjallRelationshipKv::open(messaging.relationships.clone(), 1)
            .await
            .unwrap();
        let store = PersistentRelationshipStore::new(kv);
        assert!(form(&store, &peer(2)).await.is_err());
    }

    /// A relationship recorded without an activity stamp is stamped at
    /// startup, so the sweep can age it out; one that is active is kept.
    #[tokio::test]
    async fn unstamped_relationships_are_stamped_and_then_age_out() {
        let (_dir, _messaging, store) = store(10).await;
        store
            .set(US, &peer(0), RelationshipState::Bidirectional)
            .await
            .unwrap();
        assert_eq!(store.last_active(US, &peer(0)).await.unwrap(), None);

        let established = store.established_relationships().await.unwrap();
        stamp_unstamped(&store, &established).await;
        let stamped = store.last_active(US, &peer(0)).await.unwrap();
        assert!(stamped.is_some());

        let policy = EvictionPolicy {
            ttl: Duration::from_secs(60),
        };
        let evicted = store
            .evict_idle(stamped.unwrap() + 61_000, &policy)
            .await
            .unwrap();
        assert_eq!(evicted, vec![(US.to_string(), peer(0))]);
        assert_eq!(
            store.get(US, &peer(0)).await.unwrap(),
            RelationshipState::None
        );
    }

    #[test]
    fn limits_default_when_unset() {
        assert_eq!(
            RelationshipLimits::parse(None, None).unwrap(),
            RelationshipLimits::default()
        );
    }

    #[test]
    fn limits_are_read_from_their_settings() {
        let limits = RelationshipLimits::parse(Some("50"), Some("3600")).unwrap();
        assert_eq!(limits.max_relationships, 50);
        assert_eq!(limits.idle_ttl, Duration::from_secs(3600));
        assert_eq!(limits.sweep_interval(), Duration::from_secs(1800));
        assert_eq!(
            RelationshipLimits::default().sweep_interval(),
            MAX_SWEEP_INTERVAL
        );
    }

    #[test]
    fn malformed_limits_are_an_error() {
        for (max, idle) in [
            (Some("0"), None),
            (Some("many"), None),
            (Some("-1"), None),
            (None, Some("0")),
            (None, Some("59")),
            (None, Some("1h")),
        ] {
            assert!(
                RelationshipLimits::parse(max, idle).is_err(),
                "{max:?} / {idle:?} should be refused"
            );
        }
    }
}
