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
//! record encoding, per-facet keys and defaults on top. The adapter reads the
//! SDK's key layout (`tsp-rel/v1/ ‖ facet ‖ len(our) ‖ our ‖ their`) only to
//! tell which relationship a record belongs to; a test pins it against keys the
//! SDK writes.
//!
//! This mirrors `vta-service::messaging::tsp_relationship_store`, adapted to the
//! registry's fjall substrate.
//!
//! The store is bounded, since any VID TSP authenticates can form a
//! relationship ([`super::tsp_inbound`]):
//!
//! - **by size**: [`FjallRelationshipKv`] holds at most
//!   [`RelationshipLimits::max_relationships`] relationships. Recording one
//!   more evicts the least recently active relationship first, so a new peer
//!   is always admitted and the cost of a full store falls on the idlest peer,
//!   which re-handshakes when it next writes. Relationships with an admin
//!   (`ADMIN_DIDS`) neither count against the limit nor are evicted. While the
//!   store is at its limit `/health` reports it (`tspRelationships: "full"`);
//! - **by age**: every relationship is stamped active when it is accepted and
//!   on each application message, and the maintenance loop evicts one idle for
//!   [`RelationshipLimits::idle_ttl`]. A relationship restored with no stamp,
//!   in whatever state, is stamped at startup, so it ages from then.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use affinidi_did_common::scid::same_reference;
use affinidi_messaging_sdk::errors::ATMError;
use affinidi_messaging_sdk::{EvictionPolicy, PersistentRelationshipStore, RelationshipKv};
use async_trait::async_trait;
use tokio::sync::Mutex;
use tracing::{info, warn};

use crate::health::RegistryHealth;
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

/// The SDK's relationship key layout (`affinidi-messaging-sdk`,
/// `protocols::tsp::rel_key`): `PREFIX ‖ facet ‖ len(our) u32-BE ‖ our ‖ their`.
const REL_KEY_PREFIX: &[u8] = b"tsp-rel/v1/";
/// The facets the SDK stores, `FACET_LAST_ACTIVE` last.
const FACETS: [u8; RECORDS_PER_RELATIONSHIP] = [1, 2, 3, 4, FACET_LAST_ACTIVE];
const FACET_LAST_ACTIVE: u8 = 5;

/// `(our_vid, their_vid)`.
type Pair = (String, String);

fn decode_key(key: &[u8]) -> Option<(u8, Pair)> {
    let rest = key.strip_prefix(REL_KEY_PREFIX)?;
    let (&facet, rest) = rest.split_first()?;
    let len_bytes: [u8; 4] = rest.get(..4)?.try_into().ok()?;
    let our_len = usize::try_from(u32::from_be_bytes(len_bytes)).ok()?;
    let rest = rest.get(4..)?;
    let our = String::from_utf8(rest.get(..our_len)?.to_vec()).ok()?;
    let their = String::from_utf8(rest.get(our_len..)?.to_vec()).ok()?;
    Some((facet, (our, their)))
}

fn encode_key(facet: u8, (our, their): &Pair) -> Vec<u8> {
    let mut key = Vec::with_capacity(REL_KEY_PREFIX.len() + 5 + our.len() + their.len());
    key.extend_from_slice(REL_KEY_PREFIX);
    key.push(facet);
    key.extend_from_slice(&(our.len() as u32).to_be_bytes());
    key.extend_from_slice(our.as_bytes());
    key.extend_from_slice(their.as_bytes());
    key
}

/// How large the TSP relationship store may grow and how long an idle
/// relationship is kept.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RelationshipLimits {
    /// The most relationships with non-admin peers the store holds.
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

/// A [`RelationshipKv`] over the messaging store's `relationships` keyspace,
/// bounded to [`RelationshipLimits::max_relationships`] relationships with
/// non-admin peers.
///
/// Keeps an index of the relationships it holds and when each was last
/// active, built from the keyspace's keys (and the small last-activity
/// records) on open. Recording a relationship beyond the limit first forgets
/// the least recently active non-admin one, never-stamped ones first.
pub struct FjallRelationshipKv {
    keyspace: KvKeyspace,
    max_relationships: usize,
    /// Peers whose relationships are neither counted nor evicted.
    reserved: Vec<String>,
    health: Option<Arc<RegistryHealth>>,
    /// Held across each put and delete, so the index and the keyspace move
    /// together.
    index: Mutex<BTreeMap<Pair, Held>>,
}

/// What the index knows about one relationship.
#[derive(Debug, Clone, Copy, Default)]
struct Held {
    records: usize,
    /// When it was last stamped active, if ever.
    last_active: Option<u64>,
}

impl FjallRelationshipKv {
    /// Open the store over `keyspace`, indexing the relationships it already
    /// holds. Relationships with a peer in `reserved` (the admin DIDs) are not
    /// counted against the limit and never evicted to make room. `health`, when
    /// given, is told whether the store is at its limit.
    pub async fn open(
        keyspace: KvKeyspace,
        max_relationships: usize,
        reserved: Vec<String>,
        health: Option<Arc<RegistryHealth>>,
    ) -> Result<Self, String> {
        let mut index: BTreeMap<Pair, Held> = BTreeMap::new();
        for key in keyspace.scan_keys_prefix(REL_KEY_PREFIX.to_vec()).await? {
            if let Some((_, pair)) = decode_key(&key) {
                index.entry(pair).or_default().records += 1;
            }
        }
        let mut last_active_prefix = REL_KEY_PREFIX.to_vec();
        last_active_prefix.push(FACET_LAST_ACTIVE);
        for (key, value) in keyspace.scan_prefix(last_active_prefix).await? {
            if let (Some((_, pair)), Ok(at)) = (decode_key(&key), serde_json::from_slice(&value)) {
                index.entry(pair).or_default().last_active = Some(at);
            }
        }
        let kv = Self {
            keyspace,
            max_relationships,
            reserved,
            health,
            index: Mutex::new(index),
        };
        let held = kv.counted(&*kv.index.lock().await);
        if held >= max_relationships {
            warn!(
                held,
                max_relationships,
                "the TSP relationship store is full: a new peer replaces the least recently \
                 active one"
            );
        }
        kv.report(held);
        Ok(kv)
    }

    fn is_reserved(&self, (_, their): &Pair) -> bool {
        self.reserved
            .iter()
            .any(|admin| same_reference(admin, their))
    }

    /// Relationships that count against the limit.
    fn counted(&self, index: &BTreeMap<Pair, Held>) -> usize {
        index.keys().filter(|pair| !self.is_reserved(pair)).count()
    }

    fn report(&self, held: usize) {
        if let Some(health) = &self.health {
            health.set_tsp_relationships_full(held >= self.max_relationships);
        }
    }

    /// The relationships held with no activity stamp, whatever their state.
    pub async fn unstamped(&self) -> Vec<(String, String)> {
        self.index
            .lock()
            .await
            .iter()
            .filter(|(_, held)| held.last_active.is_none())
            .map(|(pair, _)| pair.clone())
            .collect()
    }

    /// Forget the least recently active counted relationship, to make room.
    async fn evict_one(&self, index: &mut BTreeMap<Pair, Held>) -> Result<(), ATMError> {
        let Some(victim) = index
            .iter()
            .filter(|(pair, _)| !self.is_reserved(pair))
            .min_by_key(|(_, held)| held.last_active.unwrap_or(0))
            .map(|(pair, _)| pair.clone())
        else {
            return Ok(());
        };
        for facet in FACETS {
            self.keyspace
                .delete(encode_key(facet, &victim))
                .await
                .map_err(|e| ATMError::SDKError(format!("relationships keyspace delete: {e}")))?;
        }
        index.remove(&victim);
        info!(
            peer = %victim.1,
            "the TSP relationship store is full; forgot the least recently active relationship"
        );
        Ok(())
    }

    async fn raw_get(&self, key: &[u8]) -> Result<Option<Vec<u8>>, ATMError> {
        self.keyspace
            .get(key.to_vec())
            .await
            .map_err(|e| ATMError::SDKError(format!("relationships keyspace get: {e}")))
    }
}

#[async_trait]
impl RelationshipKv for FjallRelationshipKv {
    async fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>, ATMError> {
        self.raw_get(key).await
    }

    async fn put(&self, key: &[u8], value: &[u8]) -> Result<(), ATMError> {
        let mut index = self.index.lock().await;
        let decoded = decode_key(key);
        if let Some((_, pair)) = &decoded
            && !index.contains_key(pair)
            && !self.is_reserved(pair)
        {
            while self.counted(&index) >= self.max_relationships {
                let before = index.len();
                self.evict_one(&mut index).await?;
                if index.len() == before {
                    break;
                }
            }
        }
        let exists = self.raw_get(key).await?.is_some();
        self.keyspace
            .put(key.to_vec(), value.to_vec())
            .await
            .map_err(|e| ATMError::SDKError(format!("relationships keyspace put: {e}")))?;
        if let Some((facet, pair)) = decoded {
            let held = index.entry(pair).or_default();
            if !exists {
                held.records += 1;
            }
            if facet == FACET_LAST_ACTIVE {
                held.last_active = serde_json::from_slice(value).ok().or(held.last_active);
            }
        }
        self.report(self.counted(&index));
        Ok(())
    }

    async fn delete(&self, key: &[u8]) -> Result<(), ATMError> {
        let mut index = self.index.lock().await;
        if self.raw_get(key).await?.is_none() {
            return Ok(());
        }
        self.keyspace
            .delete(key.to_vec())
            .await
            .map_err(|e| ATMError::SDKError(format!("relationships keyspace delete: {e}")))?;
        if let Some((facet, pair)) = decode_key(key)
            && let Some(held) = index.get_mut(&pair)
        {
            held.records = held.records.saturating_sub(1);
            if facet == FACET_LAST_ACTIVE {
                held.last_active = None;
            }
            if held.records == 0 {
                index.remove(&pair);
            }
        }
        self.report(self.counted(&index));
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
/// On boot it logs how many relationships survived the restart and stamps
/// every one that carries no activity stamp — whatever its state, including
/// pending, half-accepted and cancelled ones — so all of them age out like the
/// rest; then it periodically evicts those idle for `limits.idle_ttl`. Spawn
/// this **once**, at startup — it holds the store and does not depend on the
/// mediator socket, so tying it to the connect path would leak one sweep task
/// per reconnect.
pub async fn maintenance_loop(store: Arc<RegistryRelationshipStore>, limits: RelationshipLimits) {
    match store.established_relationships().await {
        Ok(established) => info!(
            count = established.len(),
            "TSP relationships restored from the durable store"
        ),
        Err(e) => warn!(error = %e, "could not enumerate restored TSP relationships"),
    }
    stamp_unstamped(&store).await;

    let policy = limits.eviction_policy();
    let mut ticker = tokio::time::interval(limits.sweep_interval());
    loop {
        ticker.tick().await;
        sweep(&store, &policy).await;
    }
}

async fn stamp_unstamped(store: &RegistryRelationshipStore) {
    for (our, their) in store.backend().unstamped().await {
        mark_active(store, &our, &their).await;
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
    const ADMIN: &str = "did:example:admin";

    async fn open(
        messaging: &MessagingStore,
        max_relationships: usize,
        health: Option<Arc<RegistryHealth>>,
    ) -> RegistryRelationshipStore {
        let kv = FjallRelationshipKv::open(
            messaging.relationships.clone(),
            max_relationships,
            vec![ADMIN.to_string()],
            health,
        )
        .await
        .unwrap();
        PersistentRelationshipStore::new(kv)
    }

    async fn store(
        max_relationships: usize,
    ) -> (TempDir, MessagingStore, RegistryRelationshipStore) {
        let dir = tempfile::tempdir().unwrap();
        let messaging = MessagingStore::open(dir.path().to_str().unwrap()).unwrap();
        let store = open(&messaging, max_relationships, None).await;
        (dir, messaging, store)
    }

    fn peer(n: usize) -> String {
        format!("did:example:peer-{n}")
    }

    /// Record an inbound invite the way the transport does: the state alone,
    /// before anything is stamped.
    async fn invite(store: &RegistryRelationshipStore, their: &str) {
        store
            .set(US, their, RelationshipState::InviteReceived)
            .await
            .unwrap();
    }

    async fn held(store: &RegistryRelationshipStore, their: &str) -> bool {
        store.get(US, their).await.unwrap() != RelationshipState::None
    }

    /// The adapter's reading of the key layout matches the keys the SDK
    /// writes, for every facet.
    #[tokio::test]
    async fn the_key_layout_matches_the_sdk() {
        let (_dir, messaging, store) = store(10).await;
        let their = peer(0);
        store
            .set(US, &their, RelationshipState::Bidirectional)
            .await
            .unwrap();
        store
            .set_thread_digests(US, &their, Default::default())
            .await
            .unwrap();
        store
            .set_reply_path(US, &their, vec!["x".into()])
            .await
            .unwrap();
        store.touch(US, &their, 7).await.unwrap();
        let keys = messaging
            .relationships
            .scan_keys_prefix(Vec::new())
            .await
            .unwrap();
        assert_eq!(keys.len(), 4);
        for key in keys {
            let (facet, pair) = decode_key(&key).expect("an SDK key decodes");
            assert_eq!(pair, (US.to_string(), their.clone()));
            assert_eq!(encode_key(facet, &pair), key);
        }
        assert_eq!(
            store.backend().index.lock().await[&(US.to_string(), their)].last_active,
            Some(7)
        );
    }

    /// A new peer is admitted into a full store by forgetting the least
    /// recently active relationship, unstamped ones first.
    #[tokio::test]
    async fn a_full_store_admits_a_new_peer_by_forgetting_the_idlest() {
        let (_dir, _messaging, store) = store(2).await;
        invite(&store, &peer(0)).await;
        invite(&store, &peer(1)).await;
        store.touch(US, &peer(0), 50).await.unwrap();
        store.touch(US, &peer(1), 10).await.unwrap();

        invite(&store, &peer(2)).await;
        assert!(held(&store, &peer(0)).await);
        assert!(!held(&store, &peer(1)).await, "the idlest is forgotten");
        assert_eq!(store.last_active(US, &peer(1)).await.unwrap(), None);
        assert!(held(&store, &peer(2)).await);

        // peer-2 has no stamp yet, so it goes before peer-0.
        invite(&store, &peer(3)).await;
        assert!(held(&store, &peer(0)).await);
        assert!(!held(&store, &peer(2)).await);
        assert!(held(&store, &peer(3)).await);
    }

    /// Admin relationships are not counted and never forgotten to make room.
    #[tokio::test]
    async fn an_admin_relationship_is_kept_and_not_counted() {
        let (_dir, _messaging, store) = store(1).await;
        invite(&store, ADMIN).await;
        invite(&store, &peer(0)).await;
        assert!(held(&store, ADMIN).await);
        assert!(
            held(&store, &peer(0)).await,
            "the admin does not use the slot"
        );

        invite(&store, &peer(1)).await;
        assert!(held(&store, ADMIN).await);
        assert!(!held(&store, &peer(0)).await);
        assert!(held(&store, &peer(1)).await);
    }

    /// The store tells health when it is at its limit, and stops once it is
    /// not.
    #[tokio::test]
    async fn health_reports_a_full_store_while_it_is_full() {
        let dir = tempfile::tempdir().unwrap();
        let messaging = MessagingStore::open(dir.path().to_str().unwrap()).unwrap();
        let health = Arc::new(RegistryHealth::new(true));
        let store = open(&messaging, 1, Some(health.clone())).await;
        assert_eq!(health.to_json()["tspRelationships"], "ok");

        invite(&store, &peer(0)).await;
        assert_eq!(health.to_json()["tspRelationships"], "full");
        assert_eq!(health.to_json()["status"], "degraded");

        store.forget(US, &peer(0)).await.unwrap();
        assert_eq!(health.to_json()["tspRelationships"], "ok");
        assert_eq!(health.to_json()["status"], "OK");
    }

    /// The index survives a restart: a full store is still full after reopen.
    #[tokio::test]
    async fn the_bound_holds_across_a_reopen() {
        let dir = tempfile::tempdir().unwrap();
        {
            let messaging = MessagingStore::open(dir.path().to_str().unwrap()).unwrap();
            let store = open(&messaging, 1, None).await;
            invite(&store, &peer(0)).await;
            store.touch(US, &peer(0), 5).await.unwrap();
        }
        let messaging = MessagingStore::open(dir.path().to_str().unwrap()).unwrap();
        let store = open(&messaging, 1, None).await;
        invite(&store, &peer(1)).await;
        assert!(!held(&store, &peer(0)).await);
        assert!(held(&store, &peer(1)).await);
    }

    /// Every relationship without a stamp is stamped at startup, whatever its
    /// state, so the sweep can age it out.
    #[tokio::test]
    async fn every_unstamped_relationship_is_stamped_and_then_ages_out() {
        let (_dir, _messaging, store) = store(10).await;
        store
            .set(US, &peer(0), RelationshipState::Bidirectional)
            .await
            .unwrap();
        invite(&store, &peer(1)).await;
        // A cancelled relationship whose other records remain.
        store
            .set_reply_path(US, &peer(2), vec!["x".into()])
            .await
            .unwrap();
        store
            .set(US, &peer(2), RelationshipState::None)
            .await
            .unwrap();

        stamp_unstamped(&store).await;
        let mut stamps = Vec::new();
        for n in 0..3 {
            stamps.push(
                store
                    .last_active(US, &peer(n))
                    .await
                    .unwrap()
                    .expect("stamped"),
            );
        }
        assert!(store.backend().unstamped().await.is_empty());

        let policy = EvictionPolicy {
            ttl: Duration::from_secs(60),
        };
        let latest = stamps.into_iter().max().unwrap();
        let evicted = store.evict_idle(latest + 61_000, &policy).await.unwrap();
        assert_eq!(evicted.len(), 3);
        assert!(store.backend().index.lock().await.is_empty());
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
