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
//! - **by size and rate**: [`FjallRelationshipKv`] holds at most
//!   [`RelationshipLimits::max_relationships`] relationships, recording at most
//!   [`RelationshipLimits::max_new_per_minute`] new ones a minute. When full, a
//!   new peer may only displace a relationship that never completed, or one
//!   idle past a floor; an established relationship in use is never
//!   displaced, and when nothing can be the new one is refused. Relationships
//!   with an admin (`ADMIN_DIDS`) are exempt from both limits and never
//!   displaced. While the store is at its limit `/health` reports it
//!   (`tspRelationships: "full"`);
//! - **by age**: every relationship is stamped active when it is accepted and
//!   on each application message, and the maintenance loop evicts one idle for
//!   [`RelationshipLimits::idle_ttl`]. A relationship restored with no stamp,
//!   in whatever state, is stamped at startup, so it ages from then.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use affinidi_did_common::scid::same_reference;
use affinidi_messaging_sdk::errors::ATMError;
use affinidi_messaging_sdk::protocols::tsp::RelationshipState;
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
const FACETS: [u8; RECORDS_PER_RELATIONSHIP] = [FACET_STATE, 2, 3, 4, FACET_LAST_ACTIVE];
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

/// How large the TSP relationship store may grow, how fast, and how long an
/// idle relationship is kept.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RelationshipLimits {
    /// The most relationships with non-admin peers the store holds.
    pub max_relationships: usize,
    /// How long a relationship with no activity is kept.
    pub idle_ttl: Duration,
    /// The most relationships with new non-admin peers recorded per minute.
    pub max_new_per_minute: usize,
}

/// Default for [`RelationshipLimits::max_new_per_minute`].
pub const DEFAULT_MAX_NEW_PER_MINUTE: usize = 60;

/// The shortest time an established relationship must have been idle before a
/// new peer may displace it from a full store.
const MIN_DISPLACEMENT_IDLE: Duration = Duration::from_secs(60 * 60);

impl Default for RelationshipLimits {
    fn default() -> Self {
        Self {
            max_relationships: DEFAULT_MAX_RELATIONSHIPS,
            idle_ttl: DEFAULT_IDLE_TTL,
            max_new_per_minute: DEFAULT_MAX_NEW_PER_MINUTE,
        }
    }
}

impl RelationshipLimits {
    /// Read `TR_TSP_MAX_RELATIONSHIPS`, `TR_TSP_RELATIONSHIP_IDLE_SECS` and
    /// `TR_TSP_MAX_NEW_RELATIONSHIPS_PER_MINUTE`; each takes its default when
    /// unset. A value that is not a positive whole number, or an idle period
    /// under a minute, is an error rather than a silent default, so a typo
    /// cannot lift the bound.
    pub fn from_env() -> Result<Self, String> {
        let read = |name: &str| std::env::var(name).ok();
        Self::parse(
            read("TR_TSP_MAX_RELATIONSHIPS").as_deref(),
            read("TR_TSP_RELATIONSHIP_IDLE_SECS").as_deref(),
            read("TR_TSP_MAX_NEW_RELATIONSHIPS_PER_MINUTE").as_deref(),
        )
    }

    fn parse(
        max_relationships: Option<&str>,
        idle_secs: Option<&str>,
        max_new_per_minute: Option<&str>,
    ) -> Result<Self, String> {
        let positive = |name: &str, raw: &str| {
            raw.trim()
                .parse::<u64>()
                .ok()
                .filter(|value| *value > 0)
                .ok_or_else(|| format!("{name} must be a positive whole number, not {raw:?}"))
        };
        let count = |name: &str, raw: &str| {
            usize::try_from(positive(name, raw)?)
                .map_err(|_| format!("{name} is out of range: {raw}"))
        };
        let mut limits = Self::default();
        if let Some(raw) = max_relationships {
            limits.max_relationships = count("TR_TSP_MAX_RELATIONSHIPS", raw)?;
        }
        if let Some(raw) = max_new_per_minute {
            limits.max_new_per_minute = count("TR_TSP_MAX_NEW_RELATIONSHIPS_PER_MINUTE", raw)?;
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

    /// How long an established relationship must have been idle before a new
    /// peer may displace it from a full store: a quarter of the idle period,
    /// at least an hour, and no more than the idle period itself.
    pub fn displacement_idle(&self) -> Duration {
        (self.idle_ttl / 4)
            .max(MIN_DISPLACEMENT_IDLE)
            .min(self.idle_ttl)
    }
}

/// A [`RelationshipKv`] over the messaging store's `relationships` keyspace,
/// bounded to [`RelationshipLimits::max_relationships`] relationships with
/// non-admin peers and to
/// [`RelationshipLimits::max_new_per_minute`] new ones a minute.
///
/// Keeps an index of the relationships it holds — which records each has,
/// its state and when it was last active — built from the keyspace's keys and
/// the small state and last-activity records on open.
///
/// When the store is full, a relationship with a new peer displaces, oldest
/// first, one that never completed (an invite received and not established),
/// or failing that one idle for at least
/// [`RelationshipLimits::displacement_idle`] (the registry's own pending
/// invites are held to the same floor as established relationships). An
/// established relationship in use is never displaced: when nothing can be,
/// the new relationship is refused and `/health` reports the store full. A
/// stream of new peers therefore churns only half-open relationships, and only
/// as fast as the per-minute limit allows.
pub struct FjallRelationshipKv {
    keyspace: KvKeyspace,
    limits: RelationshipLimits,
    /// Peers whose relationships are neither counted nor displaced.
    reserved: Vec<String>,
    health: Option<Arc<RegistryHealth>>,
    /// Held across each put and delete, so the index and the keyspace move
    /// together.
    index: Mutex<Index>,
}

/// What the adapter knows about the relationships it holds.
#[derive(Default)]
struct Index {
    pairs: BTreeMap<Pair, Held>,
    /// Pairs that count against the limit (not reserved).
    counted: usize,
    /// The current one-minute window of new relationships: when it began and
    /// how many were recorded in it.
    window_started: Option<std::time::Instant>,
    new_in_window: usize,
}

/// What the index knows about one relationship.
#[derive(Debug, Clone, Copy, Default)]
struct Held {
    /// One bit per facet present.
    facets: u8,
    state: Option<RelationshipState>,
    /// When it was last stamped active, if ever.
    last_active: Option<u64>,
    reserved: bool,
}

fn facet_bit(facet: u8) -> u8 {
    1u8.checked_shl(u32::from(facet)).unwrap_or(0)
}

impl Index {
    fn insert(&mut self, pair: Pair, held: Held) {
        if !held.reserved {
            self.counted += 1;
        }
        self.pairs.insert(pair, held);
    }

    fn remove(&mut self, pair: &Pair) {
        if let Some(held) = self.pairs.remove(pair)
            && !held.reserved
        {
            self.counted = self.counted.saturating_sub(1);
        }
    }

    /// Clear `facet` of `pair`, forgetting the pair once it has none left.
    fn clear_facet(&mut self, pair: &Pair, facet: u8) {
        let empty = match self.pairs.get_mut(pair) {
            Some(held) => {
                held.facets &= !facet_bit(facet);
                if facet == FACET_LAST_ACTIVE {
                    held.last_active = None;
                }
                if facet == FACET_STATE {
                    held.state = None;
                }
                held.facets == 0
            }
            None => false,
        };
        if empty {
            self.remove(pair);
        }
    }
}

const FACET_STATE: u8 = 1;

impl FjallRelationshipKv {
    /// Open the store over `keyspace`, indexing the relationships it already
    /// holds. Relationships with a peer in `reserved` (the admin DIDs) are not
    /// counted against the limits and never displaced. `health`, when given,
    /// is told whether the store is at its limit.
    pub async fn open(
        keyspace: KvKeyspace,
        limits: RelationshipLimits,
        reserved: Vec<String>,
        health: Option<Arc<RegistryHealth>>,
    ) -> Result<Self, String> {
        let kv = Self {
            keyspace,
            limits,
            reserved,
            health,
            index: Mutex::new(Index::default()),
        };
        let mut index = Index::default();
        let mut held: BTreeMap<Pair, Held> = BTreeMap::new();
        for key in kv
            .keyspace
            .scan_keys_prefix(REL_KEY_PREFIX.to_vec())
            .await?
        {
            if let Some((facet, pair)) = decode_key(&key) {
                held.entry(pair).or_default().facets |= facet_bit(facet);
            }
        }
        for facet in [FACET_STATE, FACET_LAST_ACTIVE] {
            let mut prefix = REL_KEY_PREFIX.to_vec();
            prefix.push(facet);
            for (key, value) in kv.keyspace.scan_prefix(prefix).await? {
                let Some((_, pair)) = decode_key(&key) else {
                    continue;
                };
                let entry = held.entry(pair).or_default();
                if facet == FACET_STATE {
                    entry.state = serde_json::from_slice(&value).ok();
                } else {
                    entry.last_active = serde_json::from_slice(&value).ok();
                }
            }
        }
        for (pair, mut entry) in held {
            entry.reserved = kv.is_reserved(&pair);
            index.insert(pair, entry);
        }
        if index.counted >= limits.max_relationships {
            warn!(
                held = index.counted,
                max_relationships = limits.max_relationships,
                "the TSP relationship store is full"
            );
        }
        kv.report(&index);
        *kv.index.lock().await = index;
        Ok(kv)
    }

    fn is_reserved(&self, (_, their): &Pair) -> bool {
        self.reserved
            .iter()
            .any(|admin| same_reference(admin, their))
    }

    fn report(&self, index: &Index) {
        if let Some(health) = &self.health {
            health.set_tsp_relationships_full(index.counted >= self.limits.max_relationships);
        }
    }

    /// The relationships held with no activity stamp, whatever their state.
    pub async fn unstamped(&self) -> Vec<(String, String)> {
        self.index
            .lock()
            .await
            .pairs
            .iter()
            .filter(|(_, held)| held.last_active.is_none())
            .map(|(pair, _)| pair.clone())
            .collect()
    }

    /// The relationship a new peer may displace from a full store, if any:
    /// the oldest that never completed (an invite received, or state left
    /// unset), else the oldest whose last activity is older than the
    /// displacement floor. An established relationship or a pending invite of
    /// our own that is in use is never chosen.
    fn displaceable(&self, index: &Index, now_ms: u64) -> Option<Pair> {
        let floor_ms =
            u64::try_from(self.limits.displacement_idle().as_millis()).unwrap_or(u64::MAX);
        let idle = |held: &Held| {
            held.last_active
                .is_none_or(|at| now_ms.saturating_sub(at) >= floor_ms)
        };
        let half_open = |held: &Held| {
            !matches!(
                held.state,
                Some(RelationshipState::Bidirectional | RelationshipState::Pending)
            )
        };
        let oldest = |eligible: &dyn Fn(&Held) -> bool| {
            index
                .pairs
                .iter()
                .filter(|(_, held)| !held.reserved && eligible(held))
                .min_by_key(|(_, held)| held.last_active.unwrap_or(0))
                .map(|(pair, _)| pair.clone())
        };
        oldest(&half_open).or_else(|| oldest(&idle))
    }

    /// Forget `victim`'s records, keeping the index in step with each one.
    async fn forget(&self, index: &mut Index, victim: &Pair) -> Result<(), ATMError> {
        for facet in FACETS {
            self.keyspace
                .delete(encode_key(facet, victim))
                .await
                .map_err(|e| ATMError::SDKError(format!("relationships keyspace delete: {e}")))?;
            index.clear_facet(victim, facet);
        }
        Ok(())
    }

    /// Admit a relationship with a new, non-reserved peer: within the
    /// per-minute limit, and into a full store only by displacing one that
    /// may be ([`displaceable`](Self::displaceable)).
    async fn admit(&self, index: &mut Index, their: &str) -> Result<(), ATMError> {
        let now = std::time::Instant::now();
        let window_open = index
            .window_started
            .is_some_and(|started| now.duration_since(started) < Duration::from_secs(60));
        if !window_open {
            index.window_started = Some(now);
            index.new_in_window = 0;
        }
        if index.new_in_window >= self.limits.max_new_per_minute {
            warn!(
                peer = their,
                max_new_per_minute = self.limits.max_new_per_minute,
                "not recording a TSP relationship: too many new relationships this minute"
            );
            return Err(ATMError::SDKError(
                "too many new TSP relationships this minute".to_string(),
            ));
        }
        if index.counted >= self.limits.max_relationships {
            let Some(victim) = self.displaceable(index, unix_millis().unwrap_or(0)) else {
                warn!(
                    peer = their,
                    max_relationships = self.limits.max_relationships,
                    "the TSP relationship store is full of relationships in use; not recording \
                     a new one"
                );
                return Err(ATMError::SDKError(format!(
                    "the TSP relationship store is full ({} relationships)",
                    self.limits.max_relationships
                )));
            };
            self.forget(index, &victim).await?;
            info!(
                peer = %victim.1,
                "the TSP relationship store is full; displaced a half-open or idle relationship"
            );
        }
        index.new_in_window += 1;
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
        if let Some((facet, pair)) = &decoded
            && !index.pairs.contains_key(pair)
        {
            // An activity stamp for a relationship that is not held (one
            // forgotten while the stamp was on its way) records nothing:
            // it must not bring the relationship back, or displace another.
            if *facet == FACET_LAST_ACTIVE {
                return Ok(());
            }
            if !self.is_reserved(pair) {
                let result = self.admit(&mut index, &pair.1).await;
                self.report(&index);
                result?;
            }
        }
        self.keyspace
            .put(key.to_vec(), value.to_vec())
            .await
            .map_err(|e| ATMError::SDKError(format!("relationships keyspace put: {e}")))?;
        if let Some((facet, pair)) = decoded {
            if !index.pairs.contains_key(&pair) {
                let reserved = self.is_reserved(&pair);
                index.insert(
                    pair.clone(),
                    Held {
                        reserved,
                        ..Held::default()
                    },
                );
            }
            if let Some(held) = index.pairs.get_mut(&pair) {
                held.facets |= facet_bit(facet);
                match facet {
                    FACET_LAST_ACTIVE => {
                        held.last_active = serde_json::from_slice(value).ok().or(held.last_active);
                    }
                    FACET_STATE => held.state = serde_json::from_slice(value).ok(),
                    _ => {}
                }
            }
        }
        self.report(&index);
        Ok(())
    }

    async fn delete(&self, key: &[u8]) -> Result<(), ATMError> {
        let mut index = self.index.lock().await;
        if self.raw_get(key).await?.is_some() {
            self.keyspace
                .delete(key.to_vec())
                .await
                .map_err(|e| ATMError::SDKError(format!("relationships keyspace delete: {e}")))?;
        }
        // Reconciled whether or not the record was there.
        if let Some((facet, pair)) = decode_key(key) {
            index.clear_facet(&pair, facet);
        }
        self.report(&index);
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
    use tempfile::TempDir;

    const US: &str = "did:example:registry";
    const ADMIN: &str = "did:example:admin";

    fn limits(max_relationships: usize, max_new_per_minute: usize) -> RelationshipLimits {
        RelationshipLimits {
            max_relationships,
            max_new_per_minute,
            ..RelationshipLimits::default()
        }
    }

    async fn open(
        messaging: &MessagingStore,
        limits: RelationshipLimits,
        health: Option<Arc<RegistryHealth>>,
    ) -> RegistryRelationshipStore {
        let kv = FjallRelationshipKv::open(
            messaging.relationships.clone(),
            limits,
            vec![ADMIN.to_string()],
            health,
        )
        .await
        .unwrap();
        PersistentRelationshipStore::new(kv)
    }

    async fn store(
        limits: RelationshipLimits,
    ) -> (TempDir, MessagingStore, RegistryRelationshipStore) {
        let dir = tempfile::tempdir().unwrap();
        let messaging = MessagingStore::open(dir.path().to_str().unwrap()).unwrap();
        let store = open(&messaging, limits, None).await;
        (dir, messaging, store)
    }

    fn peer(n: usize) -> String {
        format!("did:example:peer-{n}")
    }

    fn now_ms() -> u64 {
        unix_millis().unwrap()
    }

    /// Record an inbound invite the way the transport does: the state alone.
    async fn invite(store: &RegistryRelationshipStore, their: &str) -> Result<(), ATMError> {
        store
            .set(US, their, RelationshipState::InviteReceived)
            .await
    }

    /// An established relationship last active at `at`.
    async fn establish(store: &RegistryRelationshipStore, their: &str, at: u64) {
        store
            .set(US, their, RelationshipState::Bidirectional)
            .await
            .unwrap();
        store.touch(US, their, at).await.unwrap();
    }

    async fn held(store: &RegistryRelationshipStore, their: &str) -> bool {
        store.get(US, their).await.unwrap() != RelationshipState::None
    }

    /// The adapter's reading of the key layout matches the keys the SDK
    /// writes, for every facet.
    #[tokio::test]
    async fn the_key_layout_matches_the_sdk() {
        let (_dir, messaging, store) = store(limits(10, 10)).await;
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
        let index = store.backend().index.lock().await;
        let entry = index.pairs[&(US.to_string(), their)];
        assert_eq!(entry.last_active, Some(7));
        assert_eq!(entry.state, Some(RelationshipState::Bidirectional));
    }

    /// A stream of invites from fresh VIDs churns only half-open
    /// relationships: an established peer in use survives it.
    #[tokio::test]
    async fn an_active_peer_survives_ten_thousand_fresh_invites() {
        let (_dir, _messaging, store) = store(limits(100, usize::MAX)).await;
        establish(&store, "did:example:member", now_ms()).await;
        for n in 0..10_000 {
            invite(&store, &peer(n)).await.unwrap();
        }
        assert!(held(&store, "did:example:member").await);
        assert_eq!(store.backend().index.lock().await.counted, 100);
    }

    /// When nothing can be displaced the new relationship is refused, and the
    /// store does not grow.
    #[tokio::test]
    async fn a_store_full_of_active_relationships_refuses_a_new_one() {
        let (_dir, _messaging, store) = store(limits(2, usize::MAX)).await;
        establish(&store, &peer(0), now_ms()).await;
        establish(&store, &peer(1), now_ms()).await;

        assert!(invite(&store, &peer(2)).await.is_err());
        assert!(!held(&store, &peer(2)).await);
        assert!(held(&store, &peer(0)).await);
        assert!(held(&store, &peer(1)).await);
    }

    /// An established relationship idle past the floor may be displaced,
    /// oldest first; one in use may not.
    #[tokio::test]
    async fn an_idle_established_relationship_may_be_displaced() {
        let (_dir, _messaging, store) = store(limits(2, usize::MAX)).await;
        establish(&store, &peer(0), now_ms()).await;
        establish(&store, &peer(1), 1).await;

        invite(&store, &peer(2)).await.unwrap();
        assert!(held(&store, &peer(0)).await);
        assert!(!held(&store, &peer(1)).await, "the idle one is displaced");
        assert!(held(&store, &peer(2)).await);
    }

    /// No more than the per-minute number of new relationships are recorded,
    /// whatever room there is; admins are not limited.
    #[tokio::test]
    async fn new_relationships_are_limited_per_minute() {
        let (_dir, _messaging, store) = store(limits(100, 3)).await;
        for n in 0..3 {
            invite(&store, &peer(n)).await.unwrap();
        }
        assert!(invite(&store, &peer(3)).await.is_err());
        invite(&store, ADMIN)
            .await
            .expect("an admin is not limited");
        store
            .set_reply_path(US, &peer(0), vec!["x".into()])
            .await
            .expect("a held relationship is not new");
    }

    /// Admin relationships are not counted and never displaced.
    #[tokio::test]
    async fn an_admin_relationship_is_kept_and_not_counted() {
        let (_dir, _messaging, store) = store(limits(1, usize::MAX)).await;
        invite(&store, ADMIN).await.unwrap();
        invite(&store, &peer(0)).await.unwrap();
        assert!(held(&store, ADMIN).await);
        assert!(
            held(&store, &peer(0)).await,
            "the admin does not use the slot"
        );

        invite(&store, &peer(1)).await.unwrap();
        assert!(held(&store, ADMIN).await);
        assert!(!held(&store, &peer(0)).await);
        assert!(held(&store, &peer(1)).await);
    }

    /// A stamp for a relationship no longer held records nothing, so it
    /// cannot bring it back or displace another.
    #[tokio::test]
    async fn a_stamp_for_a_forgotten_relationship_records_nothing() {
        let (_dir, messaging, store) = store(limits(1, usize::MAX)).await;
        establish(&store, &peer(0), now_ms()).await;

        mark_active(&store, US, &peer(1)).await;
        store.touch(US, &peer(1), now_ms()).await.unwrap();

        assert!(held(&store, &peer(0)).await);
        assert_eq!(store.last_active(US, &peer(1)).await.unwrap(), None);
        assert_eq!(
            messaging
                .relationships
                .scan_keys_prefix(Vec::new())
                .await
                .unwrap()
                .len(),
            2
        );
    }

    /// Deleting a record that is already gone still brings the index in step.
    #[tokio::test]
    async fn deleting_an_absent_record_reconciles_the_index() {
        let (_dir, messaging, store) = store(limits(10, 10)).await;
        invite(&store, &peer(0)).await.unwrap();
        messaging
            .relationships
            .delete(encode_key(FACET_STATE, &(US.to_string(), peer(0))))
            .await
            .unwrap();
        assert_eq!(store.backend().index.lock().await.counted, 1);

        store.forget(US, &peer(0)).await.unwrap();
        let index = store.backend().index.lock().await;
        assert!(index.pairs.is_empty());
        assert_eq!(index.counted, 0);
    }

    /// The store tells health when it is at its limit, and stops once it is
    /// not.
    #[tokio::test]
    async fn health_reports_a_full_store_while_it_is_full() {
        let dir = tempfile::tempdir().unwrap();
        let messaging = MessagingStore::open(dir.path().to_str().unwrap()).unwrap();
        let health = Arc::new(RegistryHealth::new(true));
        let store = open(&messaging, limits(1, usize::MAX), Some(health.clone())).await;
        assert_eq!(health.to_json()["tspRelationships"], "ok");

        establish(&store, &peer(0), now_ms()).await;
        assert_eq!(health.to_json()["tspRelationships"], "full");
        assert_eq!(health.to_json()["status"], "degraded");
        assert!(invite(&store, &peer(1)).await.is_err());

        store.forget(US, &peer(0)).await.unwrap();
        assert_eq!(health.to_json()["tspRelationships"], "ok");
        assert_eq!(health.to_json()["status"], "OK");
    }

    /// The index survives a restart: state, activity and count.
    #[tokio::test]
    async fn the_index_survives_a_reopen() {
        let dir = tempfile::tempdir().unwrap();
        {
            let messaging = MessagingStore::open(dir.path().to_str().unwrap()).unwrap();
            let store = open(&messaging, limits(1, usize::MAX), None).await;
            establish(&store, &peer(0), now_ms()).await;
        }
        let messaging = MessagingStore::open(dir.path().to_str().unwrap()).unwrap();
        let store = open(&messaging, limits(1, usize::MAX), None).await;
        assert!(
            invite(&store, &peer(1)).await.is_err(),
            "still full of a peer in use"
        );
        assert!(held(&store, &peer(0)).await);
    }

    /// Every relationship without a stamp is stamped at startup, whatever its
    /// state, so the sweep can age it out.
    #[tokio::test]
    async fn every_unstamped_relationship_is_stamped_and_then_ages_out() {
        let (_dir, _messaging, store) = store(limits(10, 10)).await;
        store
            .set(US, &peer(0), RelationshipState::Bidirectional)
            .await
            .unwrap();
        invite(&store, &peer(1)).await.unwrap();
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
        assert!(store.backend().index.lock().await.pairs.is_empty());
    }

    #[test]
    fn limits_default_when_unset() {
        assert_eq!(
            RelationshipLimits::parse(None, None, None).unwrap(),
            RelationshipLimits::default()
        );
    }

    #[test]
    fn limits_are_read_from_their_settings() {
        let limits = RelationshipLimits::parse(Some("50"), Some("3600"), Some("5")).unwrap();
        assert_eq!(limits.max_relationships, 50);
        assert_eq!(limits.idle_ttl, Duration::from_secs(3600));
        assert_eq!(limits.max_new_per_minute, 5);
        assert_eq!(limits.sweep_interval(), Duration::from_secs(1800));
        assert_eq!(limits.displacement_idle(), Duration::from_secs(3600));
        assert_eq!(
            RelationshipLimits::default().sweep_interval(),
            MAX_SWEEP_INTERVAL
        );
        assert_eq!(
            RelationshipLimits::default().displacement_idle(),
            DEFAULT_IDLE_TTL / 4
        );
    }

    #[test]
    fn malformed_limits_are_an_error() {
        for (max, idle, rate) in [
            (Some("0"), None, None),
            (Some("many"), None, None),
            (Some("-1"), None, None),
            (None, Some("0"), None),
            (None, Some("59"), None),
            (None, Some("1h"), None),
            (None, None, Some("0")),
            (None, None, Some("lots")),
        ] {
            assert!(
                RelationshipLimits::parse(max, idle, rate).is_err(),
                "{max:?} / {idle:?} / {rate:?} should be refused"
            );
        }
    }
}
