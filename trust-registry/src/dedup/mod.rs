//! Message-id deduplication for the Trust Tasks executed at most once (R1.4).
//!
//! DIDComm and TSP are at-least-once: the mediator redelivers anything it has
//! not seen acked, and the offline-sync poller re-fetches and re-dispatches a
//! whole batch every 30s when its ack fails. Without dedup that means duplicate
//! record mutations and duplicate responses — and it is why the TSP receive path
//! still deletes frames before handling them ([`crate::tsp`]): redelivery could
//! not recover a write, only double it.
//!
//! ## What is deduplicated
//!
//! Every task whose [`descriptor`](crate::trust_tasks::descriptor) gives it a
//! replay record, and every capability write: the writes go through the one
//! store shared by every binding, and `registry/record/query` through a
//! separate store of its own, so queries cannot use up the capacity writes
//! need. The [`TaskHandler`](crate::trust_tasks::TaskHandler) picks the store
//! and calls [`execute_once`]. The public TRQP queries are naturally
//! idempotent and do not go through a store.
//!
//! ## Claim protocol
//!
//! Check-then-act is not enough: a redelivery can arrive while the first copy is
//! still in flight, and both would pass a bare "have I seen this?" test. So the
//! store *claims* an id atomically before dispatch and resolves the claim after:
//!
//! ```text
//!   claim(key, digest) ->  Acquired(t) -> dispatch -> complete(key, t, outcome)
//!                      ->  Replay(o)   -> return the original response, do not dispatch
//!                      ->  InFlight    -> reject as retryable; the sender re-sends and
//!                                         finds Replay once the first copy resolves
//!                      ->  Conflict    -> the id was accepted for a different
//!                                         document: reject as `idConflict`
//! ```
//!
//! [`execute_once`] reports which of these happened ([`Disposition`]) beside
//! the outcome, so the audit entry of a replayed or in-flight duplicate does
//! not read as a second execution.
//!
//! A claim is a **lease**: it lapses after the in-flight lease
//! ([`DEFAULT_IN_FLIGHT_TTL`], `TR_DEDUP_IN_FLIGHT_LEASE_SEC`) unless resolved
//! first, so an id whose claimant died is not blocked until the document
//! expires. Each claim carries a [`ClaimToken`]; `complete` and `release` act
//! only for the claim that holds the id, so a claimant whose lease lapsed and
//! was taken over cannot overwrite or free the new claimant's entry.
//!
//! ## The exact guarantee
//!
//! - A document is executed **once** when its claimant stores the outcome:
//!   every later copy inside the retention gets that outcome verbatim, on any
//!   binding, and (with a durable store) on any replica and after a restart.
//! - A copy arriving while the first is executing is refused as retryable and
//!   is not executed.
//! - The write and the stored outcome are two steps. If the claimant stops
//!   between them (the process dies, the store cannot be reached for every
//!   retry of `complete`, the handler panics), the claim lapses after the
//!   lease (immediately, for a panic) and a later copy **executes again**.
//!   That re-execution sees the first one's effect: `registry/record/put`
//!   without `expectedExisting` is an upsert and converges (answering
//!   `wasCreated: false`); a strict create answers "already exists" and a
//!   delete "not found", although the first execution succeeded. Whatever the
//!   re-execution answers is then stored, so every copy after it gets that
//!   same answer. Nothing executes a third time unless the same failure
//!   happens again.
//!
//! ## The record of accepted identifiers (VTI-OPS-025..027)
//!
//! This store is the registry's record of accepted document identifiers. One
//! store is shared by every binding that carries writes (DIDComm, TSP and a
//! host driving the registry), so a document accepted on one binding is not
//! executed again on another. Its retention ([`DEFAULT_TTL`]) must be at least
//! the write acceptance window
//! ([`WRITE_ACCEPTANCE_WINDOW`](crate::trust_tasks::handler::WRITE_ACCEPTANCE_WINDOW)):
//! a document older than the window is refused on its time of issue, so it
//! never needs to be remembered for longer.
//!
//! A write is refused rather than executed when the store cannot be
//! consulted: without the record there is no replay protection.
//!
//! Implementations:
//!
//! - [`MemoryMessageIdStore`]: per process, lost on restart. Used with the
//!   CSV and in-memory record backends, and whenever a host passes a
//!   repository without a durable store of its own.
//! - `redis::RedisMessageIdStore` (feature `storage-redis`), shared by every
//!   replica on one Redis.
//! - `dynamodb::DynamoDbMessageIdStore` (feature `storage-ddb`), shared by every
//!   replica on one table.
//! - `fjall::FjallMessageIdStore` (feature `storage-fjall`), in the record
//!   database, surviving a restart.
//!
//! The record backends hand out theirs through
//! [`TrustRecordAdminRepository::message_id_store`](crate::storage::repository::TrustRecordAdminRepository::message_id_store),
//! which the [`TrustRegistryBuilder`](crate::TrustRegistryBuilder) uses by
//! default. Every implementation passes the suite in `dedup::conformance`.
//!
//! A duplicate that arrives after completion replays the **stored response**
//! rather than being silently dropped. At-least-once exists because responses
//! get lost too; a sender whose response vanished needs the answer on retry, not
//! silence.
//!
//! ## What is not cached
//!
//! Rejections the framework marks **retryable** release the claim instead of
//! being stored. SPEC §8.4 sets that flag for exactly the transient codes
//! (`unavailable`, `internalError`), which is where a repository
//! `ConnectionFailed` / `QueryFailed` / `LockPoisoned` lands via
//! `trust_tasks::router::map_repo_err`. Caching one would answer every
//! redelivery with a stale database error for the whole TTL. Deterministic
//! rejections by the task itself (a malformed record, a strict create of a key
//! that exists) are properties of the document and replay correctly. The
//! checks that decide whether a document may run at all (freshness, proof,
//! admin, authority) are made before the claim, so their refusals never reach
//! the store.

// `TaskOutcome`'s error is a whole `trust-task-error` document, which is large
// by design; boxing it would only move the allocation onto every caller. The
// router allows this lint for the same reason.
#![allow(clippy::result_large_err)]

#[cfg(test)]
pub(crate) mod conformance;
#[cfg(feature = "storage-ddb")]
pub mod dynamodb;
#[cfg(feature = "storage-fjall")]
pub mod fjall;
#[cfg(feature = "storage-redis")]
pub mod redis;

use std::collections::{HashMap, VecDeque};
use std::sync::Mutex;
use std::time::Duration;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use futures::FutureExt;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use trust_tasks_rs::{ErrorResponse, RejectReason, TrustTask, document_digest};
use uuid::Uuid;

use crate::configs::MessageIdStoreConfig;
use crate::trust_tasks::TaskOutcome;

/// How long a completed outcome stays replayable: the write acceptance window
/// (five minutes of age, one of future skew) plus a minute of margin.
///
/// It only has to cover that window. A document older than it is refused on
/// its time of issue before the record is consulted, so a redelivery that
/// arrives after its entry has expired is refused as `expired`, never applied
/// again. Keeping entries longer would only hold capacity that bounds new
/// writes. `TR_DEDUP_RETENTION_SEC` sets it.
pub const DEFAULT_TTL: Duration = Duration::from_secs(7 * 60);

/// Bounds of the record kept for `registry/record/query` documents, which is
/// separate from the one for writes so that queries cannot use up the
/// capacity writes need.
pub const DEFAULT_QUERY_MAX_ENTRIES: usize = 10_000;
/// Per-issuer bound of the query record.
pub const DEFAULT_QUERY_MAX_ENTRIES_PER_ISSUER: usize = 1_000;

/// How long an unresolved claim is honoured before another copy may take it.
///
/// A process that dies mid-dispatch, or a store that cannot be reached to
/// record the outcome, would otherwise leave an `InFlight` marker that blocks
/// its message id until the document expires. Two minutes is far above any
/// realistic handler runtime (a copy re-executes only if the first is still
/// running when the lease lapses) and leaves most of the five-minute
/// acceptance window for a retry to get a definite answer.
/// `TR_DEDUP_IN_FLIGHT_LEASE_SEC` sets it.
pub const DEFAULT_IN_FLIGHT_TTL: Duration = Duration::from_secs(2 * 60);

#[derive(Debug, thiserror::Error)]
pub enum DedupError {
    #[error("dedup store unavailable: {0}")]
    Unavailable(String),
    /// The store is at its bound and refuses new claims rather than forget
    /// accepted ones.
    #[error("dedup store at capacity: {0}")]
    CapacityReached(String),
    /// `complete` for a claim that no longer holds the id: its lease lapsed
    /// and another copy claimed (or completed) it. The other copy's entry is
    /// left as it is.
    #[error("dedup claim lost: {0}")]
    ClaimLost(String),
}

/// Storage key for a document: `MID#<issuer>#<id>`.
///
/// Composed with the issuer, not the bare `id`, so one sender cannot occupy
/// another's id space — whether by accident (a client with a weak id generator)
/// or deliberately (claiming an id to suppress somebody else's write). The
/// `MID#` prefix keeps these clear of the `TR#` namespace every backend's
/// `list()` scans.
///
/// The issuer is taken in its normalised form (a did:scid without its `?src=`
/// locator), so one document id under the two spellings of one issuer is one
/// key.
pub fn message_key(doc: &TrustTask<Value>) -> String {
    let issuer = doc.issuer.as_deref().unwrap_or("anonymous");
    let issuer = affinidi_did_common::scid::strip_scid_src(issuer);
    format!("MID#{issuer}#{}", doc.id)
}

/// A completed outcome, in a form every backend can persist.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "lowercase")]
pub enum StoredOutcome {
    Completed(TrustTask<Value>),
    Rejected(ErrorResponse),
}

impl StoredOutcome {
    pub fn from_outcome(outcome: &TaskOutcome) -> Self {
        match outcome {
            Ok(response) => Self::Completed(response.clone()),
            Err(error) => Self::Rejected(error.clone()),
        }
    }

    // `TaskOutcome` is the crate-wide alias every handler already returns; its
    // `Err` variant is a full `ErrorResponse` document by design. Boxing it here
    // alone would just force an unwrap at every call site.
    #[allow(clippy::result_large_err)]
    pub fn into_outcome(self) -> TaskOutcome {
        match self {
            Self::Completed(response) => Ok(response),
            Self::Rejected(error) => Err(error),
        }
    }
}

/// Identifies one claim of a message id, so that only that claim can resolve
/// it ([`MessageIdStore::complete`], [`MessageIdStore::release`]).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ClaimToken(String);

impl ClaimToken {
    /// A fresh, unique token.
    pub fn new() -> Self {
        Self(Uuid::new_v4().to_string())
    }

    /// A token as a store persisted it.
    pub fn from_stored(token: impl Into<String>) -> Self {
        Self(token.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Default for ClaimToken {
    fn default() -> Self {
        Self::new()
    }
}

/// Result of attempting to claim a message id.
#[derive(Debug)]
pub enum Claim {
    /// The caller owns this id and must resolve it with `complete` or
    /// `release`, passing this token.
    Acquired(ClaimToken),
    /// Already handled — replay this outcome without dispatching.
    Replay(Box<StoredOutcome>),
    /// Another copy holds the claim right now.
    InFlight,
    /// The id was already claimed for a document with different content.
    Conflict,
}

/// Claim/replay store for message ids.
#[async_trait]
pub trait MessageIdStore: Send + Sync {
    /// Atomically claim `key` for the document whose content identity is
    /// `digest`, or report why it could not be claimed.
    ///
    /// A key already held for a different `digest` MUST yield
    /// [`Claim::Conflict`], never a replay of the other document's outcome.
    /// An in-flight claim older than the store's lease, and an outcome older
    /// than its retention, MUST be treated as absent.
    ///
    /// Implementations MUST make this atomic against concurrent callers (for
    /// a shared store, a conditional put such as `SET NX`). The check-then-set
    /// pattern the record backends use for `create` is **not** sufficient here.
    async fn claim(&self, key: &str, digest: &str) -> Result<Claim, DedupError>;

    /// Resolve the claim `token` names with the outcome to replay for later
    /// duplicates, kept for the store's retention.
    ///
    /// Stores the outcome when that claim still holds `key`. A store may keep
    /// a lapsed claim until another copy claims the id, and then completes it
    /// too. When the claim no longer holds `key` (another copy claimed or
    /// completed it, or the lapsed claim is gone), changes nothing and
    /// returns [`DedupError::ClaimLost`].
    async fn complete(
        &self,
        key: &str,
        token: &ClaimToken,
        outcome: &StoredOutcome,
    ) -> Result<(), DedupError>;

    /// Abandon the claim `token` names so a retry may take it (transient
    /// failures only). Does nothing when that claim no longer holds `key`.
    async fn release(&self, key: &str, token: &ClaimToken) -> Result<(), DedupError>;
}

enum Entry {
    InFlight {
        digest: String,
        claimed_at: DateTime<Utc>,
        token: ClaimToken,
    },
    Done {
        digest: String,
        // Boxed: a stored outcome is a full Trust Task document, dwarfing the
        // timestamp in the `InFlight` variant.
        outcome: Box<StoredOutcome>,
        expires_at: DateTime<Utc>,
    },
}

/// Most documents one issuer may have in the in-memory record at once.
pub const DEFAULT_MAX_ENTRIES_PER_ISSUER: usize = 10_000;

/// Most documents the in-memory record holds at once, across all issuers.
pub const DEFAULT_MAX_ENTRIES: usize = 100_000;

/// The issuer part of a [`message_key`].
fn key_issuer(key: &str) -> &str {
    key.strip_prefix("MID#")
        .and_then(|rest| rest.split_once('#'))
        .map_or("", |(issuer, _)| issuer)
}

fn chrono_duration(duration: Duration) -> chrono::Duration {
    chrono::Duration::from_std(duration).unwrap_or(chrono::Duration::MAX)
}

/// The record kept in process memory: entries, their expiry queues and the
/// per-issuer counts. The in-memory store is this behind a lock; the fjall
/// store also persists its outcomes.
#[derive(Default)]
pub(crate) struct Inner {
    entries: HashMap<String, Entry>,
    /// Claims in the order they were made, which is the order their in-flight
    /// window closes in. An item whose entry has since completed, been
    /// released or been re-claimed is stale and skipped.
    in_flight_order: VecDeque<(DateTime<Utc>, String)>,
    /// Completions in the order they were made, which is expiry order.
    done_order: VecDeque<(DateTime<Utc>, String)>,
    per_issuer: HashMap<String, usize>,
}

impl Inner {
    fn remove(&mut self, key: &str) {
        if self.entries.remove(key).is_some() {
            let issuer = key_issuer(key);
            if let Some(count) = self.per_issuer.get_mut(issuer) {
                *count -= 1;
                if *count == 0 {
                    self.per_issuer.remove(issuer);
                }
            }
        }
    }

    fn insert(&mut self, key: &str, entry: Entry) {
        if self.entries.insert(key.to_string(), entry).is_none() {
            *self
                .per_issuer
                .entry(key_issuer(key).to_string())
                .or_insert(0) += 1;
        }
    }

    /// Drop what has expired, oldest first, and return the keys of the
    /// outcomes dropped. Each queue item is looked at once, so the cost is
    /// amortised over the claims that created them.
    pub(crate) fn evict_expired(&mut self, now: DateTime<Utc>, in_flight: Duration) -> Vec<String> {
        let in_flight = chrono_duration(in_flight);
        while let Some((claimed_at, key)) = self.in_flight_order.front().cloned() {
            if now.signed_duration_since(claimed_at) < in_flight {
                break;
            }
            self.in_flight_order.pop_front();
            if matches!(
                self.entries.get(&key),
                Some(Entry::InFlight { claimed_at: held, .. }) if *held == claimed_at
            ) {
                self.remove(&key);
            }
        }
        let mut expired = Vec::new();
        while let Some((expires_at, key)) = self.done_order.front().cloned() {
            if expires_at > now {
                break;
            }
            self.done_order.pop_front();
            if matches!(
                self.entries.get(&key),
                Some(Entry::Done { expires_at: held, .. }) if *held == expires_at
            ) {
                self.remove(&key);
                expired.push(key);
            }
        }
        expired
    }

    /// Claim `key`, under the bounds of `config`. Expired entries must have
    /// been evicted first.
    pub(crate) fn claim(
        &mut self,
        key: &str,
        digest: &str,
        now: DateTime<Utc>,
        config: &MessageIdStoreConfig,
    ) -> Result<Claim, DedupError> {
        match self.entries.get(key) {
            Some(Entry::Done { digest: held, .. } | Entry::InFlight { digest: held, .. })
                if held != digest =>
            {
                return Ok(Claim::Conflict);
            }
            Some(Entry::Done { outcome, .. }) => return Ok(Claim::Replay(outcome.clone())),
            Some(Entry::InFlight { .. }) => return Ok(Claim::InFlight),
            None => {}
        }

        let issuer = key_issuer(key);
        if self.entries.len() >= config.max_entries {
            return Err(DedupError::CapacityReached(
                "the record of accepted documents is full".to_string(),
            ));
        }
        if self.per_issuer.get(issuer).copied().unwrap_or(0) >= config.max_entries_per_issuer {
            return Err(DedupError::CapacityReached(format!(
                "{issuer} has too many documents in the record of accepted documents"
            )));
        }
        let token = ClaimToken::new();
        self.insert(
            key,
            Entry::InFlight {
                digest: digest.to_string(),
                claimed_at: now,
                token: token.clone(),
            },
        );
        self.in_flight_order.push_back((now, key.to_string()));
        Ok(Claim::Acquired(token))
    }

    /// Resolve the claim `token` names with `outcome` until `expires_at`, by
    /// the rule of [`MessageIdStore::complete`]. Returns the digest stored.
    pub(crate) fn complete(
        &mut self,
        key: &str,
        token: &ClaimToken,
        outcome: &StoredOutcome,
        expires_at: DateTime<Utc>,
    ) -> Result<String, DedupError> {
        let digest = match self.entries.get(key) {
            Some(Entry::InFlight {
                digest,
                token: held,
                ..
            }) if held == token => digest.clone(),
            Some(_) => {
                return Err(DedupError::ClaimLost(format!(
                    "{key} is held by another claim"
                )));
            }
            None => {
                return Err(DedupError::ClaimLost(format!("the claim on {key} lapsed")));
            }
        };
        self.insert(
            key,
            Entry::Done {
                digest: digest.clone(),
                outcome: Box::new(outcome.clone()),
                expires_at,
            },
        );
        self.done_order.push_back((expires_at, key.to_string()));
        Ok(digest)
    }

    /// The digest of the claim `token` names, when it still holds `key`.
    // Used by the fjall store only.
    #[cfg_attr(not(feature = "storage-fjall"), allow(dead_code))]
    pub(crate) fn held_by(&self, key: &str, token: &ClaimToken) -> Option<String> {
        match self.entries.get(key) {
            Some(Entry::InFlight {
                digest,
                token: held,
                ..
            }) if held == token => Some(digest.clone()),
            _ => None,
        }
    }

    pub(crate) fn release(&mut self, key: &str, token: &ClaimToken) {
        if matches!(
            self.entries.get(key),
            Some(Entry::InFlight { token: held, .. }) if held == token
        ) {
            self.remove(key);
        }
    }

    /// Restore an outcome persisted by an earlier run. Callers restore in
    /// expiry order.
    #[cfg_attr(not(feature = "storage-fjall"), allow(dead_code))]
    pub(crate) fn restore(
        &mut self,
        key: &str,
        digest: String,
        outcome: StoredOutcome,
        expires_at: DateTime<Utc>,
    ) {
        self.insert(
            key,
            Entry::Done {
                digest,
                outcome: Box::new(outcome),
                expires_at,
            },
        );
        self.done_order.push_back((expires_at, key.to_string()));
    }
}

/// In-memory store: correct dedup semantics, no durability.
///
/// Used with the CSV and in-memory record backends. Its state is lost on
/// restart, which the acceptance window bounds: a document older than
/// [`DEFAULT_TTL`] is refused on its time of issue. It is also local to one
/// process: replicas of a registry do not share it.
///
/// Bounded: at [`DEFAULT_MAX_ENTRIES`] in total, or
/// [`DEFAULT_MAX_ENTRIES_PER_ISSUER`] for one issuer, a new claim is refused
/// rather than evicting an entry, since forgetting an accepted document would
/// let it be replayed.
pub struct MemoryMessageIdStore {
    config: MessageIdStoreConfig,
    inner: Mutex<Inner>,
}

impl MemoryMessageIdStore {
    pub fn new(ttl: Duration, in_flight_ttl: Duration) -> Self {
        Self::from_config(MessageIdStoreConfig {
            retention: ttl,
            in_flight_lease: in_flight_ttl,
            ..MessageIdStoreConfig::default()
        })
    }

    /// A store with the retention, lease and bounds of `config`.
    pub fn from_config(config: MessageIdStoreConfig) -> Self {
        Self {
            config,
            inner: Mutex::new(Inner::default()),
        }
    }

    /// Set the total and per-issuer bounds.
    pub fn with_limits(mut self, max_entries: usize, max_entries_per_issuer: usize) -> Self {
        self.config.max_entries = max_entries;
        self.config.max_entries_per_issuer = max_entries_per_issuer;
        self
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Inner> {
        // Poison-tolerant: a panic while holding this lock must not wedge every
        // subsequent write, mirroring `MemoryCapabilityStore`.
        self.inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

impl Default for MemoryMessageIdStore {
    fn default() -> Self {
        Self::from_config(MessageIdStoreConfig::default())
    }
}

#[async_trait]
impl MessageIdStore for MemoryMessageIdStore {
    async fn claim(&self, key: &str, digest: &str) -> Result<Claim, DedupError> {
        let now = Utc::now();
        let mut inner = self.lock();
        inner.evict_expired(now, self.config.in_flight_lease);
        inner.claim(key, digest, now, &self.config)
    }

    async fn complete(
        &self,
        key: &str,
        token: &ClaimToken,
        outcome: &StoredOutcome,
    ) -> Result<(), DedupError> {
        let expires_at = Utc::now() + chrono_duration(self.config.retention);
        self.lock()
            .complete(key, token, outcome, expires_at)
            .map(|_| ())
    }

    async fn release(&self, key: &str, token: &ClaimToken) -> Result<(), DedupError> {
        self.lock().release(key, token);
        Ok(())
    }
}

/// Is this outcome safe to remember, or was it a transient failure?
///
/// Keyed on the framework's own `retryable` flag rather than a local list of
/// reasons: SPEC §8.4 sets it for exactly the transient codes (`unavailable`,
/// `internalError` — see `StandardCode::default_retryable`), which is the same
/// bucket a repository `ConnectionFailed` / `QueryFailed` / `LockPoisoned`
/// lands in via `trust_tasks::router::map_repo_err`. Deferring to the flag also
/// means a handler that explicitly marks something retryable is honoured.
///
/// Caching a retryable rejection would pin a momentary database outage as this
/// message's permanent answer for the whole TTL.
fn is_cacheable(outcome: &TaskOutcome) -> bool {
    match outcome {
        Ok(_) => true,
        Err(error) => !error.payload.retryable,
    }
}

/// What [`execute_once`] did with a document.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Disposition {
    /// The document was claimed and executed: the outcome is its own.
    Executed,
    /// The document had already been executed: the outcome is the stored one,
    /// and nothing was executed again.
    Replayed,
    /// An identical document was being executed: nothing was executed, and
    /// the outcome is a retryable refusal.
    InFlight,
    /// The document was refused before it could be claimed: its identifier
    /// was accepted for a different document, the store could not be
    /// consulted, or the document could not be canonicalised.
    NotClaimed,
}

/// The outcome of [`execute_once`], and how it was reached.
#[derive(Debug)]
pub struct Once {
    pub outcome: TaskOutcome,
    pub disposition: Disposition,
}

impl Once {
    fn new(disposition: Disposition, outcome: TaskOutcome) -> Self {
        Self {
            outcome,
            disposition,
        }
    }
}

/// How many times [`execute_once`] tries to store an outcome before leaving
/// the claim to lapse, and the pause before the second try (doubled after).
const RESOLVE_ATTEMPTS: u32 = 3;
const RESOLVE_RETRY_DELAY: Duration = Duration::from_millis(100);

/// Store `outcome` for `key` (or release the claim, for a transient failure),
/// retrying a store that cannot be reached: an outcome that is not stored
/// lets a redelivery execute the document again once the lease lapses.
async fn resolve(store: &dyn MessageIdStore, key: &str, token: &ClaimToken, outcome: &TaskOutcome) {
    let cacheable = is_cacheable(outcome);
    let stored = cacheable.then(|| StoredOutcome::from_outcome(outcome));
    let mut delay = RESOLVE_RETRY_DELAY;
    for attempt in 1..=RESOLVE_ATTEMPTS {
        let resolution = match &stored {
            Some(stored) => store.complete(key, token, stored).await,
            // Transient failure: let the sender's retry try again for real.
            None => store.release(key, token).await,
        };
        match resolution {
            Ok(()) => return,
            Err(DedupError::ClaimLost(reason)) => {
                // Another copy took the id after this claim's lease lapsed:
                // the document ran more than once (see "The exact
                // guarantee"). Its entry stands.
                tracing::error!(
                    "Executed {key}, but its claim was taken over before the outcome was \
                     stored: {reason}"
                );
                return;
            }
            Err(e) if attempt < RESOLVE_ATTEMPTS => {
                tracing::warn!("Failed to resolve dedup claim {key} (attempt {attempt}): {e}");
                tokio::time::sleep(delay).await;
                delay *= 2;
            }
            Err(e) => {
                // The mutation already happened; losing the record of it means
                // a redelivery after the lease executes it again, so it is
                // worth an error-level log.
                tracing::error!(
                    "Failed to resolve dedup claim {key}; a redelivery after the in-flight \
                     lease will execute it again: {e}"
                );
            }
        }
    }
}

/// Run `execute` on `doc` at most once per accepted document identifier, by
/// the claim/replay protocol above.
///
/// If `execute` panics, the claim is released before the panic continues, so
/// a retry executes the document again rather than waiting out the lease. A
/// call cancelled while `execute` runs leaves the claim to its lease.
pub async fn execute_once<F, Fut>(
    store: &dyn MessageIdStore,
    doc: TrustTask<Value>,
    execute: F,
) -> Once
where
    F: FnOnce(TrustTask<Value>) -> Fut,
    Fut: std::future::Future<Output = TaskOutcome>,
{
    let key = message_key(&doc);
    let digest = match document_digest(&doc) {
        Ok(digest) => digest,
        Err(e) => {
            return Once::new(
                Disposition::NotClaimed,
                Err(doc.reject_with(
                    Uuid::new_v4().to_string(),
                    RejectReason::MalformedRequest {
                        reason: format!("the document cannot be canonicalised: {e}"),
                    },
                )),
            );
        }
    };

    let token = match store.claim(&key, digest.as_str()).await {
        Ok(Claim::Replay(stored)) => {
            tracing::info!("Replaying stored outcome for duplicate write {key}");
            return Once::new(Disposition::Replayed, stored.into_outcome());
        }
        Ok(Claim::InFlight) => {
            tracing::warn!("Duplicate write {key} arrived while the original is in flight");
            let mut rejection = doc.reject_with(
                Uuid::new_v4().to_string(),
                RejectReason::TaskFailed {
                    reason: "an identical document is currently being processed".to_string(),
                    details: None,
                },
            );
            // SPEC §8.4: a retry is a bit-for-bit re-send — exactly what a
            // mediator redelivery is — so this is genuinely retryable, and the
            // retry will find the completed outcome to replay.
            rejection.payload = rejection.payload.with_retryable(true);
            return Once::new(Disposition::InFlight, Err(rejection));
        }
        Ok(Claim::Conflict) => {
            tracing::warn!("Write {key} reuses an accepted id for a different document");
            return Once::new(
                Disposition::NotClaimed,
                Err(doc.reject_with(Uuid::new_v4().to_string(), RejectReason::IdConflict)),
            );
        }
        Ok(Claim::Acquired(token)) => token,
        Err(e) => {
            // Fail closed: without the record of accepted identifiers a
            // replayed write cannot be told from a fresh one.
            tracing::error!("Dedup store unavailable, refusing write {key}: {e}");
            return Once::new(
                Disposition::NotClaimed,
                Err(doc.reject_with(
                    Uuid::new_v4().to_string(),
                    RejectReason::Unavailable { retry_after: None },
                )),
            );
        }
    };

    let outcome = match std::panic::AssertUnwindSafe(execute(doc))
        .catch_unwind()
        .await
    {
        Ok(outcome) => outcome,
        Err(panic) => {
            if let Err(e) = store.release(&key, &token).await {
                tracing::error!("Failed to release dedup claim {key} after a panic: {e}");
            }
            std::panic::resume_unwind(panic);
        }
    };

    resolve(store, &key, &token, &outcome).await;
    Once::new(Disposition::Executed, outcome)
}

/// Dispatch `doc`, executing the registry's own writes and the capability
/// writes of `capabilities` at most once. Test-only: production goes through
/// the [`TaskHandler`](crate::trust_tasks::TaskHandler), which also checks the
/// document before calling [`execute_once`].
#[cfg(test)]
pub(crate) async fn dispatch_idempotent(
    dispatcher: &crate::trust_tasks::RegistryDispatcher,
    store: &dyn MessageIdStore,
    capabilities: Option<&crate::capabilities::CapabilitySet>,
    doc: TrustTask<Value>,
) -> TaskOutcome {
    use crate::trust_tasks::{handle_document, proof::is_write_slug};

    let slug = doc.type_uri.slug();
    if !is_write_slug(slug) && !capabilities.is_some_and(|c| c.is_write(slug)) {
        return handle_document(dispatcher, doc).await;
    }
    execute_once(store, doc, |doc| handle_document(dispatcher, doc))
        .await
        .outcome
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;
    use trust_tasks_rs::TrustTask;

    const PUT: &str = "https://trusttasks.org/spec/registry/record/put/0.1";

    fn write_doc(id: &str, issuer: Option<&str>) -> TrustTask<Value> {
        let mut doc = TrustTask::new(
            id.to_string(),
            PUT.parse().expect("valid type uri"),
            serde_json::json!({}),
        );
        doc.issuer = issuer.map(str::to_string);
        doc
    }

    fn ok_outcome(doc: &TrustTask<Value>) -> TaskOutcome {
        Ok(doc.clone())
    }

    fn store() -> MemoryMessageIdStore {
        MemoryMessageIdStore::default()
    }

    #[track_caller]
    fn acquired(claim: Claim) -> ClaimToken {
        match claim {
            Claim::Acquired(token) => token,
            other => panic!("expected an acquired claim, got {other:?}"),
        }
    }

    #[test]
    fn key_is_scoped_by_issuer() {
        // Two senders using the same document id must not collide — otherwise
        // one can suppress the other's write.
        let a = message_key(&write_doc("shared-id", Some("did:example:alice")));
        let b = message_key(&write_doc("shared-id", Some("did:example:bob")));
        assert_ne!(a, b);
        assert!(
            a.starts_with("MID#"),
            "must not collide with the TR# namespace"
        );
    }

    #[test]
    fn a_did_scid_issuer_has_one_key_with_or_without_its_locator() {
        let bare = message_key(&write_doc("id", Some("did:scid:vh:1:abc")));
        let located = message_key(&write_doc("id", Some("did:scid:vh:1:abc?src=example.com")));
        assert_eq!(bare, located);
    }

    #[tokio::test]
    async fn first_claim_is_acquired_second_is_in_flight() {
        let store = store();
        assert!(matches!(
            store.claim("MID#a#1", "digest").await.unwrap(),
            Claim::Acquired(_)
        ));
        assert!(matches!(
            store.claim("MID#a#1", "digest").await.unwrap(),
            Claim::InFlight
        ));
    }

    #[tokio::test]
    async fn execute_once_reports_how_each_copy_was_answered() {
        let store = store();
        let doc = write_doc("disposition", Some("did:example:alice"));
        let first = execute_once(&store, doc.clone(), |doc| async move { ok_outcome(&doc) }).await;
        assert_eq!(first.disposition, Disposition::Executed);
        let again = execute_once(&store, doc.clone(), |_| async {
            unreachable!("a duplicate is not executed")
        })
        .await;
        assert_eq!(again.disposition, Disposition::Replayed);
        assert_eq!(again.outcome.ok(), first.outcome.ok());

        let held = write_doc("held", Some("did:example:alice"));
        let digest = document_digest(&held).unwrap();
        store
            .claim(&message_key(&held), digest.as_str())
            .await
            .unwrap();
        let in_flight = execute_once(&store, held, |_| async {
            unreachable!("an in-flight duplicate is not executed")
        })
        .await;
        assert_eq!(in_flight.disposition, Disposition::InFlight);
        assert!(in_flight.outcome.is_err());
    }

    #[tokio::test]
    async fn completed_claim_replays_the_stored_outcome() {
        let store = store();
        let doc = write_doc("1", Some("did:example:alice"));
        let key = message_key(&doc);

        let token = acquired(store.claim(&key, "digest").await.unwrap());
        store
            .complete(
                &key,
                &token,
                &StoredOutcome::from_outcome(&ok_outcome(&doc)),
            )
            .await
            .unwrap();

        match store.claim(&key, "digest").await.unwrap() {
            Claim::Replay(stored) => {
                let replayed = stored.into_outcome().expect("stored a success");
                assert_eq!(replayed.id, doc.id);
            }
            other => panic!("expected replay, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn released_claim_can_be_retaken() {
        let store = store();
        let token = acquired(store.claim("MID#a#1", "digest").await.unwrap());
        store.release("MID#a#1", &token).await.unwrap();
        assert!(
            matches!(
                store.claim("MID#a#1", "digest").await.unwrap(),
                Claim::Acquired(_)
            ),
            "a released claim must be retryable, not permanently blocked"
        );
    }

    /// A handler that panics mid-dispatch would otherwise wedge its message id
    /// until the full TTL.
    #[tokio::test]
    async fn stale_in_flight_claims_are_reclaimable() {
        let store = MemoryMessageIdStore::new(DEFAULT_TTL, Duration::from_millis(1));
        store.claim("MID#a#1", "digest").await.unwrap();
        tokio::time::sleep(Duration::from_millis(5)).await;
        assert!(matches!(
            store.claim("MID#a#1", "digest").await.unwrap(),
            Claim::Acquired(_)
        ));
    }

    #[tokio::test]
    async fn completed_entries_expire() {
        let store = MemoryMessageIdStore::new(Duration::from_millis(1), DEFAULT_IN_FLIGHT_TTL);
        let doc = write_doc("1", None);
        let key = message_key(&doc);
        let token = acquired(store.claim(&key, "digest").await.unwrap());
        store
            .complete(
                &key,
                &token,
                &StoredOutcome::from_outcome(&ok_outcome(&doc)),
            )
            .await
            .unwrap();

        tokio::time::sleep(Duration::from_millis(5)).await;
        assert!(matches!(
            store.claim(&key, "digest").await.unwrap(),
            Claim::Acquired(_)
        ));
    }

    /// The rule that stops a momentary database outage becoming this message's
    /// permanent answer.
    #[test]
    fn internal_errors_are_not_cacheable() {
        let doc = write_doc("1", None);
        let transient = doc.reject_with(
            "err-1".to_string(),
            RejectReason::InternalError {
                reason: "connection refused".to_string(),
            },
        );
        assert!(!is_cacheable(&Err(transient)));
    }

    #[test]
    fn deterministic_rejections_are_cacheable() {
        let doc = write_doc("1", None);
        for reason in [
            RejectReason::ProofRequired,
            RejectReason::PermissionDenied {
                reason: "not an admin".to_string(),
            },
        ] {
            let rejection = doc.reject_with("err-1".to_string(), reason);
            assert!(
                is_cacheable(&Err(rejection)),
                "a deterministic rejection must replay, not re-run"
            );
        }
        assert!(is_cacheable(&ok_outcome(&doc)));
    }

    // --- End-to-end through the real dispatcher -------------------------
    //
    // The property R1.4 is actually about: a redelivered mutation must be
    // applied once, and the duplicate must still get an answer.

    use crate::domain::{
        Action, AuthorityId, EntityId, RecordType, Resource, TrustRecord, TrustRecordBuilder,
    };
    use crate::storage::repository::{
        RepositoryError, TrustRecordAdminRepository, TrustRecordList, TrustRecordQuery,
        TrustRecordRepository,
    };
    use crate::trust_tasks::build_dispatcher;
    use std::sync::Arc;

    /// Counts how many times a write actually reached the repository.
    #[derive(Default)]
    struct CountingRepo {
        created: Mutex<Vec<TrustRecord>>,
    }

    #[async_trait]
    impl TrustRecordRepository for CountingRepo {
        async fn find_by_query(
            &self,
            _query: TrustRecordQuery,
        ) -> Result<Option<TrustRecord>, RepositoryError> {
            Ok(None)
        }
    }

    #[async_trait]
    impl TrustRecordAdminRepository for CountingRepo {
        async fn create(&self, record: TrustRecord) -> Result<(), RepositoryError> {
            self.created
                .lock()
                .map_err(|_| RepositoryError::LockPoisoned)?
                .push(record);
            Ok(())
        }
        async fn update(&self, _record: TrustRecord) -> Result<(), RepositoryError> {
            Ok(())
        }
        async fn delete(&self, _query: TrustRecordQuery) -> Result<(), RepositoryError> {
            Ok(())
        }
        async fn list(&self) -> Result<TrustRecordList, RepositoryError> {
            Ok(TrustRecordList::new(vec![]))
        }
        async fn read(&self, _query: TrustRecordQuery) -> Result<TrustRecord, RepositoryError> {
            Err(RepositoryError::RecordNotFound("none".into()))
        }
    }

    fn sample_record() -> TrustRecord {
        TrustRecordBuilder::new()
            .entity_id(EntityId::new("did:example:entity"))
            .authority_id(AuthorityId::new("did:example:authority"))
            .action(Action::new("issue"))
            .resource(Resource::new("vc"))
            .recognized(true)
            .authorized(true)
            .record_type(RecordType::Authorization)
            .build()
            .expect("valid record")
    }

    fn create_doc(id: &str, issuer: &str) -> TrustTask<Value> {
        let record = serde_json::to_value(sample_record()).expect("record serialises");
        let mut doc = TrustTask::new(
            id.to_string(),
            PUT.parse().expect("valid type uri"),
            serde_json::json!({ "record": record }),
        );
        doc.issuer = Some(issuer.to_string());
        doc
    }

    /// The R1.4 property: the same document delivered twice mutates once, and
    /// the duplicate still receives the original response.
    #[tokio::test]
    async fn duplicate_write_applies_once_and_replays_the_response() {
        let repo = Arc::new(CountingRepo::default());
        let dispatcher = build_dispatcher(repo.clone());
        let store = store();
        let doc = create_doc("msg-1", "did:example:admin");

        let first = dispatch_idempotent(&dispatcher, &store, None, doc.clone()).await;
        let second = dispatch_idempotent(&dispatcher, &store, None, doc.clone()).await;

        assert_eq!(
            repo.created.lock().unwrap().len(),
            1,
            "a redelivered write must reach the repository exactly once"
        );
        assert_eq!(
            first.expect("first succeeds"),
            second.expect("duplicate replays rather than being dropped"),
            "the duplicate must receive the original response verbatim"
        );
    }

    /// A different document reusing an accepted id is neither applied nor
    /// answered with the first document's response.
    #[tokio::test]
    async fn a_different_document_reusing_an_accepted_id_is_a_conflict() {
        let repo = Arc::new(CountingRepo::default());
        let dispatcher = build_dispatcher(repo.clone());
        let store = store();
        let first = create_doc("msg-1", "did:example:admin");
        let mut second = first.clone();
        second.payload["record"]["entity_id"] = serde_json::json!("did:example:other");

        dispatch_idempotent(&dispatcher, &store, None, first)
            .await
            .expect("first write");
        let err = dispatch_idempotent(&dispatcher, &store, None, second)
            .await
            .expect_err("the reused id is refused");

        assert_eq!(
            serde_json::to_value(&err.payload.code).unwrap(),
            "idConflict"
        );
        assert_eq!(repo.created.lock().unwrap().len(), 1);
    }

    struct UnavailableStore;

    #[async_trait]
    impl MessageIdStore for UnavailableStore {
        async fn claim(&self, _key: &str, _digest: &str) -> Result<Claim, DedupError> {
            Err(DedupError::Unavailable("down".to_string()))
        }
        async fn complete(
            &self,
            _key: &str,
            _token: &ClaimToken,
            _outcome: &StoredOutcome,
        ) -> Result<(), DedupError> {
            Err(DedupError::Unavailable("down".to_string()))
        }
        async fn release(&self, _key: &str, _token: &ClaimToken) -> Result<(), DedupError> {
            Err(DedupError::Unavailable("down".to_string()))
        }
    }

    /// Without the record of accepted identifiers a replay cannot be told from
    /// a fresh write, so the write is refused rather than applied.
    #[tokio::test]
    async fn a_write_is_refused_when_the_store_is_unavailable() {
        let repo = Arc::new(CountingRepo::default());
        let dispatcher = build_dispatcher(repo.clone());

        let err = dispatch_idempotent(
            &dispatcher,
            &UnavailableStore,
            None,
            create_doc("msg-1", "did:example:admin"),
        )
        .await
        .expect_err("refused");

        assert_eq!(
            serde_json::to_value(&err.payload.code).unwrap(),
            "unavailable"
        );
        assert!(err.payload.retryable);
        assert!(repo.created.lock().unwrap().is_empty());
    }

    /// Distinct documents from the same issuer must both apply — dedup must not
    /// over-match and swallow legitimate writes.
    #[tokio::test]
    async fn distinct_writes_are_not_deduplicated() {
        let repo = Arc::new(CountingRepo::default());
        let dispatcher = build_dispatcher(repo.clone());
        let store = store();

        dispatch_idempotent(
            &dispatcher,
            &store,
            None,
            create_doc("msg-1", "did:example:admin"),
        )
        .await
        .expect("first write");
        dispatch_idempotent(
            &dispatcher,
            &store,
            None,
            create_doc("msg-2", "did:example:admin"),
        )
        .await
        .expect("second write");

        assert_eq!(repo.created.lock().unwrap().len(), 2);
    }

    /// Reads bypass the store entirely, so repeating one re-evaluates against
    /// current state rather than replaying a stale answer.
    #[tokio::test]
    async fn reads_are_not_deduplicated() {
        let repo = Arc::new(CountingRepo::default());
        let dispatcher = build_dispatcher(repo.clone());
        let store = store();

        let read = TrustTask::new(
            "read-1".to_string(),
            crate::trust_tasks::type_uris::RECOGNITION
                .parse()
                .expect("valid type uri"),
            serde_json::json!({
                "entity_id": "did:example:entity",
                "authority_id": "did:example:authority",
                "action": "issue",
                "resource": "vc"
            }),
        );

        assert!(
            dispatch_idempotent(&dispatcher, &store, None, read.clone())
                .await
                .is_ok()
        );
        assert!(
            dispatch_idempotent(&dispatcher, &store, None, read.clone())
                .await
                .is_ok()
        );

        // Nothing was claimed, so the same id is still free.
        assert!(matches!(
            store.claim(&message_key(&read), "digest").await.unwrap(),
            Claim::Acquired(_)
        ));
    }

    #[test]
    fn stored_outcome_round_trips_through_serde() {
        // Every durable backend will persist this shape.
        let doc = write_doc("1", Some("did:example:alice"));
        let stored = StoredOutcome::from_outcome(&ok_outcome(&doc));
        let json = serde_json::to_string(&stored).expect("serializes");
        let back: StoredOutcome = serde_json::from_str(&json).expect("deserializes");
        assert_eq!(back.into_outcome().unwrap().id, doc.id);
    }

    #[tokio::test]
    async fn a_full_store_refuses_new_claims_and_keeps_old_ones() {
        let store = MemoryMessageIdStore::default().with_limits(2, 10);
        store.claim("MID#a#1", "d").await.unwrap();
        store.claim("MID#b#1", "d").await.unwrap();

        assert!(matches!(
            store.claim("MID#c#1", "d").await,
            Err(DedupError::CapacityReached(_))
        ));
        assert!(
            matches!(store.claim("MID#a#1", "d").await.unwrap(), Claim::InFlight),
            "nothing was evicted to make room"
        );
    }

    #[tokio::test]
    async fn one_issuer_cannot_fill_the_store() {
        let store = MemoryMessageIdStore::default().with_limits(100, 2);
        store.claim("MID#a#1", "d").await.unwrap();
        store.claim("MID#a#2", "d").await.unwrap();

        assert!(matches!(
            store.claim("MID#a#3", "d").await,
            Err(DedupError::CapacityReached(_))
        ));
        assert!(matches!(
            store.claim("MID#b#1", "d").await.unwrap(),
            Claim::Acquired(_)
        ));
    }

    #[tokio::test]
    async fn expiry_frees_capacity() {
        let store = MemoryMessageIdStore::new(Duration::from_millis(1), Duration::from_millis(1))
            .with_limits(1, 1);
        store.claim("MID#a#1", "d").await.unwrap();
        tokio::time::sleep(Duration::from_millis(5)).await;
        assert!(matches!(
            store.claim("MID#a#2", "d").await.unwrap(),
            Claim::Acquired(_)
        ));
    }

    #[tokio::test]
    async fn released_claims_free_their_issuer_slot() {
        let store = MemoryMessageIdStore::default().with_limits(10, 1);
        let token = acquired(store.claim("MID#a#1", "d").await.unwrap());
        store.release("MID#a#1", &token).await.unwrap();
        assert!(matches!(
            store.claim("MID#a#2", "d").await.unwrap(),
            Claim::Acquired(_)
        ));
    }

    /// A handler that panics releases its claim, so a retry executes rather
    /// than being told "in flight" until the lease lapses.
    #[tokio::test]
    async fn a_panicking_execution_releases_its_claim() {
        let store = store();
        let doc = write_doc("panics", Some("did:example:alice"));
        let panicked = std::panic::AssertUnwindSafe(execute_once(&store, doc.clone(), |_| async {
            panic!("handler bug")
        }))
        .catch_unwind()
        .await;
        assert!(panicked.is_err(), "the panic continues");

        let retry = execute_once(&store, doc, |doc| async move { ok_outcome(&doc) }).await;
        assert_eq!(retry.disposition, Disposition::Executed);
    }

    /// Fails the first `complete`s as unreachable, then delegates.
    struct FlakyComplete {
        inner: MemoryMessageIdStore,
        failures_left: Mutex<u32>,
    }

    #[async_trait]
    impl MessageIdStore for FlakyComplete {
        async fn claim(&self, key: &str, digest: &str) -> Result<Claim, DedupError> {
            self.inner.claim(key, digest).await
        }
        async fn complete(
            &self,
            key: &str,
            token: &ClaimToken,
            outcome: &StoredOutcome,
        ) -> Result<(), DedupError> {
            {
                let mut left = self.failures_left.lock().unwrap();
                if *left > 0 {
                    *left -= 1;
                    return Err(DedupError::Unavailable("blip".to_string()));
                }
            }
            self.inner.complete(key, token, outcome).await
        }
        async fn release(&self, key: &str, token: &ClaimToken) -> Result<(), DedupError> {
            self.inner.release(key, token).await
        }
    }

    /// A store that cannot be reached for a moment does not lose the outcome:
    /// `complete` is retried, and the duplicate replays.
    #[tokio::test]
    async fn storing_the_outcome_is_retried() {
        let store = FlakyComplete {
            inner: MemoryMessageIdStore::default(),
            failures_left: Mutex::new(RESOLVE_ATTEMPTS - 1),
        };
        let doc = write_doc("flaky", Some("did:example:alice"));
        let first = execute_once(&store, doc.clone(), |doc| async move { ok_outcome(&doc) }).await;
        assert_eq!(first.disposition, Disposition::Executed);
        let again = execute_once(&store, doc, |_| async {
            unreachable!("the outcome was stored on a retry")
        })
        .await;
        assert_eq!(again.disposition, Disposition::Replayed);
    }

    // The store contract, as every implementation must keep it.
    crate::dedup::conformance::message_id_store_conformance_tests!(
        memory,
        Some(crate::dedup::conformance::StoreFixture::new(|config| {
            Box::pin(async move {
                std::sync::Arc::new(MemoryMessageIdStore::from_config(config))
                    as std::sync::Arc<dyn MessageIdStore>
            })
        }))
    );
}
