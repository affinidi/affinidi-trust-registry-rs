//! Message-id deduplication for write-path Trust Tasks (R1.4).
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
//! Writes only — the slugs [`is_write_slug`](crate::trust_tasks::proof::is_write_slug)
//! names. Reads are naturally idempotent, and putting them through the store
//! would cost a round trip and unbounded storage for no correctness gain.
//!
//! ## Claim protocol
//!
//! Check-then-act is not enough: a redelivery can arrive while the first copy is
//! still in flight, and both would pass a bare "have I seen this?" test. So the
//! store *claims* an id atomically before dispatch and resolves the claim after:
//!
//! ```text
//!   claim(key) ->  Acquired  -> dispatch -> complete(key, outcome)
//!              ->  Replay(o) -> return the original response, do not dispatch
//!              ->  InFlight  -> reject as retryable; the sender re-sends and
//!                               finds Replay once the first copy resolves
//! ```
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
//! rejections — malformed, expired, proof invalid, permission denied — are
//! properties of the document itself and replay correctly.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::Duration;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use trust_tasks_rs::{ErrorResponse, RejectReason, TrustTask};
use uuid::Uuid;

use crate::trust_tasks::{RegistryDispatcher, TaskOutcome, handle_document, proof::is_write_slug};

/// How long a completed outcome stays replayable.
///
/// Must comfortably exceed the mediator's redelivery window: once the entry
/// expires, a redelivery is indistinguishable from a fresh document and would
/// be applied a second time.
pub const DEFAULT_TTL: Duration = Duration::from_secs(24 * 60 * 60);

/// How long an unresolved claim is honoured before another copy may take it.
///
/// A handler that panics — or a process that dies mid-dispatch — would
/// otherwise leave an `InFlight` marker that blocks its message id until TTL.
/// Reclaiming after this window trades a small duplicate-application risk for
/// not wedging a write permanently; it is set well above any realistic handler
/// runtime.
pub const DEFAULT_IN_FLIGHT_TTL: Duration = Duration::from_secs(5 * 60);

#[derive(Debug, thiserror::Error)]
pub enum DedupError {
    #[error("dedup store unavailable: {0}")]
    Unavailable(String),
}

/// Storage key for a document: `MID#<issuer>#<id>`.
///
/// Composed with the issuer, not the bare `id`, so one sender cannot occupy
/// another's id space — whether by accident (a client with a weak id generator)
/// or deliberately (claiming an id to suppress somebody else's write). The
/// `MID#` prefix keeps these clear of the `TR#` namespace every backend's
/// `list()` scans.
pub fn message_key(doc: &TrustTask<Value>) -> String {
    let issuer = doc.issuer.as_deref().unwrap_or("anonymous");
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

/// Result of attempting to claim a message id.
#[derive(Debug)]
pub enum Claim {
    /// The caller owns this id and must resolve it with `complete` or `release`.
    Acquired,
    /// Already handled — replay this outcome without dispatching.
    Replay(Box<StoredOutcome>),
    /// Another copy holds the claim right now.
    InFlight,
}

/// Durable claim/replay store for message ids.
#[async_trait]
pub trait MessageIdStore: Send + Sync {
    /// Atomically claim `key`, or report why it could not be claimed.
    ///
    /// Implementations MUST make this atomic against concurrent callers —
    /// `SET NX` for Redis, a conditional put for DynamoDB. The check-then-set
    /// pattern the record backends use for `create` is **not** sufficient here.
    async fn claim(&self, key: &str) -> Result<Claim, DedupError>;

    /// Resolve a claim with the outcome to replay for later duplicates.
    async fn complete(&self, key: &str, outcome: &StoredOutcome) -> Result<(), DedupError>;

    /// Abandon a claim so a retry may take it (transient failures only).
    async fn release(&self, key: &str) -> Result<(), DedupError>;
}

enum Entry {
    InFlight {
        claimed_at: DateTime<Utc>,
    },
    Done {
        // Boxed: a stored outcome is a full Trust Task document, dwarfing the
        // timestamp in the `InFlight` variant.
        outcome: Box<StoredOutcome>,
        expires_at: DateTime<Utc>,
    },
}

/// In-memory store: correct dedup semantics, no durability.
///
/// Used with the CSV backend, whose writes rewrite the whole records file and
/// so cannot absorb per-message inserts. Dedup state is lost on restart, which
/// is acceptable for the local-development posture CSV serves — the server warns
/// at startup so this is never a silent property of a deployment.
pub struct MemoryMessageIdStore {
    ttl: Duration,
    in_flight_ttl: Duration,
    entries: Mutex<HashMap<String, Entry>>,
}

impl MemoryMessageIdStore {
    pub fn new(ttl: Duration, in_flight_ttl: Duration) -> Self {
        Self {
            ttl,
            in_flight_ttl,
            entries: Mutex::new(HashMap::new()),
        }
    }

    /// Drop entries past their expiry. Called on every claim: the map is only
    /// ever touched on the write path, so there is no separate sweeper task to
    /// shut down, and a registry that stops receiving writes stops accruing.
    fn evict_expired(
        entries: &mut HashMap<String, Entry>,
        now: DateTime<Utc>,
        in_flight: Duration,
    ) {
        let in_flight = chrono::Duration::from_std(in_flight).unwrap_or(chrono::Duration::zero());
        entries.retain(|_, entry| match entry {
            Entry::Done { expires_at, .. } => *expires_at > now,
            Entry::InFlight { claimed_at } => now.signed_duration_since(*claimed_at) < in_flight,
        });
    }
}

impl Default for MemoryMessageIdStore {
    fn default() -> Self {
        Self::new(DEFAULT_TTL, DEFAULT_IN_FLIGHT_TTL)
    }
}

#[async_trait]
impl MessageIdStore for MemoryMessageIdStore {
    async fn claim(&self, key: &str) -> Result<Claim, DedupError> {
        let now = Utc::now();
        // Poison-tolerant: a panic while holding this lock must not wedge every
        // subsequent write, mirroring `MemoryCapabilityStore`.
        let mut entries = self
            .entries
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());

        Self::evict_expired(&mut entries, now, self.in_flight_ttl);

        match entries.get(key) {
            Some(Entry::Done { outcome, .. }) => Ok(Claim::Replay(outcome.clone())),
            Some(Entry::InFlight { .. }) => Ok(Claim::InFlight),
            None => {
                entries.insert(key.to_string(), Entry::InFlight { claimed_at: now });
                Ok(Claim::Acquired)
            }
        }
    }

    async fn complete(&self, key: &str, outcome: &StoredOutcome) -> Result<(), DedupError> {
        let expires_at =
            Utc::now() + chrono::Duration::from_std(self.ttl).unwrap_or(chrono::Duration::zero());
        let mut entries = self
            .entries
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        entries.insert(
            key.to_string(),
            Entry::Done {
                outcome: Box::new(outcome.clone()),
                expires_at,
            },
        );
        Ok(())
    }

    async fn release(&self, key: &str) -> Result<(), DedupError> {
        let mut entries = self
            .entries
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        entries.remove(key);
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

/// Dispatch `doc`, applying write-path dedup.
///
/// Reads bypass the store entirely. Writes claim their message id first, so a
/// redelivery either replays the original response or is told to retry, but
/// never mutates the registry twice.
pub async fn dispatch_idempotent(
    dispatcher: &RegistryDispatcher,
    store: &dyn MessageIdStore,
    doc: TrustTask<Value>,
) -> TaskOutcome {
    if !is_write_slug(doc.type_uri.slug()) {
        return handle_document(dispatcher, doc).await;
    }

    let key = message_key(&doc);

    match store.claim(&key).await {
        Ok(Claim::Replay(stored)) => {
            tracing::info!("Replaying stored outcome for duplicate write {key}");
            return stored.into_outcome();
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
            return Err(rejection);
        }
        Ok(Claim::Acquired) => {}
        Err(e) => {
            // Fail open: a dedup store outage must not stop the registry
            // accepting writes. The exposure is a possible duplicate, which is
            // strictly better than refusing every mutation while the store is
            // down.
            tracing::error!("Dedup store unavailable, dispatching without dedup: {e}");
            return handle_document(dispatcher, doc).await;
        }
    }

    let outcome = handle_document(dispatcher, doc).await;

    let resolution = if is_cacheable(&outcome) {
        store
            .complete(&key, &StoredOutcome::from_outcome(&outcome))
            .await
    } else {
        // Transient failure: let the sender's retry try again for real.
        store.release(&key).await
    };
    if let Err(e) = resolution {
        // The mutation already happened; losing the record of it risks a
        // duplicate on redelivery, so it is worth an error-level log.
        tracing::error!("Failed to resolve dedup claim {key}: {e}");
    }

    outcome
}

#[cfg(test)]
mod tests {
    use super::*;
    use trust_tasks_rs::TrustTask;

    const CREATE: &str = "https://trusttasks.org/spec/registry/record/create/0.1";

    fn write_doc(id: &str, issuer: Option<&str>) -> TrustTask<Value> {
        let mut doc = TrustTask::new(
            id.to_string(),
            CREATE.parse().expect("valid type uri"),
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

    #[tokio::test]
    async fn first_claim_is_acquired_second_is_in_flight() {
        let store = store();
        assert!(matches!(
            store.claim("MID#a#1").await.unwrap(),
            Claim::Acquired
        ));
        assert!(matches!(
            store.claim("MID#a#1").await.unwrap(),
            Claim::InFlight
        ));
    }

    #[tokio::test]
    async fn completed_claim_replays_the_stored_outcome() {
        let store = store();
        let doc = write_doc("1", Some("did:example:alice"));
        let key = message_key(&doc);

        store.claim(&key).await.unwrap();
        store
            .complete(&key, &StoredOutcome::from_outcome(&ok_outcome(&doc)))
            .await
            .unwrap();

        match store.claim(&key).await.unwrap() {
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
        store.claim("MID#a#1").await.unwrap();
        store.release("MID#a#1").await.unwrap();
        assert!(
            matches!(store.claim("MID#a#1").await.unwrap(), Claim::Acquired),
            "a released claim must be retryable, not permanently blocked"
        );
    }

    /// A handler that panics mid-dispatch would otherwise wedge its message id
    /// until the full TTL.
    #[tokio::test]
    async fn stale_in_flight_claims_are_reclaimable() {
        let store = MemoryMessageIdStore::new(DEFAULT_TTL, Duration::from_millis(1));
        store.claim("MID#a#1").await.unwrap();
        tokio::time::sleep(Duration::from_millis(5)).await;
        assert!(matches!(
            store.claim("MID#a#1").await.unwrap(),
            Claim::Acquired
        ));
    }

    #[tokio::test]
    async fn completed_entries_expire() {
        let store = MemoryMessageIdStore::new(Duration::from_millis(1), DEFAULT_IN_FLIGHT_TTL);
        let doc = write_doc("1", None);
        let key = message_key(&doc);
        store.claim(&key).await.unwrap();
        store
            .complete(&key, &StoredOutcome::from_outcome(&ok_outcome(&doc)))
            .await
            .unwrap();

        tokio::time::sleep(Duration::from_millis(5)).await;
        assert!(matches!(store.claim(&key).await.unwrap(), Claim::Acquired));
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
            CREATE.parse().expect("valid type uri"),
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

        let first = dispatch_idempotent(&dispatcher, &store, doc.clone()).await;
        let second = dispatch_idempotent(&dispatcher, &store, doc.clone()).await;

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
            create_doc("msg-1", "did:example:admin"),
        )
        .await
        .expect("first write");
        dispatch_idempotent(
            &dispatcher,
            &store,
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
            dispatch_idempotent(&dispatcher, &store, read.clone())
                .await
                .is_ok()
        );
        assert!(
            dispatch_idempotent(&dispatcher, &store, read.clone())
                .await
                .is_ok()
        );

        // Nothing was claimed, so the same id is still free.
        assert!(matches!(
            store.claim(&message_key(&read)).await.unwrap(),
            Claim::Acquired
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
}
