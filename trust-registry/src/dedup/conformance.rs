//! The behaviour every [`MessageIdStore`] must show, as one test suite each
//! implementation runs.
//!
//! An implementation's test module builds a [`StoreFixture`] and expands
//! [`message_id_store_conformance_tests!`]:
//!
//! ```ignore
//! crate::dedup::conformance::message_id_store_conformance_tests!(
//!     my_store,
//!     Some(StoreFixture::new(|config| Box::pin(async move { make(config) })))
//! );
//! ```
//!
//! The fixture expression yields `None` to skip the suite, as the stores
//! backed by an external service do when the variable naming the service is
//! unset (see [`crate::storage::conformance::redis_test_url`]).
//!
//! Every test uses message keys under an issuer unique to that test, and
//! short retentions, so the suite can run against a shared store and leaves
//! nothing that outlives it for long.

use std::any::Any;
use std::sync::Arc;
use std::time::Duration;

use futures::future::BoxFuture;
use serde_json::Value;
use trust_tasks_rs::TrustTask;

use super::{Claim, ClaimToken, DedupError, MessageIdStore, StoredOutcome};
use crate::configs::MessageIdStoreConfig;

/// Builds a handle on the store under test with the given settings.
pub(crate) type MakeStore =
    Arc<dyn Fn(MessageIdStoreConfig) -> BoxFuture<'static, Arc<dyn MessageIdStore>> + Send + Sync>;

/// Stops the store and starts it again, as a registry restart would. Every
/// handle the test held is dropped before it is called.
pub(crate) type Restart = Arc<dyn Fn() -> BoxFuture<'static, ()> + Send + Sync>;

/// One store implementation under test.
pub(crate) struct StoreFixture {
    make: MakeStore,
    /// Whether two handles from `make` see the same entries (a second Redis
    /// connection, a second DynamoDB client), as two replicas would.
    shared: bool,
    /// Whether the store keeps the per-issuer bound of its config.
    bounded: bool,
    restart: Option<Restart>,
    _guard: Option<Box<dyn Any + Send + Sync>>,
}

impl StoreFixture {
    pub(crate) fn new<F>(make: F) -> Self
    where
        F: Fn(MessageIdStoreConfig) -> BoxFuture<'static, Arc<dyn MessageIdStore>>
            + Send
            + Sync
            + 'static,
    {
        Self {
            make: Arc::new(make),
            shared: false,
            bounded: true,
            restart: None,
            _guard: None,
        }
    }

    /// Handles share their entries.
    pub(crate) fn shared(mut self) -> Self {
        self.shared = true;
        self
    }

    /// The store bounds entries by retention only, not by count.
    pub(crate) fn unbounded(mut self) -> Self {
        self.bounded = false;
        self
    }

    /// The store is durable: what it held before `restart` it holds after.
    pub(crate) fn with_restart<R>(mut self, restart: R) -> Self
    where
        R: Fn() -> BoxFuture<'static, ()> + Send + Sync + 'static,
    {
        self.restart = Some(Arc::new(restart));
        self
    }

    pub(crate) fn with_guard(mut self, guard: impl Any + Send + Sync) -> Self {
        self._guard = Some(Box::new(guard));
        self
    }

    async fn store(&self, config: MessageIdStoreConfig) -> Arc<dyn MessageIdStore> {
        (self.make)(config).await
    }
}

/// Settings long enough that nothing lapses during a test.
fn steady() -> MessageIdStoreConfig {
    MessageIdStoreConfig {
        retention: Duration::from_secs(20),
        in_flight_lease: Duration::from_secs(10),
        max_entries: 100_000,
        max_entries_per_issuer: 10_000,
    }
}

/// How long the tests that wait for a lease or retention to lapse set it to,
/// and how long they then wait.
const SHORT: Duration = Duration::from_millis(400);
const PAST_SHORT: Duration = Duration::from_millis(1_200);

/// Message keys under an issuer unique to one test.
struct Keys {
    issuer: String,
}

impl Keys {
    fn new() -> Self {
        Self {
            issuer: format!("did:example:dedup-conformance-{}", uuid::Uuid::new_v4()),
        }
    }

    fn key(&self, id: &str) -> String {
        format!("MID#{}#{id}", self.issuer)
    }
}

fn outcome(marker: &str) -> StoredOutcome {
    let doc = TrustTask::new(
        marker.to_string(),
        "https://trusttasks.org/spec/registry/record/put/0.1"
            .parse()
            .expect("type uri"),
        serde_json::json!({ "marker": marker, "nested": { "list": [1, 2, 3] } }),
    );
    StoredOutcome::Completed(doc)
}

fn marker_of(stored: StoredOutcome) -> Value {
    stored.into_outcome().expect("a stored success").payload["marker"].clone()
}

#[track_caller]
fn acquired(claim: Result<Claim, DedupError>) -> ClaimToken {
    match claim {
        Ok(Claim::Acquired(token)) => token,
        other => panic!("expected an acquired claim, got {other:?}"),
    }
}

#[track_caller]
fn replayed(claim: Result<Claim, DedupError>) -> StoredOutcome {
    match claim {
        Ok(Claim::Replay(stored)) => *stored,
        other => panic!("expected a replay, got {other:?}"),
    }
}

/// The first claim is acquired; while it is held, the same document is in
/// flight and a different one is a conflict.
pub(crate) async fn a_claim_is_exclusive(fixture: &StoreFixture) {
    let store = fixture.store(steady()).await;
    let keys = Keys::new();
    let key = keys.key("1");

    acquired(store.claim(&key, "digest-a").await);
    assert!(matches!(
        store.claim(&key, "digest-a").await,
        Ok(Claim::InFlight)
    ));
    assert!(matches!(
        store.claim(&key, "digest-b").await,
        Ok(Claim::Conflict)
    ));
    // Another key is unaffected.
    acquired(store.claim(&keys.key("2"), "digest-a").await);
}

/// A completed claim replays its outcome, field for field, to the same
/// document, and is a conflict for a different one.
pub(crate) async fn a_completed_claim_replays_its_outcome(fixture: &StoreFixture) {
    let store = fixture.store(steady()).await;
    let keys = Keys::new();
    let key = keys.key("1");

    let token = acquired(store.claim(&key, "digest").await);
    let stored = outcome("first");
    store
        .complete(&key, &token, &stored)
        .await
        .expect("complete");

    let replay = replayed(store.claim(&key, "digest").await);
    assert_eq!(
        serde_json::to_value(&replay).expect("serialises"),
        serde_json::to_value(&stored).expect("serialises"),
        "the outcome replays verbatim"
    );
    assert!(matches!(
        store.claim(&key, "other").await,
        Ok(Claim::Conflict)
    ));

    // A rejection replays too.
    let key = keys.key("2");
    let token = acquired(store.claim(&key, "digest").await);
    let doc = TrustTask::new(
        "2".to_string(),
        "https://trusttasks.org/spec/registry/record/put/0.1"
            .parse()
            .expect("type uri"),
        serde_json::json!({}),
    );
    let rejection = doc.reject_with("err".to_string(), trust_tasks_rs::RejectReason::IdConflict);
    store
        .complete(&key, &token, &StoredOutcome::Rejected(rejection.clone()))
        .await
        .expect("complete");
    match replayed(store.claim(&key, "digest").await).into_outcome() {
        Err(replayed) => assert_eq!(
            serde_json::to_value(&replayed).expect("serialises"),
            serde_json::to_value(&rejection).expect("serialises")
        ),
        Ok(_) => panic!("a stored rejection replays as one"),
    }
}

/// A released claim can be taken again; a release by a token that does not
/// hold the claim changes nothing.
pub(crate) async fn release_frees_only_its_own_claim(fixture: &StoreFixture) {
    let store = fixture.store(steady()).await;
    let keys = Keys::new();
    let key = keys.key("1");

    let token = acquired(store.claim(&key, "digest").await);
    store
        .release(&key, &ClaimToken::new())
        .await
        .expect("a stranger's release is not an error");
    assert!(matches!(
        store.claim(&key, "digest").await,
        Ok(Claim::InFlight)
    ));

    store.release(&key, &token).await.expect("release");
    let token = acquired(store.claim(&key, "digest").await);

    // A completed id is not released by its old token.
    store
        .complete(&key, &token, &outcome("kept"))
        .await
        .expect("complete");
    store.release(&key, &token).await.expect("release");
    assert_eq!(
        marker_of(replayed(store.claim(&key, "digest").await)),
        "kept"
    );
}

/// A claim whose lease lapsed can be taken by another copy. The first
/// claimant can then neither store its outcome over the second's claim nor
/// release it.
pub(crate) async fn a_lapsed_claim_is_taken_over_and_fenced(fixture: &StoreFixture) {
    let store = fixture
        .store(MessageIdStoreConfig {
            in_flight_lease: SHORT,
            ..steady()
        })
        .await;
    let keys = Keys::new();
    let key = keys.key("1");

    let first = acquired(store.claim(&key, "digest").await);
    tokio::time::sleep(PAST_SHORT).await;
    let second = acquired(store.claim(&key, "digest").await);

    assert!(matches!(
        store.complete(&key, &first, &outcome("first")).await,
        Err(DedupError::ClaimLost(_))
    ));
    store.release(&key, &first).await.expect("release");
    assert!(
        matches!(store.claim(&key, "digest").await, Ok(Claim::InFlight)),
        "the second claim still holds the id"
    );

    store
        .complete(&key, &second, &outcome("second"))
        .await
        .expect("complete");
    assert_eq!(
        marker_of(replayed(store.claim(&key, "digest").await)),
        "second"
    );
}

/// A completed outcome is forgotten after the retention: the id can be
/// claimed again.
pub(crate) async fn an_outcome_expires_after_the_retention(fixture: &StoreFixture) {
    let store = fixture
        .store(MessageIdStoreConfig {
            retention: SHORT,
            ..steady()
        })
        .await;
    let keys = Keys::new();
    let key = keys.key("1");

    let token = acquired(store.claim(&key, "digest").await);
    store
        .complete(&key, &token, &outcome("short-lived"))
        .await
        .expect("complete");
    replayed(store.claim(&key, "digest").await);
    tokio::time::sleep(PAST_SHORT).await;
    acquired(store.claim(&key, "digest").await);
}

const CONCURRENT_CLAIMS: usize = 16;

/// Concurrent claims of one id, split across two handles where the store is
/// shared: exactly one is acquired, every other one is in flight.
pub(crate) async fn concurrent_claims_have_one_winner(fixture: &StoreFixture) {
    let first = fixture.store(steady()).await;
    let second = if fixture.shared {
        fixture.store(steady()).await
    } else {
        Arc::clone(&first)
    };
    let key = Keys::new().key("1");
    let claims: Vec<_> = (0..CONCURRENT_CLAIMS)
        .map(|index| {
            let store = if index % 2 == 0 {
                Arc::clone(&first)
            } else {
                Arc::clone(&second)
            };
            let key = key.clone();
            tokio::spawn(async move { store.claim(&key, "digest").await })
        })
        .collect();
    let mut won = 0;
    for claim in claims {
        match claim.await.expect("claim task") {
            Ok(Claim::Acquired(_)) => won += 1,
            Ok(Claim::InFlight) => {}
            other => panic!("expected acquired or in flight, got {other:?}"),
        }
    }
    assert_eq!(won, 1, "exactly one concurrent claim wins");
}

/// Two handles on a shared store see each other's claims and outcomes, as two
/// replicas must.
pub(crate) async fn handles_share_entries(fixture: &StoreFixture) {
    if !fixture.shared {
        return;
    }
    let first = fixture.store(steady()).await;
    let second = fixture.store(steady()).await;
    let key = Keys::new().key("1");

    let token = acquired(first.claim(&key, "digest").await);
    assert!(matches!(
        second.claim(&key, "digest").await,
        Ok(Claim::InFlight)
    ));
    first
        .complete(&key, &token, &outcome("shared"))
        .await
        .expect("complete");
    assert_eq!(
        marker_of(replayed(second.claim(&key, "digest").await)),
        "shared"
    );
}

/// A durable store still replays an outcome after a restart.
pub(crate) async fn an_outcome_survives_a_restart(fixture: &StoreFixture) {
    let Some(restart) = &fixture.restart else {
        return;
    };
    let key = Keys::new().key("1");
    {
        let store = fixture.store(steady()).await;
        let token = acquired(store.claim(&key, "digest").await);
        store
            .complete(&key, &token, &outcome("durable"))
            .await
            .expect("complete");
    }
    restart().await;
    let store = fixture.store(steady()).await;
    assert_eq!(
        marker_of(replayed(store.claim(&key, "digest").await)),
        "durable"
    );
    assert!(matches!(
        store.claim(&key, "other").await,
        Ok(Claim::Conflict)
    ));
}

/// A bounded store refuses a new claim from an issuer at its bound, and keeps
/// what it holds; other issuers are unaffected.
pub(crate) async fn one_issuer_cannot_fill_the_store(fixture: &StoreFixture) {
    if !fixture.bounded {
        return;
    }
    let store = fixture
        .store(MessageIdStoreConfig {
            max_entries_per_issuer: 2,
            ..steady()
        })
        .await;
    let keys = Keys::new();
    acquired(store.claim(&keys.key("1"), "d").await);
    let token = acquired(store.claim(&keys.key("2"), "d").await);
    store
        .complete(&keys.key("2"), &token, &outcome("two"))
        .await
        .expect("complete");

    assert!(matches!(
        store.claim(&keys.key("3"), "d").await,
        Err(DedupError::CapacityReached(_))
    ));
    replayed(store.claim(&keys.key("2"), "d").await);
    acquired(store.claim(&Keys::new().key("1"), "d").await);
}

/// Expand the suite as `#[tokio::test]`s in a `message_id_conformance` child
/// module. `$group` names the `serial_test` group the tests run in; `$fixture`
/// is an expression yielding `Option<StoreFixture>`, evaluated in each test.
macro_rules! message_id_store_conformance_tests {
    ($group:ident, $fixture:expr) => {
        mod message_id_conformance {
            #[allow(unused_imports)]
            use super::*;

            $crate::dedup::conformance::message_id_store_conformance_tests!(
                @tests $group, $fixture,
                a_claim_is_exclusive,
                a_completed_claim_replays_its_outcome,
                release_frees_only_its_own_claim,
                a_lapsed_claim_is_taken_over_and_fenced,
                an_outcome_expires_after_the_retention,
                concurrent_claims_have_one_winner,
                handles_share_entries,
                an_outcome_survives_a_restart,
                one_issuer_cannot_fill_the_store
            );
        }
    };
    (@tests $group:ident, $fixture:expr, $($test:ident),+) => {
        $(
            #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
            #[::serial_test::serial($group)]
            async fn $test() {
                let Some(fixture) = $fixture else {
                    return;
                };
                $crate::dedup::conformance::$test(&fixture).await;
            }
        )+
    };
}
pub(crate) use message_id_store_conformance_tests;
