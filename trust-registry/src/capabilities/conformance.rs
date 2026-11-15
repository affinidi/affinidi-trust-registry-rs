//! The conformance suite every [`CapabilityStateStore`] passes, and the
//! replica tests every shared one passes: two [`CapabilitySet`]s over one
//! store converge, and concurrent changes lose no update.
//!
//! A backend runs it with [`capability_store_conformance_tests!`]:
//!
//! ```ignore
//! crate::capabilities::conformance::capability_store_conformance_tests!(
//!     memory_caps,
//!     Some(fixture())
//! );
//! ```
//!
//! The fixture expression is evaluated inside each test (it may `.await`)
//! and yields `None` to skip, as the Redis and DynamoDB fixtures do when
//! their service is not configured.

#![allow(clippy::unwrap_used, clippy::expect_used, deprecated)]

use std::sync::Arc;

use chrono::Utc;
use futures::future::BoxFuture;
use serde_json::Value;
use trust_tasks_rs::{Dispatcher, Payload as _, TrustTask};

use super::*;

type Handles = (Box<dyn CapabilityStateStore>, Box<dyn CapabilityStateStore>);

/// Makes, per test, two handles on one fresh, empty state (two connections,
/// as two replicas would hold; or one shared store twice).
pub(crate) struct CapabilityStoreFixture {
    make: Box<dyn Fn() -> BoxFuture<'static, Handles> + Send + Sync>,
}

impl CapabilityStoreFixture {
    pub(crate) fn new(
        make: impl Fn() -> BoxFuture<'static, Handles> + Send + Sync + 'static,
    ) -> Self {
        Self {
            make: Box::new(make),
        }
    }

    pub(crate) async fn handles(&self) -> Handles {
        (self.make)().await
    }
}

/// An enablement's state, enabled or not, under `authority`.
pub(crate) fn state(enabled: bool, authority: Option<&str>) -> CapabilityState {
    CapabilityState {
        version: "0.1".to_string(),
        enabled,
        config: authority.map(|a| serde_json::json!({ CONFIG_AUTHORITY: a })),
        enabled_at: Utc::now(),
        revision: 0,
    }
}

pub(crate) async fn starts_empty_and_round_trips(f: CapabilityStoreFixture) {
    let (store, other) = f.handles().await;
    assert!(store.load().await.unwrap().is_empty());
    let key = EnablementKey::new("demo", Some("did:example:a"));
    let written = state(true, Some("did:example:a"));
    assert_eq!(store.put(&key, 0, &written).await.unwrap(), Put::Written(1));
    for handle in [&store, &other] {
        let loaded = handle.load().await.unwrap();
        assert_eq!(loaded.len(), 1);
        assert_eq!(
            loaded.get(&key),
            Some(&CapabilityState {
                revision: 1,
                ..written.clone()
            }),
            "stored as written, at revision 1, and visible to every handle"
        );
    }
    let disabled = state(false, Some("did:example:a"));
    assert_eq!(
        store.put(&key, 1, &disabled).await.unwrap(),
        Put::Written(2)
    );
    assert_eq!(other.load().await.unwrap()[&key].revision, 2);
    assert!(!other.load().await.unwrap()[&key].enabled);
}

pub(crate) async fn a_stale_revision_is_refused(f: CapabilityStoreFixture) {
    let (store, other) = f.handles().await;
    let key = EnablementKey::new("demo", None);
    assert_eq!(
        store.put(&key, 0, &state(true, None)).await.unwrap(),
        Put::Written(1)
    );
    // Absent expected, but present.
    assert_eq!(
        other.put(&key, 0, &state(false, None)).await.unwrap(),
        Put::Conflict
    );
    // Ahead of the store.
    assert_eq!(
        other.put(&key, 5, &state(false, None)).await.unwrap(),
        Put::Conflict
    );
    assert!(store.load().await.unwrap()[&key].enabled, "nothing written");
    assert_eq!(
        other.put(&key, 1, &state(false, None)).await.unwrap(),
        Put::Written(2)
    );
    // The first writer's revision is now stale.
    assert_eq!(
        store.put(&key, 1, &state(true, None)).await.unwrap(),
        Put::Conflict
    );
    assert!(!store.load().await.unwrap()[&key].enabled);
}

pub(crate) async fn enablements_are_independent(f: CapabilityStoreFixture) {
    let (store, other) = f.handles().await;
    let authorities = [
        None,
        Some("did:example:a"),
        Some("did:web:example.com%3A8080:x#frag"),
        Some("did:example:\"quoted\"|[]"),
    ];
    for (n, authority) in authorities.iter().enumerate() {
        let key = EnablementKey::new("demo", *authority);
        assert_eq!(
            store
                .put(&key, 0, &state(n % 2 == 0, *authority))
                .await
                .unwrap(),
            Put::Written(1)
        );
    }
    let other_capability = EnablementKey::new("other", Some("did:example:a"));
    assert_eq!(
        other
            .put(&other_capability, 0, &state(true, Some("did:example:a")))
            .await
            .unwrap(),
        Put::Written(1)
    );
    let loaded = other.load().await.unwrap();
    assert_eq!(loaded.len(), authorities.len() + 1);
    for (n, authority) in authorities.iter().enumerate() {
        let entry = &loaded[&EnablementKey::new("demo", *authority)];
        assert_eq!(entry.enabled, n % 2 == 0);
        assert_eq!(entry.revision, 1);
    }
}

/// Writers on two handles each add one to a counter many times, re-reading
/// on every conflict: every increment lands exactly once.
pub(crate) async fn concurrent_writers_lose_no_update(f: CapabilityStoreFixture) {
    const WRITERS: usize = 4;
    const EACH: usize = 5;
    let (store, other) = f.handles().await;
    let (store, other): (Arc<dyn CapabilityStateStore>, Arc<dyn CapabilityStateStore>) =
        (Arc::from(store), Arc::from(other));
    let key = EnablementKey::new("counter", None);
    let mut writers = Vec::new();
    for n in 0..WRITERS {
        let handle = if n % 2 == 0 { &store } else { &other }.clone();
        let key = key.clone();
        writers.push(tokio::spawn(async move {
            let mut conflicts = 0usize;
            for _ in 0..EACH {
                loop {
                    let current = handle.load().await.unwrap().get(&key).cloned();
                    let (expected, count) = current.as_ref().map_or((0, 0), |s| {
                        (
                            s.revision,
                            s.config
                                .as_ref()
                                .and_then(|c| c.get("count"))
                                .and_then(Value::as_u64)
                                .unwrap_or(0),
                        )
                    });
                    let next = CapabilityState {
                        config: Some(serde_json::json!({ "count": count + 1 })),
                        ..state(true, None)
                    };
                    match handle.put(&key, expected, &next).await.unwrap() {
                        Put::Written(revision) => {
                            assert_eq!(revision, expected + 1);
                            break;
                        }
                        Put::Conflict => conflicts += 1,
                    }
                }
            }
            conflicts
        }));
    }
    for writer in writers {
        writer.await.unwrap();
    }
    let total = (WRITERS * EACH) as u64;
    let stored = &store.load().await.unwrap()[&key];
    assert_eq!(stored.revision, total, "one revision per increment");
    assert_eq!(
        stored.config.as_ref().and_then(|c| c.get("count")),
        Some(&serde_json::json!(total)),
        "no increment lost"
    );
}

// --- two replicas -------------------------------------------------------------

/// A capability serving `registry/recognition`, enabled per authority.
fn replica_capability() -> CapabilityDefinition {
    use crate::specs::registry::recognition::v0_1 as recognition;
    CapabilityDefinition {
        manifest: CapabilityManifest::builder()
            .capability("demo")
            .version("0.1")
            .specs(vec!["demo/*".to_string()])
            .try_into()
            .unwrap(),
        register: Arc::new(|d: RegistryDispatcher, _: &CapabilityState| {
            d.on::<recognition::Payload, _>(|doc| -> crate::trust_tasks::TaskFuture {
                // Raw JSON: a test-only capability's marker answer.
                Box::pin(async move {
                    Ok(doc.respond_with(new_id(), serde_json::json!({ "handled": true })))
                })
            })
        }),
        register_reads: None,
        validate_config: None,
        requires_authority: false,
    }
}

async fn replica(store: Box<dyn CapabilityStateStore>) -> Arc<CapabilitySet> {
    CapabilitySet::new(
        vec![replica_capability()],
        store,
        Box::new(Dispatcher::new),
        Box::new(Dispatcher::new),
    )
    .await
    .unwrap()
}

/// Whether `set` serves the capability's task for `authority`, through the
/// dispatcher of that enablement.
async fn serves(set: &CapabilitySet, authority: Option<&str>) -> bool {
    use crate::specs::registry::recognition::v0_1 as recognition;
    let Some(tasks) = set.snapshot("demo", authority).await.tasks else {
        return false;
    };
    let payload: recognition::Payload = recognition::Payload::builder()
        .entity_id("e")
        .authority_id("a")
        .action("x")
        .resource("r")
        .try_into()
        .unwrap();
    let doc = TrustTask::new(
        new_id(),
        recognition::Payload::type_uri(),
        serde_json::to_value(payload).unwrap(),
    );
    crate::trust_tasks::handle_document(&tasks, doc)
        .await
        .is_ok()
}

fn config_for(authority: &str) -> Option<Value> {
    Some(serde_json::json!({ CONFIG_AUTHORITY: authority }))
}

/// An enable on one replica is honoured on the other from its next refresh,
/// and so is a disable; a replica that has not refreshed still decides a
/// change against the store, never against what it last read.
pub(crate) async fn replicas_converge(f: CapabilityStoreFixture) {
    let (a_store, b_store) = f.handles().await;
    assert!(a_store.is_shared() && b_store.is_shared());
    let (a, b) = (replica(a_store).await, replica(b_store).await);
    let authority = "did:example:a";

    a.enable("demo", "0.1", config_for(authority), None)
        .await
        .unwrap();
    assert!(serves(&a, Some(authority)).await);
    b.refresh().await.unwrap();
    assert!(b.snapshot("demo", Some(authority)).await.enabled);
    assert!(serves(&b, Some(authority)).await, "B serves A's enable");
    assert_eq!(
        b.authorities("demo").await,
        vec![Some(authority.to_string())]
    );

    // B has not refreshed since; it still decides against the store.
    b.disable("demo", Some(authority)).await.unwrap();
    assert_eq!(
        a.enable("demo", "0.1", config_for(authority), None)
            .await
            .map(|_| ()),
        Ok(()),
        "A re-reads before deciding: the enablement is disabled, so it may enable it"
    );
    assert_eq!(
        b.enable("demo", "0.1", config_for(authority), None)
            .await
            .map(|_| ()),
        Err(CapabilityError::AlreadyEnabled),
        "B re-reads before deciding: A enabled it again"
    );
    assert!(b.snapshot("demo", Some(authority)).await.enabled);

    a.disable("demo", Some(authority)).await.unwrap();
    assert!(!serves(&a, Some(authority)).await);
    b.refresh().await.unwrap();
    assert!(!b.snapshot("demo", Some(authority)).await.enabled);
    assert!(!serves(&b, Some(authority)).await, "B honours A's disable");
    assert_eq!(
        b.disable("demo", Some(authority)).await,
        Err(CapabilityError::NotEnabled)
    );
}

/// Replicas changing the state at once lose no update: of two enables of one
/// enablement exactly one succeeds, and enables of different enablements
/// all land.
pub(crate) async fn concurrent_changes_lose_no_update(f: CapabilityStoreFixture) {
    let (a_store, b_store) = f.handles().await;
    let (a, b) = (replica(a_store).await, replica(b_store).await);

    for round in 0..3 {
        let authority = format!("did:example:same-{round}");
        let (on_a, on_b) = tokio::join!(
            a.enable("demo", "0.1", config_for(&authority), None),
            b.enable("demo", "0.1", config_for(&authority), None),
        );
        let outcomes = [on_a.map(|_| ()), on_b.map(|_| ())];
        assert_eq!(
            outcomes.iter().filter(|o| o.is_ok()).count(),
            1,
            "{outcomes:?}"
        );
        assert!(outcomes.contains(&Err(CapabilityError::AlreadyEnabled)));
        let (off_a, off_b) = tokio::join!(
            a.disable("demo", Some(&authority)),
            b.disable("demo", Some(&authority)),
        );
        assert_eq!(
            [off_a.is_ok(), off_b.is_ok()]
                .iter()
                .filter(|ok| **ok)
                .count(),
            1
        );
    }

    let mut changes = Vec::new();
    for n in 0..6 {
        let set = if n % 2 == 0 { a.clone() } else { b.clone() };
        changes.push(tokio::spawn(async move {
            set.enable(
                "demo",
                "0.1",
                config_for(&format!("did:example:each-{n}")),
                None,
            )
            .await
            .map(|_| ())
        }));
    }
    for change in changes {
        assert_eq!(change.await.unwrap(), Ok(()));
    }
    for set in [&a, &b] {
        set.refresh().await.unwrap();
        let each = set
            .authorities("demo")
            .await
            .into_iter()
            .flatten()
            .filter(|a| a.starts_with("did:example:each-"))
            .count();
        assert_eq!(each, 6, "every replica sees every enable");
    }
}

/// `inner`, whose puts fail once `ok` of them have succeeded: the store
/// becoming unreachable part-way through an import.
struct FailingPuts<'a> {
    inner: &'a dyn CapabilityStateStore,
    ok: std::sync::atomic::AtomicUsize,
}

#[async_trait::async_trait]
impl CapabilityStateStore for FailingPuts<'_> {
    async fn load(&self) -> Result<CapabilityStates, String> {
        self.inner.load().await
    }

    async fn put(
        &self,
        key: &EnablementKey,
        expected: u64,
        state: &CapabilityState,
    ) -> Result<Put, String> {
        let left = self.ok.load(std::sync::atomic::Ordering::SeqCst);
        if left == 0 {
            return Err("unreachable".to_string());
        }
        self.ok.store(left - 1, std::sync::atomic::Ordering::SeqCst);
        self.inner.put(key, expected, state).await
    }
}

/// A state file is merged into the shared store until it has been imported
/// whole: an import cut short by a failed write leaves the file in place, and
/// the next start writes the rest; another replica's file adds only what the
/// shared state has never held; an imported file is renamed and not read
/// again.
pub(crate) async fn a_state_file_is_merged_until_imported(f: CapabilityStoreFixture) {
    let (shared, _) = f.handles().await;
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("capabilities.json");
    let imported = dir.path().join("capabilities.json.imported");
    let keys: Vec<EnablementKey> = ["did:example:a", "did:example:b", "did:example:c"]
        .iter()
        .map(|a| EnablementKey::new("demo", Some(a)))
        .collect();
    let file = FileCapabilityStore::new(&path);
    for key in &keys {
        let authority = key.authority.as_deref();
        file.put(key, 0, &state(true, authority)).await.unwrap();
    }

    // The store fails after the first write: the import fails, the file
    // stays.
    let failing = FailingPuts {
        inner: shared.as_ref(),
        ok: std::sync::atomic::AtomicUsize::new(1),
    };
    assert!(import_state_file(&failing, &file).await.is_err());
    assert!(path.exists(), "a failed import leaves the file to retry");
    assert_eq!(shared.load().await.unwrap().len(), 1);

    // The restart repeats it: the rest is written, nothing twice.
    assert_eq!(import_state_file(shared.as_ref(), &file).await.unwrap(), 2);
    let loaded = shared.load().await.unwrap();
    for key in &keys {
        assert!(loaded[key].enabled, "{key:?} imported");
        assert_eq!(loaded[key].revision, 1, "{key:?} written once");
    }
    assert!(!path.exists() && imported.exists(), "renamed once imported");

    // A renamed file is not read again.
    assert_eq!(import_state_file(shared.as_ref(), &file).await.unwrap(), 0);

    // Another replica's file: what the shared state holds is kept as it
    // holds it, what it never held is added.
    let other_dir = tempfile::tempdir().unwrap();
    let other_path = other_dir.path().join("capabilities.json");
    let other = FileCapabilityStore::new(&other_path);
    let first = &keys[0];
    other
        .put(first, 0, &state(false, first.authority.as_deref()))
        .await
        .unwrap();
    let new = EnablementKey::new("demo", Some("did:example:d"));
    other
        .put(&new, 0, &state(true, Some("did:example:d")))
        .await
        .unwrap();
    assert_eq!(import_state_file(shared.as_ref(), &other).await.unwrap(), 1);
    let loaded = shared.load().await.unwrap();
    assert!(loaded[first].enabled, "the shared state wins");
    assert!(loaded[&new].enabled, "a new enablement is merged in");
    assert!(!other_path.exists(), "renamed once merged");
}

/// Generates the suite for one backend: `$name` names the module, `$fixture`
/// is an expression of type `Option<CapabilityStoreFixture>`.
macro_rules! capability_store_conformance_tests {
    ($name:ident, $fixture:expr) => {
        mod $name {
            #[allow(unused_imports)]
            use super::*;

            $crate::capabilities::conformance::capability_store_conformance_tests!(
                @tests $fixture;
                starts_empty_and_round_trips,
                a_stale_revision_is_refused,
                enablements_are_independent,
                concurrent_writers_lose_no_update,
            );
        }
    };
    (@tests $fixture:expr; $($test:ident),* $(,)?) => {
        $(
            #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
            async fn $test() {
                let Some(fixture) = $fixture else { return };
                $crate::capabilities::conformance::$test(fixture).await;
            }
        )*
    };
}

/// Generates the replica tests for one shared backend, as
/// [`capability_store_conformance_tests!`] does.
macro_rules! replica_tests {
    ($name:ident, $fixture:expr) => {
        mod $name {
            #[allow(unused_imports)]
            use super::*;

            $crate::capabilities::conformance::capability_store_conformance_tests!(
                @tests $fixture;
                replicas_converge,
                concurrent_changes_lose_no_update,
                a_state_file_is_merged_until_imported,
            );
        }
    };
}

pub(crate) use capability_store_conformance_tests;
pub(crate) use replica_tests;
