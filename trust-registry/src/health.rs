//! Liveness and capability reporting for `/health`.
//!
//! The registry has two independent surfaces: a read path (REST/TRQP over
//! HTTP) and a write path (Trust Tasks over DIDComm, via a mediator). They
//! fail independently, and an unreachable mediator must not take the read
//! path down with it — a registry that can still answer recognition and
//! authorization queries is useful even when no new records can arrive.
//!
//! What it must *not* do is claim to be fully healthy while writes are
//! impossible. A green health check masking a dead write path is how a
//! deployment ends up silently serving records that stopped updating hours
//! ago. So each dependency's state is reported explicitly, and every state is
//! driven by something that can go false again (R6.2):
//!
//! - **writes** — `starting` until the pickup listener has completed a round
//!   trip with the mediator, then `ok` while those round trips keep
//!   succeeding (the offline sync makes one every 30 seconds), `unavailable`
//!   after consecutive failures, when none has succeeded for
//!   [`MEDIATOR_STALE_AFTER`], or when the listener stops. A path this process
//!   cannot observe (a host-driven socket, the TSP delivery layer) is
//!   `unknown` rather than a guessed `ok`.
//! - **storage** — a cheap lookup against the record store, made when
//!   `/health` is asked and cached for [`STORAGE_PROBE_TTL`].
//! - **verifier** — whether write proofs can be checked for every DID method,
//!   or only `did:key` while the DID resolver is being rebuilt.
//! - **transports** — whether the DID document peers resolve advertises a
//!   transport this process does not serve.
//!
//! `/health` keeps returning **200** while degraded: the process is alive and
//! serving reads, so an orchestrator should not evict or restart it — the
//! mediator being unreachable is rarely something a restart fixes. The
//! degradation is carried in the body, where a monitor can alert on it.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, OnceLock, RwLock};
use std::time::Duration;

use tokio::time::Instant;

use crate::storage::repository::{TrustRecordQuery, TrustRecordRepository};

/// How long a successful mediator round trip vouches for the write path. Well
/// beyond one offline-sync cycle (a 30 second wait plus the time to dispatch a
/// batch), so a busy registry is not reported down.
pub const MEDIATOR_STALE_AFTER: Duration = Duration::from_secs(5 * 60);

/// Consecutive failed mediator round trips after which writes are reported
/// unavailable. One failure is often a blip the next sync recovers from.
pub const MEDIATOR_FAILURES_BEFORE_UNAVAILABLE: u32 = 2;

/// How long one storage probe answers `/health` for, so a burst of health
/// requests costs the record store one lookup.
pub const STORAGE_PROBE_TTL: Duration = Duration::from_secs(5);

/// How long a storage probe may take before the store is reported unavailable.
pub const STORAGE_PROBE_TIMEOUT: Duration = Duration::from_secs(3);

/// State of the DIDComm write path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum WriteStatus {
    /// The listener is connected and its mediator round trips succeed; record
    /// mutations can arrive.
    Ok,
    /// DIDComm is switched off by configuration (`ENABLE_DIDCOMM != "true"`).
    /// This is a deployment choice, not a fault — a read-only registry is a
    /// legitimate configuration, so it does not degrade health.
    Disabled,
    /// DIDComm was enabled but the listener stopped or cannot reach the
    /// mediator. Reads continue; no new record mutations can be received until
    /// it recovers.
    Unavailable,
    /// DIDComm is enabled and the listener has not yet completed a round trip
    /// with the mediator.
    Starting,
    /// The write path is not one this process can observe: the host owns the
    /// socket ([`DidCommSource::HostDriven`](crate::didcomm::listener::DidCommSource::HostDriven)),
    /// or the TSP delivery layer drives it. A host can report its own state with
    /// [`RegistryHealth::mark_writes_ok`] and
    /// [`RegistryHealth::mark_writes_unavailable`].
    Unknown,
}

impl WriteStatus {
    /// Lowercase wire value for the `writes` field.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Ok => "ok",
            Self::Disabled => "disabled",
            Self::Unavailable => "unavailable",
            Self::Starting => "starting",
            Self::Unknown => "unknown",
        }
    }

    /// Whether this state should be reported as degraded overall.
    #[must_use]
    pub fn is_degraded(self) -> bool {
        matches!(self, Self::Unavailable)
    }
}

/// Shared, mutable health state, updated by the listener, the supervisor and
/// the background tasks, and read by the `/health` handler.
pub struct RegistryHealth {
    writes: RwLock<WriteState>,
    /// Whether the TSP relationship store is at its limit: `None` until a TSP
    /// listener reports it, then updated on every change, so it reads `false`
    /// again once room is made.
    tsp_relationships_full: RwLock<Option<bool>>,
    /// Messages the pickup listener deleted from the mediator after they kept
    /// failing to be handled.
    given_up: AtomicU64,
    /// Whether a pickup listener reports given-up messages here, which is
    /// when `givenUpMessages` is part of the body.
    pickup_attached: AtomicBool,
    /// `Some(true)` while the proof verifier can only check `did:key` issuers.
    /// `None` when the host supplied its own verifier.
    verifier_did_key_only: RwLock<Option<bool>>,
    /// The advertised-vs-served transport check: `None` until it has run.
    transports: RwLock<Option<TransportState>>,
    storage: StorageProbe,
}

impl std::fmt::Debug for RegistryHealth {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RegistryHealth")
            .field("body", &self.to_json())
            .finish()
    }
}

#[derive(Debug, Clone)]
struct WriteState {
    status: WriteStatus,
    /// Why writes are unavailable, when they are — surfaced so an operator
    /// does not have to correlate against server logs to find out.
    detail: Option<String>,
    /// When the mediator last answered a round trip.
    last_link_ok: Option<Instant>,
    /// Consecutive failed round trips since the last success.
    link_failures: u32,
    /// Set once a listener reports round trips: past this age without one, the
    /// link is reported unavailable rather than its last good value.
    link_window: Option<Duration>,
}

/// Outcome of the advertised-vs-served transport check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransportState {
    /// The published document advertises only transports this process serves.
    Ok,
    /// The published document advertises a transport this process does not
    /// serve; peers choosing it are dropped.
    Mismatch,
    /// The published document could not be resolved, so nothing is known.
    Unknown,
}

impl TransportState {
    fn as_str(self) -> &'static str {
        match self {
            Self::Ok => "ok",
            Self::Mismatch => "mismatch",
            Self::Unknown => "unknown",
        }
    }
}

#[derive(Default)]
struct StorageProbe {
    repository: OnceLock<Arc<dyn TrustRecordRepository>>,
    /// The last probe: when it ran and whether the store answered. The async
    /// lock also makes concurrent `/health` requests share one probe.
    last: tokio::sync::Mutex<Option<(Instant, bool)>>,
    /// The last result, readable without awaiting, for [`RegistryHealth::to_json`].
    available: RwLock<Option<bool>>,
}

impl RegistryHealth {
    /// Create health state for a server whose DIDComm path is enabled or not.
    ///
    /// An enabled path starts as [`WriteStatus::Starting`]: nothing has
    /// connected yet.
    #[must_use]
    pub fn new(didcomm_enabled: bool) -> Self {
        Self::with_write_status(if didcomm_enabled {
            WriteStatus::Starting
        } else {
            WriteStatus::Disabled
        })
    }

    /// Create health state with the write path in `status`.
    #[must_use]
    pub fn with_write_status(status: WriteStatus) -> Self {
        Self {
            writes: RwLock::new(WriteState {
                status,
                detail: None,
                last_link_ok: None,
                link_failures: 0,
                link_window: None,
            }),
            tsp_relationships_full: RwLock::new(None),
            given_up: AtomicU64::new(0),
            pickup_attached: AtomicBool::new(false),
            verifier_did_key_only: RwLock::new(None),
            transports: RwLock::new(None),
            storage: StorageProbe::default(),
        }
    }

    /// Probe `repository` when `/health` is asked (see [`report`](Self::report)).
    /// Only the first repository attached is used.
    pub fn attach_storage(&self, repository: Arc<dyn TrustRecordRepository>) {
        let _ = self.storage.repository.set(repository);
    }

    /// Record whether the TSP relationship store is at its limit. While it is,
    /// each new peer displaces the least recently active one, so health is
    /// degraded and says why.
    pub fn set_tsp_relationships_full(&self, full: bool) {
        *write(&self.tsp_relationships_full) = Some(full);
    }

    /// Record that the write path works: the listener (or, for a host-driven
    /// registry, the host) has a working connection.
    pub fn mark_writes_ok(&self) {
        let mut guard = write(&self.writes);
        guard.status = WriteStatus::Ok;
        guard.detail = None;
        guard.link_failures = 0;
        guard.last_link_ok = Some(Instant::now());
    }

    /// Record that the write path has stopped, with the reason.
    pub fn mark_writes_unavailable(&self, detail: impl Into<String>) {
        let mut guard = write(&self.writes);
        guard.status = WriteStatus::Unavailable;
        guard.detail = Some(detail.into());
    }

    /// Record that the write path's state cannot be observed from here.
    pub fn mark_writes_unknown(&self) {
        let mut guard = write(&self.writes);
        guard.status = WriteStatus::Unknown;
        guard.detail = None;
        guard.link_window = None;
    }

    /// A round trip with the mediator succeeded. From now on the link is
    /// reported unavailable if none succeeds for [`MEDIATOR_STALE_AFTER`].
    pub(crate) fn record_mediator_ok(&self) {
        self.mark_writes_ok();
        write(&self.writes).link_window = Some(MEDIATOR_STALE_AFTER);
    }

    /// A round trip with the mediator failed. After
    /// [`MEDIATOR_FAILURES_BEFORE_UNAVAILABLE`] in a row, writes are
    /// reported unavailable until one succeeds.
    pub(crate) fn record_mediator_failure(&self) {
        let mut guard = write(&self.writes);
        guard.link_failures = guard.link_failures.saturating_add(1);
        if guard.link_failures >= MEDIATOR_FAILURES_BEFORE_UNAVAILABLE
            && matches!(guard.status, WriteStatus::Ok | WriteStatus::Starting)
        {
            guard.status = WriteStatus::Unavailable;
            guard.detail = Some(
                "the mediator is not answering the listener's round trips; see the \
                 registry's log"
                    .to_string(),
            );
        }
    }

    /// A pickup listener reports to this health state: include
    /// `givenUpMessages` in the body.
    pub(crate) fn attach_pickup_listener(&self) {
        self.pickup_attached.store(true, Ordering::Relaxed);
    }

    /// The pickup listener deleted a message from the mediator after it kept
    /// failing.
    pub(crate) fn record_given_up(&self) {
        self.given_up.fetch_add(1, Ordering::Relaxed);
    }

    /// Messages the pickup listener has given up on since start.
    #[must_use]
    pub fn given_up_messages(&self) -> u64 {
        self.given_up.load(Ordering::Relaxed)
    }

    /// Record whether the proof verifier is limited to `did:key` issuers
    /// because the DID resolver could not be built.
    pub fn set_verifier_did_key_only(&self, did_key_only: bool) {
        *write(&self.verifier_did_key_only) = Some(did_key_only);
    }

    /// Record the outcome of the advertised-vs-served transport check.
    pub fn set_transports(&self, state: TransportState) {
        *write(&self.transports) = Some(state);
    }

    /// Current write-path status, as `/health` reports it.
    #[must_use]
    pub fn write_status(&self) -> WriteStatus {
        self.effective_writes().0
    }

    /// The write status and detail, with a link that has gone quiet for too
    /// long reported unavailable rather than at its last good value.
    fn effective_writes(&self) -> (WriteStatus, Option<String>) {
        let state = read(&self.writes).clone();
        if state.status == WriteStatus::Ok
            && let (Some(window), Some(last)) = (state.link_window, state.last_link_ok)
            && last.elapsed() > window
        {
            return (
                WriteStatus::Unavailable,
                Some(format!(
                    "no successful round trip with the mediator in the last {}s; see the \
                     registry's log",
                    window.as_secs()
                )),
            );
        }
        (state.status, state.detail)
    }

    /// Probe the record store if the last probe is older than
    /// [`STORAGE_PROBE_TTL`], then return the `/health` body.
    pub async fn report(&self) -> serde_json::Value {
        self.probe_storage().await;
        self.to_json()
    }

    async fn probe_storage(&self) {
        let Some(repository) = self.storage.repository.get() else {
            return;
        };
        let mut last = self.storage.last.lock().await;
        if let Some((at, _)) = *last
            && at.elapsed() < STORAGE_PROBE_TTL
        {
            return;
        }
        let available = probe(repository.as_ref()).await;
        *last = Some((Instant::now(), available));
        *write(&self.storage.available) = Some(available);
    }

    /// The `/health` response body, from the state last recorded. Use
    /// [`report`](Self::report) to refresh the storage probe first.
    ///
    /// `status` stays exactly `"OK"` in the healthy case — it is a documented
    /// wire value that existing probes match on — and becomes `"degraded"`
    /// when a dependency fails. Every other field is additive.
    #[must_use]
    pub fn to_json(&self) -> serde_json::Value {
        let (writes, write_detail) = self.effective_writes();
        let tsp_full = *read(&self.tsp_relationships_full);
        let storage = *read(&self.storage.available);
        let did_key_only = *read(&self.verifier_did_key_only);
        let transports = *read(&self.transports);

        let mut details = Vec::new();
        details.extend(write_detail);
        if storage == Some(false) {
            details.push("the record store is not answering; see the registry's log".to_string());
        }
        if did_key_only == Some(true) {
            details.push(
                "the DID resolver is unavailable, so only did:key write proofs can be \
                 verified; retrying"
                    .to_string(),
            );
        }
        if transports == Some(TransportState::Mismatch) {
            details.push(
                "the published DID document advertises a transport this registry does not \
                 serve; see the registry's log"
                    .to_string(),
            );
        }

        let degraded = writes.is_degraded()
            || tsp_full == Some(true)
            || storage == Some(false)
            || did_key_only == Some(true)
            || transports == Some(TransportState::Mismatch);
        let mut body = serde_json::json!({
            "status": if degraded { "degraded" } else { "OK" },
            "writes": writes.as_str(),
        });
        if let Some(available) = storage {
            body["storage"] = (if available { "ok" } else { "unavailable" }).into();
        }
        if let Some(did_key_only) = did_key_only {
            body["verifier"] = (if did_key_only { "didKeyOnly" } else { "ok" }).into();
        }
        if let Some(transports) = transports {
            body["transports"] = transports.as_str().into();
        }
        if let Some(full) = tsp_full {
            body["tspRelationships"] = (if full { "full" } else { "ok" }).into();
        }
        if self.pickup_attached.load(Ordering::Relaxed) {
            body["givenUpMessages"] = self.given_up_messages().into();
        }
        if !details.is_empty() {
            body["detail"] = details.join("; ").into();
        }
        body
    }
}

/// Look up a record that does not exist. Any answer, found or not, shows the
/// store is reachable; an error or no answer within
/// [`STORAGE_PROBE_TIMEOUT`] shows it is not.
async fn probe(repository: &dyn TrustRecordRepository) -> bool {
    use crate::domain::{Action, AuthorityId, EntityId, Resource};

    let query = TrustRecordQuery::new(
        EntityId::new("urn:trust-registry:health-probe"),
        AuthorityId::new("urn:trust-registry:health-probe"),
        Action::new("health-probe"),
        Resource::new("health-probe"),
    );
    match tokio::time::timeout(STORAGE_PROBE_TIMEOUT, repository.find_by_query(query)).await {
        Ok(Ok(_)) => true,
        Ok(Err(e)) => {
            tracing::warn!("/health: the record store refused a probe lookup: {e}");
            false
        }
        Err(_) => {
            tracing::warn!(
                "/health: the record store did not answer a probe lookup within {:?}",
                STORAGE_PROBE_TIMEOUT
            );
            false
        }
    }
}

/// Read a lock, tolerating poison.
///
/// A panic while holding one of these locks must not turn every subsequent
/// health probe into a panic — the reported state is still readable and is
/// more useful than an unresponsive endpoint.
fn read<T>(lock: &RwLock<T>) -> std::sync::RwLockReadGuard<'_, T> {
    lock.read()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

fn write<T>(lock: &RwLock<T>) -> std::sync::RwLockWriteGuard<'_, T> {
    lock.write()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::TrustRecord;
    use crate::storage::repository::RepositoryError;
    use serde_json::json;

    /// The healthy body keeps `status: "OK"`: probes in the wild match on it.
    #[test]
    fn healthy_reports_ok() {
        let health = RegistryHealth::new(true);
        health.mark_writes_ok();
        assert_eq!(health.to_json(), json!({ "status": "OK", "writes": "ok" }));
        assert!(!health.write_status().is_degraded());
    }

    /// Before the listener has connected, writes are not claimed to work —
    /// but nothing has failed, so the registry is not degraded either.
    #[test]
    fn enabled_writes_start_as_starting_not_ok() {
        let health = RegistryHealth::new(true);
        assert_eq!(
            health.to_json(),
            json!({ "status": "OK", "writes": "starting" })
        );
    }

    /// DIDComm switched off is a configuration choice, not a fault. A
    /// read-only registry must not alarm every monitor that watches it.
    #[test]
    fn disabled_didcomm_is_not_degraded() {
        let health = RegistryHealth::new(false);
        assert_eq!(
            health.to_json(),
            json!({ "status": "OK", "writes": "disabled" })
        );
        assert!(!health.write_status().is_degraded());
    }

    #[test]
    fn failed_listener_degrades_and_explains_why() {
        let health = RegistryHealth::new(true);
        health.mark_writes_unavailable("mediator unreachable: NXDOMAIN");

        assert_eq!(
            health.to_json(),
            json!({
                "status": "degraded",
                "writes": "unavailable",
                "detail": "mediator unreachable: NXDOMAIN",
            })
        );
        assert!(health.write_status().is_degraded());
    }

    /// A registry configured without DIDComm can still be marked unavailable
    /// if something else stops the path; the transition must not be silently
    /// ignored because the initial state was `Disabled`.
    #[test]
    fn disabled_can_still_transition_to_unavailable() {
        let health = RegistryHealth::new(false);
        health.mark_writes_unavailable("stopped");
        assert_eq!(health.write_status(), WriteStatus::Unavailable);
    }

    #[test]
    fn detail_is_absent_until_something_fails() {
        let health = RegistryHealth::new(true);
        assert!(health.to_json().get("detail").is_none());
    }

    #[test]
    fn wire_values_are_stable() {
        assert_eq!(WriteStatus::Ok.as_str(), "ok");
        assert_eq!(WriteStatus::Disabled.as_str(), "disabled");
        assert_eq!(WriteStatus::Unavailable.as_str(), "unavailable");
        assert_eq!(WriteStatus::Starting.as_str(), "starting");
        assert_eq!(WriteStatus::Unknown.as_str(), "unknown");
    }

    /// Failing round trips flip writes to unavailable, and a success flips
    /// them back: the state is never latched (R6.2).
    #[test]
    fn mediator_failures_degrade_and_recovery_restores() {
        let health = RegistryHealth::new(true);
        health.record_mediator_ok();
        assert_eq!(health.write_status(), WriteStatus::Ok);

        health.record_mediator_failure();
        assert_eq!(
            health.write_status(),
            WriteStatus::Ok,
            "one failure is a blip"
        );
        health.record_mediator_failure();
        assert_eq!(health.write_status(), WriteStatus::Unavailable);
        assert_eq!(health.to_json()["status"], "degraded");

        health.record_mediator_ok();
        assert_eq!(health.write_status(), WriteStatus::Ok);
        assert_eq!(health.to_json()["status"], "OK");
    }

    /// A listener that stops reporting is not still `ok` forever.
    #[tokio::test(start_paused = true)]
    async fn a_quiet_mediator_link_goes_stale() {
        let health = RegistryHealth::new(true);
        health.record_mediator_ok();
        tokio::time::advance(MEDIATOR_STALE_AFTER - Duration::from_secs(1)).await;
        assert_eq!(health.write_status(), WriteStatus::Ok);

        tokio::time::advance(Duration::from_secs(2)).await;
        assert_eq!(health.write_status(), WriteStatus::Unavailable);
        assert!(
            health.to_json()["detail"]
                .as_str()
                .is_some_and(|d| d.contains("mediator")),
            "{}",
            health.to_json()
        );
    }

    /// A host-reported `ok` has no heartbeat behind it, so it does not expire.
    #[tokio::test(start_paused = true)]
    async fn a_host_reported_ok_does_not_expire() {
        let health = RegistryHealth::with_write_status(WriteStatus::Unknown);
        health.mark_writes_ok();
        tokio::time::advance(MEDIATOR_STALE_AFTER * 2).await;
        assert_eq!(health.write_status(), WriteStatus::Ok);
    }

    #[test]
    fn given_up_messages_are_counted_once_a_listener_reports() {
        let health = RegistryHealth::new(true);
        assert!(health.to_json().get("givenUpMessages").is_none());
        health.attach_pickup_listener();
        assert_eq!(health.to_json()["givenUpMessages"], 0);
        health.record_given_up();
        health.record_given_up();
        assert_eq!(health.to_json()["givenUpMessages"], 2);
    }

    #[test]
    fn a_did_key_only_verifier_degrades() {
        let health = RegistryHealth::new(false);
        health.set_verifier_did_key_only(true);
        let body = health.to_json();
        assert_eq!(body["status"], "degraded");
        assert_eq!(body["verifier"], "didKeyOnly");

        health.set_verifier_did_key_only(false);
        let body = health.to_json();
        assert_eq!(body["status"], "OK");
        assert_eq!(body["verifier"], "ok");
    }

    #[test]
    fn a_transport_mismatch_degrades() {
        let health = RegistryHealth::new(false);
        health.set_transports(TransportState::Unknown);
        assert_eq!(health.to_json()["status"], "OK");
        health.set_transports(TransportState::Mismatch);
        let body = health.to_json();
        assert_eq!(body["status"], "degraded");
        assert_eq!(body["transports"], "mismatch");
    }

    /// A store that fails every lookup.
    struct DownStore;

    #[async_trait::async_trait]
    impl TrustRecordRepository for DownStore {
        async fn find_by_query(
            &self,
            _query: TrustRecordQuery,
        ) -> Result<Option<TrustRecord>, RepositoryError> {
            Err(RepositoryError::ConnectionFailed("refused".into()))
        }
    }

    #[tokio::test]
    async fn a_failing_store_degrades_health() {
        let health = RegistryHealth::new(false);
        health.attach_storage(Arc::new(DownStore));
        let body = health.report().await;
        assert_eq!(body["status"], "degraded");
        assert_eq!(body["storage"], "unavailable");
        // The error itself is logged, not published.
        assert!(
            !body["detail"]
                .as_str()
                .unwrap_or_default()
                .contains("refused")
        );
    }

    #[tokio::test]
    async fn a_working_store_is_ok() {
        let health = RegistryHealth::new(false);
        health.attach_storage(Arc::new(
            crate::storage::adapters::local_storage::LocalStorage::new(),
        ));
        let body = health.report().await;
        assert_eq!(
            body,
            json!({ "status": "OK", "writes": "disabled", "storage": "ok" })
        );
    }

    /// A store that counts lookups.
    #[derive(Default)]
    struct CountingStore(AtomicU64);

    #[async_trait::async_trait]
    impl TrustRecordRepository for CountingStore {
        async fn find_by_query(
            &self,
            _query: TrustRecordQuery,
        ) -> Result<Option<TrustRecord>, RepositoryError> {
            self.0.fetch_add(1, Ordering::Relaxed);
            Ok(None)
        }
    }

    /// Health requests are unauthenticated; they must not each reach the store.
    #[tokio::test(start_paused = true)]
    async fn storage_probes_are_cached() {
        let store = Arc::new(CountingStore::default());
        let health = RegistryHealth::new(false);
        health.attach_storage(store.clone());
        for _ in 0..10 {
            health.report().await;
        }
        assert_eq!(store.0.load(Ordering::Relaxed), 1);
        tokio::time::advance(STORAGE_PROBE_TTL + Duration::from_millis(1)).await;
        health.report().await;
        assert_eq!(store.0.load(Ordering::Relaxed), 2);
    }
}
