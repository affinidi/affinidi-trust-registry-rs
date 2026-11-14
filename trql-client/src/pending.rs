//! Reply demultiplexing shared by the mediator-based transports.
//!
//! One background task owns the inbound stream (never per-request wait
//! loops — concurrent callers must not steal each other's replies) and routes
//! each reply document to its waiter by the document's `threadId`.
//!
//! A reply is handed over only when the party the transport authenticated as
//! its sender is the party the request was addressed to. The `threadId` is
//! chosen by whoever sends the document, so it identifies the exchange but
//! not who answered it; the sender binding does that.
//!
//! ### Waiter lifetime
//!
//! [`PendingReplies::register`] returns a [`Registration`] that owns the
//! waiter: dropping it removes the map entry. An exchange is therefore
//! cleaned up on every path — reply, send failure, timeout, *and* the caller
//! dropping the exchange future mid-flight (its own shorter timeout, a
//! `select!` against shutdown, a disconnected HTTP client) — without any
//! explicit removal on each arm.
//!
//! ### Inbound health
//!
//! The demux task reports every poll of its stream to an [`InboundMonitor`].
//! After [`UNAVAILABLE_AFTER`] consecutive failures the stream is marked
//! unavailable: every waiter is failed at once with the stream's error, and
//! new exchanges are refused up front, rather than each waiting out the full
//! reply window and reporting a timeout that points at the registry. The
//! first successful poll clears the state (it is never latched). When the
//! demux task ends — panic or abort — the monitor's `Drop` marks the
//! transport stopped and closes every waiter.

use std::collections::HashMap;
use std::future::Future;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use affinidi_tdk::did_common::scid::same_reference;
use serde_json::Value;
use tokio::sync::oneshot;
use tracing::{debug, error, info, warn};
use trust_tasks_rs::TrustTask;

use crate::error::TrqlError;
use crate::transport::TransportKind;

/// Consecutive inbound-stream failures after which the stream is reported
/// unavailable and in-flight and new exchanges fail fast.
pub(crate) const UNAVAILABLE_AFTER: u32 = 3;
/// First retry delay after an inbound-stream failure.
const BACKOFF_INITIAL: Duration = Duration::from_millis(500);
/// Ceiling on the retry delay.
const BACKOFF_MAX: Duration = Duration::from_secs(5);
/// While the stream stays down, repeat the warning every this many failures.
const WARN_EVERY: u32 = 20;

/// What a waiter receives: the reply document, or the reason the inbound
/// stream can no longer deliver one.
type Reply = Result<TrustTask<Value>, String>;

/// A registered exchange: the party whose reply it waits for, and where to
/// deliver that reply.
struct Waiter {
    expected_sender: String,
    tx: oneshot::Sender<Reply>,
}

/// What [`PendingReplies::route`] did with a document.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum RouteOutcome {
    /// Handed to the waiter registered under its `threadId`.
    Delivered,
    /// No waiter for its `threadId` (or it carried none, or the waiter had
    /// already gone away): a late reply to an exchange that timed out or was
    /// cancelled, or an unsolicited document.
    Unsolicited,
    /// A waiter exists, but the document did not come from the party that
    /// waiter's request was addressed to (or its sender was not
    /// authenticated). The waiter stays registered for the real reply.
    WrongSender {
        /// The party the request was addressed to.
        expected: String,
    },
}

/// The inbound side's state, as exchanges observe it.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Health {
    /// Polling normally (or not yet failed).
    Healthy,
    /// The stream has failed [`UNAVAILABLE_AFTER`] times in a row; carries
    /// the last error. Cleared by the next successful poll.
    Unavailable(String),
    /// The demux task has ended; nothing will ever be routed again.
    Stopped,
}

#[derive(Default)]
struct State {
    waiters: HashMap<String, Waiter>,
    health: Option<Health>,
}

impl State {
    fn health(&self) -> &Health {
        self.health.as_ref().unwrap_or(&Health::Healthy)
    }
}

/// In-flight exchanges awaiting a reply, keyed by request document id, and
/// the health of the stream that delivers them.
#[derive(Clone, Default)]
pub(crate) struct PendingReplies {
    inner: Arc<Mutex<State>>,
}

/// One registered exchange. Owns the reply receiver; dropping it removes the
/// waiter from the map (a no-op once [`PendingReplies::route`] has taken it).
pub(crate) struct Registration {
    pending: PendingReplies,
    request_id: String,
    rx: oneshot::Receiver<Reply>,
}

impl Registration {
    /// The receiver the reply (or the stream's failure) arrives on.
    pub(crate) fn receiver(&mut self) -> &mut oneshot::Receiver<Reply> {
        &mut self.rx
    }
}

impl Drop for Registration {
    fn drop(&mut self) {
        self.pending.lock().waiters.remove(&self.request_id);
    }
}

impl PendingReplies {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    /// Register a waiter for `request_id` before the request is sent, so a
    /// fast reply cannot race the registration. Only a reply authenticated
    /// as coming from `expected_sender` (the request's recipient) completes it.
    ///
    /// Refused, with the reason, while the inbound stream is unavailable or
    /// the demux task has stopped: the reply could not be received.
    pub(crate) fn register(
        &self,
        request_id: &str,
        expected_sender: &str,
    ) -> Result<Registration, String> {
        let (tx, rx) = oneshot::channel();
        {
            let mut state = self.lock();
            match state.health() {
                Health::Healthy => {}
                Health::Unavailable(detail) => {
                    return Err(format!("inbound stream unavailable: {detail}"));
                }
                Health::Stopped => return Err(DEMUX_STOPPED.to_string()),
            }
            state.waiters.insert(
                request_id.to_string(),
                Waiter {
                    expected_sender: expected_sender.to_string(),
                    tx,
                },
            );
        }
        Ok(Registration {
            pending: self.clone(),
            request_id: request_id.to_string(),
            rx,
        })
    }

    /// Why the inbound stream cannot deliver replies right now, or `None`
    /// while it is healthy.
    pub(crate) fn inbound_error(&self) -> Option<String> {
        match self.lock().health() {
            Health::Healthy => None,
            Health::Unavailable(detail) => Some(format!("inbound stream unavailable: {detail}")),
            Health::Stopped => Some(DEMUX_STOPPED.to_string()),
        }
    }

    /// Route `document` to the waiter registered under its `threadId`, if
    /// `sender` — the sender the transport authenticated, `None` when it
    /// authenticated none — is the party that waiter's request was addressed
    /// to. A document from anyone else leaves the waiter in place, so it can
    /// neither complete nor cancel the exchange.
    pub(crate) fn route(&self, document: TrustTask<Value>, sender: Option<&str>) -> RouteOutcome {
        let Some(thread_id) = document.thread_id.clone() else {
            return RouteOutcome::Unsolicited;
        };
        // Take the sender under the lock, send after releasing it.
        let waiter = {
            let mut state = self.lock();
            let Some(waiter) = state.waiters.get(&thread_id) else {
                return RouteOutcome::Unsolicited;
            };
            if !sender.is_some_and(|s| same_reference(s, &waiter.expected_sender)) {
                return RouteOutcome::WrongSender {
                    expected: waiter.expected_sender.clone(),
                };
            }
            state.waiters.remove(&thread_id)
        };
        match waiter.map(|waiter| waiter.tx.send(Ok(document)).is_ok()) {
            Some(true) => RouteOutcome::Delivered,
            _ => RouteOutcome::Unsolicited,
        }
    }

    /// Run one exchange: register the waiter, drive `send`, and wait up to
    /// `reply_timeout` for the reply.
    ///
    /// The waiter is removed however this ends, including when the returned
    /// future is dropped before it completes.
    pub(crate) async fn exchange<S>(
        &self,
        kind: TransportKind,
        request_id: &str,
        recipient: &str,
        reply_timeout: Duration,
        send: S,
    ) -> Result<TrustTask<Value>, TrqlError>
    where
        S: Future<Output = Result<(), TrqlError>>,
    {
        let transport_error = |detail: String| TrqlError::Transport { kind, detail };

        // Register before sending so a fast reply cannot be lost.
        let mut registration = self
            .register(request_id, recipient)
            .map_err(transport_error)?;
        send.await?;

        match tokio::time::timeout(reply_timeout, registration.receiver()).await {
            Ok(Ok(Ok(document))) => Ok(document),
            // The demux task failed the waiter: the stream is unavailable.
            Ok(Ok(Err(detail))) => Err(transport_error(detail)),
            // The sender was dropped without a reply: the demux task ended
            // (its monitor closes every waiter on the way out).
            Ok(Err(_closed)) => Err(transport_error(DEMUX_STOPPED.to_string())),
            Err(_elapsed) => Err(TrqlError::Timeout {
                kind,
                waited_secs: reply_timeout.as_secs(),
            }),
        }
    }

    /// Mark the stream unavailable and fail every waiter with `detail`.
    fn mark_unavailable(&self, detail: &str) {
        let waiters = {
            let mut state = self.lock();
            if state.health() == &Health::Stopped {
                return;
            }
            state.health = Some(Health::Unavailable(detail.to_string()));
            std::mem::take(&mut state.waiters)
        };
        for waiter in waiters.into_values() {
            let _ = waiter
                .tx
                .send(Err(format!("inbound stream unavailable: {detail}")));
        }
    }

    /// Clear an unavailable state after a successful poll.
    fn mark_healthy(&self) {
        let mut state = self.lock();
        if matches!(state.health(), Health::Unavailable(_)) {
            state.health = Some(Health::Healthy);
        }
    }

    /// The demux task has ended: refuse new exchanges and close every waiter
    /// (dropping its sender), so each sees "reply demux task stopped".
    fn mark_stopped(&self) {
        let waiters = {
            let mut state = self.lock();
            state.health = Some(Health::Stopped);
            std::mem::take(&mut state.waiters)
        };
        drop(waiters);
    }

    /// How many exchanges are waiting for a reply.
    pub(crate) fn waiting(&self) -> usize {
        self.lock().waiters.len()
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, State> {
        // A poisoned map only means another thread panicked mid-insert; the
        // map itself is still coherent for our usage.
        self.inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

/// The error an exchange reports once the demux task has ended.
pub(crate) const DEMUX_STOPPED: &str = "reply demux task stopped";

/// The demux task's view of its own stream: counts consecutive failures,
/// escalates the logging, computes the backoff, and publishes the health
/// that exchanges observe. Owned by the demux task; its `Drop` (which also
/// runs when the task panics or is aborted) marks the transport stopped.
pub(crate) struct InboundMonitor {
    pending: PendingReplies,
    kind: TransportKind,
    consecutive_failures: u32,
}

impl InboundMonitor {
    pub(crate) fn new(pending: PendingReplies, kind: TransportKind) -> Self {
        Self {
            pending,
            kind,
            consecutive_failures: 0,
        }
    }

    /// A poll of the stream succeeded (with or without a message).
    pub(crate) fn succeeded(&mut self) {
        if self.consecutive_failures > 0 {
            info!(
                transport = %self.kind,
                failures = self.consecutive_failures,
                "trql-client reply stream recovered"
            );
            self.consecutive_failures = 0;
            self.pending.mark_healthy();
        }
    }

    /// A poll of the stream failed with `detail`. Returns how long to wait
    /// before polling again.
    pub(crate) fn failed(&mut self, detail: &str) -> Duration {
        self.consecutive_failures = self.consecutive_failures.saturating_add(1);
        let n = self.consecutive_failures;
        let kind = self.kind;
        if n == 1 {
            warn!(transport = %kind, "trql-client reply stream failed (retrying): {detail}");
        } else if n == UNAVAILABLE_AFTER {
            error!(
                transport = %kind,
                failures = n,
                "trql-client reply stream unavailable; failing in-flight and new registry \
                 queries until it recovers: {detail}"
            );
            self.pending.mark_unavailable(detail);
        } else if n > UNAVAILABLE_AFTER && n.is_multiple_of(WARN_EVERY) {
            warn!(transport = %kind, failures = n, "trql-client reply stream still unavailable: {detail}");
        } else {
            debug!(transport = %kind, failures = n, "trql-client reply stream failed: {detail}");
        }
        if n > UNAVAILABLE_AFTER {
            // Keep the reported reason current.
            self.pending.mark_unavailable(detail);
        }
        backoff(n)
    }
}

impl Drop for InboundMonitor {
    fn drop(&mut self) {
        if std::thread::panicking() {
            error!(transport = %self.kind, "trql-client reply demux task panicked; the transport can no longer receive replies");
        } else {
            debug!(transport = %self.kind, "trql-client reply demux task stopped");
        }
        self.pending.mark_stopped();
    }
}

/// Exponential backoff for the `n`th consecutive failure (`n >= 1`), capped
/// at [`BACKOFF_MAX`], plus up to a quarter of it in random jitter.
fn backoff(n: u32) -> Duration {
    let exponent = n.saturating_sub(1).min(16);
    let base = BACKOFF_INITIAL
        .saturating_mul(1u32 << exponent)
        .min(BACKOFF_MAX);
    let quarter_ms = u64::try_from(base.as_millis() / 4).unwrap_or(0).max(1);
    let random = u64::try_from(uuid::Uuid::new_v4().as_u128() & u128::from(u64::MAX)).unwrap_or(0);
    base + Duration::from_millis(random % quarter_ms)
}

#[cfg(test)]
pub(crate) mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;

    pub(crate) const REGISTRY: &str = "did:example:registry";
    pub(crate) const OTHER: &str = "did:example:someone-else";

    /// A well-formed authorization `#response` correlated to `request_id`
    /// that echoes the asked tuple, as the registry would send it.
    pub(crate) fn reply_to(request_id: &str) -> TrustTask<Value> {
        let mut doc = TrustTask::new(
            "urn:uuid:reply".to_string(),
            "https://trusttasks.org/spec/registry/authorization/0.2#response"
                .parse()
                .unwrap(),
            serde_json::json!({
                "entity_id": "did:example:e",
                "authority_id": "did:example:a",
                "action": "act",
                "resource": "res",
                "authorized": true,
            }),
        );
        doc.thread_id = Some(request_id.to_string());
        doc
    }

    fn try_reply(registration: &mut Registration) -> Result<Reply, oneshot::error::TryRecvError> {
        registration.receiver().try_recv()
    }

    #[test]
    fn a_reply_from_the_addressed_party_is_delivered() {
        let pending = PendingReplies::new();
        let mut reg = pending.register("req-1", REGISTRY).unwrap();
        assert_eq!(
            pending.route(reply_to("req-1"), Some(REGISTRY)),
            RouteOutcome::Delivered
        );
        let reply = try_reply(&mut reg).unwrap().unwrap();
        assert_eq!(reply.thread_id.as_deref(), Some("req-1"));
        assert_eq!(pending.waiting(), 0, "a delivered waiter leaves the map");
    }

    #[test]
    fn each_reply_reaches_its_own_waiter() {
        let pending = PendingReplies::new();
        let mut first = pending.register("req-1", REGISTRY).unwrap();
        let mut second = pending.register("req-2", REGISTRY).unwrap();
        assert_eq!(
            pending.route(reply_to("req-2"), Some(REGISTRY)),
            RouteOutcome::Delivered
        );
        assert!(matches!(
            try_reply(&mut first),
            Err(oneshot::error::TryRecvError::Empty)
        ));
        let got = try_reply(&mut second).unwrap().unwrap();
        assert_eq!(got.thread_id.as_deref(), Some("req-2"));
        assert_eq!(
            pending.route(reply_to("req-1"), Some(REGISTRY)),
            RouteOutcome::Delivered
        );
        let got = try_reply(&mut first).unwrap().unwrap();
        assert_eq!(got.thread_id.as_deref(), Some("req-1"));
    }

    #[test]
    fn a_correlated_reply_from_another_party_does_not_complete_the_exchange() {
        let pending = PendingReplies::new();
        let mut reg = pending.register("req-1", REGISTRY).unwrap();

        assert_eq!(
            pending.route(reply_to("req-1"), Some(OTHER)),
            RouteOutcome::WrongSender {
                expected: REGISTRY.to_string()
            }
        );
        // Neither completed nor cancelled.
        assert!(matches!(
            try_reply(&mut reg),
            Err(oneshot::error::TryRecvError::Empty)
        ));

        // The registry's own reply still gets through afterwards.
        assert_eq!(
            pending.route(reply_to("req-1"), Some(REGISTRY)),
            RouteOutcome::Delivered
        );
        assert!(try_reply(&mut reg).is_ok());
    }

    #[test]
    fn a_reply_with_no_authenticated_sender_does_not_complete_the_exchange() {
        let pending = PendingReplies::new();
        let mut reg = pending.register("req-1", REGISTRY).unwrap();
        assert!(matches!(
            pending.route(reply_to("req-1"), None),
            RouteOutcome::WrongSender { .. }
        ));
        assert!(matches!(
            try_reply(&mut reg),
            Err(oneshot::error::TryRecvError::Empty)
        ));
    }

    #[test]
    fn an_uncorrelated_reply_is_unsolicited() {
        let pending = PendingReplies::new();
        let _reg = pending.register("req-1", REGISTRY).unwrap();
        assert_eq!(
            pending.route(reply_to("req-2"), Some(REGISTRY)),
            RouteOutcome::Unsolicited
        );
        let mut no_thread = reply_to("req-1");
        no_thread.thread_id = None;
        assert_eq!(
            pending.route(no_thread, Some(REGISTRY)),
            RouteOutcome::Unsolicited
        );
    }

    #[test]
    fn a_did_scid_sender_matches_regardless_of_its_src_locator() {
        let pending = PendingReplies::new();
        let mut reg = pending
            .register("req-1", "did:scid:vh:1:Qm?src=example.com/r")
            .unwrap();
        assert_eq!(
            pending.route(reply_to("req-1"), Some("did:scid:vh:1:Qm")),
            RouteOutcome::Delivered
        );
        assert!(try_reply(&mut reg).is_ok());
    }

    #[test]
    fn dropping_a_registration_removes_its_waiter() {
        let pending = PendingReplies::new();
        let reg = pending.register("req-1", REGISTRY).unwrap();
        assert_eq!(pending.waiting(), 1);
        drop(reg);
        assert_eq!(pending.waiting(), 0);
        // A reply arriving afterwards is late, not delivered to a dead waiter.
        assert_eq!(
            pending.route(reply_to("req-1"), Some(REGISTRY)),
            RouteOutcome::Unsolicited
        );
    }

    #[test]
    fn a_reply_to_a_dropped_receiver_is_unsolicited() {
        let pending = PendingReplies::new();
        let mut reg = pending.register("req-1", REGISTRY).unwrap();
        // Close the receiver while the waiter is still registered.
        reg.receiver().close();
        assert_eq!(
            pending.route(reply_to("req-1"), Some(REGISTRY)),
            RouteOutcome::Unsolicited
        );
    }

    // --- exchange cancellation ----------------------------------------------

    /// The future returned by `exchange`, dropped while it awaits the reply,
    /// leaves nothing behind in the map.
    #[tokio::test]
    async fn dropping_the_exchange_future_while_awaiting_the_reply_removes_the_waiter() {
        let pending = PendingReplies::new();
        let exchange = pending.exchange(
            TransportKind::Didcomm,
            "req-1",
            REGISTRY,
            Duration::from_secs(60),
            async { Ok(()) },
        );
        // A caller's own, shorter deadline cancels the exchange.
        let outcome = tokio::time::timeout(Duration::from_millis(50), exchange).await;
        assert!(outcome.is_err(), "the exchange should still be waiting");
        assert_eq!(
            pending.waiting(),
            0,
            "the cancelled exchange leaked its waiter"
        );
    }

    /// The same while the send itself is still in flight.
    #[tokio::test]
    async fn dropping_the_exchange_future_while_sending_removes_the_waiter() {
        let pending = PendingReplies::new();
        let exchange = pending.exchange(
            TransportKind::Tsp,
            "req-1",
            REGISTRY,
            Duration::from_secs(60),
            std::future::pending::<Result<(), TrqlError>>(),
        );
        let outcome = tokio::time::timeout(Duration::from_millis(50), exchange).await;
        assert!(outcome.is_err());
        assert_eq!(pending.waiting(), 0);
    }

    #[tokio::test]
    async fn a_failed_send_removes_the_waiter() {
        let pending = PendingReplies::new();
        let err = pending
            .exchange(
                TransportKind::Didcomm,
                "req-1",
                REGISTRY,
                Duration::from_secs(60),
                async {
                    Err(TrqlError::Transport {
                        kind: TransportKind::Didcomm,
                        detail: "send failed".into(),
                    })
                },
            )
            .await
            .unwrap_err();
        assert!(matches!(err, TrqlError::Transport { .. }), "{err}");
        assert_eq!(pending.waiting(), 0);
    }

    #[tokio::test]
    async fn a_timed_out_exchange_removes_the_waiter() {
        let pending = PendingReplies::new();
        let err = pending
            .exchange(
                TransportKind::Didcomm,
                "req-1",
                REGISTRY,
                Duration::from_millis(20),
                async { Ok(()) },
            )
            .await
            .unwrap_err();
        assert!(matches!(err, TrqlError::Timeout { .. }), "{err}");
        assert_eq!(pending.waiting(), 0);
    }

    #[tokio::test]
    async fn an_exchange_returns_the_routed_reply() {
        let pending = PendingReplies::new();
        let router = pending.clone();
        tokio::spawn(async move {
            // Route once the waiter exists.
            while router.waiting() == 0 {
                tokio::task::yield_now().await;
            }
            router.route(reply_to("req-1"), Some(REGISTRY));
        });
        let reply = pending
            .exchange(
                TransportKind::Didcomm,
                "req-1",
                REGISTRY,
                Duration::from_secs(5),
                async { Ok(()) },
            )
            .await
            .unwrap();
        assert_eq!(reply.thread_id.as_deref(), Some("req-1"));
        assert_eq!(pending.waiting(), 0);
    }

    // --- inbound health -----------------------------------------------------

    #[tokio::test]
    async fn a_persistently_failing_stream_fails_waiters_fast_and_refuses_new_ones() {
        let pending = PendingReplies::new();
        let mut monitor = InboundMonitor::new(pending.clone(), TransportKind::Didcomm);

        let waiting = {
            let pending = pending.clone();
            tokio::spawn(async move {
                pending
                    .exchange(
                        TransportKind::Didcomm,
                        "req-1",
                        REGISTRY,
                        Duration::from_secs(60),
                        async { Ok(()) },
                    )
                    .await
            })
        };
        while pending.waiting() == 0 {
            tokio::task::yield_now().await;
        }

        // Fewer than the threshold: a transient blip changes nothing.
        for _ in 1..UNAVAILABLE_AFTER {
            monitor.failed("websocket closed");
        }
        assert_eq!(pending.waiting(), 1);
        assert_eq!(pending.inbound_error(), None);

        monitor.failed("websocket closed");
        let err = tokio::time::timeout(Duration::from_secs(5), waiting)
            .await
            .expect("the waiter must fail fast, not wait out the reply window")
            .unwrap()
            .unwrap_err();
        match &err {
            TrqlError::Transport { detail, .. } => {
                assert!(detail.contains("inbound stream unavailable"), "{detail}");
                assert!(detail.contains("websocket closed"), "{detail}");
            }
            other => panic!("expected Transport, got {other}"),
        }

        // A new exchange is refused up front, before anything is sent.
        let sent = std::sync::atomic::AtomicBool::new(false);
        let err = pending
            .exchange(
                TransportKind::Didcomm,
                "req-2",
                REGISTRY,
                Duration::from_secs(60),
                async {
                    sent.store(true, std::sync::atomic::Ordering::Relaxed);
                    Ok(())
                },
            )
            .await
            .unwrap_err();
        assert!(matches!(err, TrqlError::Transport { .. }), "{err}");
        assert!(!sent.load(std::sync::atomic::Ordering::Relaxed));
        assert!(pending.inbound_error().is_some());

        // Not latched: one good poll clears it.
        monitor.succeeded();
        assert_eq!(pending.inbound_error(), None);
        assert!(pending.register("req-3", REGISTRY).is_ok());
    }

    #[tokio::test]
    async fn a_stopped_demux_task_is_reported_not_timed_out() {
        let pending = PendingReplies::new();
        let monitor = InboundMonitor::new(pending.clone(), TransportKind::Tsp);
        let waiting = {
            let pending = pending.clone();
            tokio::spawn(async move {
                pending
                    .exchange(
                        TransportKind::Tsp,
                        "req-1",
                        REGISTRY,
                        Duration::from_secs(60),
                        async { Ok(()) },
                    )
                    .await
            })
        };
        while pending.waiting() == 0 {
            tokio::task::yield_now().await;
        }

        // The demux task ends (panic or abort drops its monitor).
        drop(monitor);

        let err = tokio::time::timeout(Duration::from_secs(5), waiting)
            .await
            .expect("a stopped demux task must not surface as a timeout")
            .unwrap()
            .unwrap_err();
        match &err {
            TrqlError::Transport { detail, .. } => assert_eq!(detail, DEMUX_STOPPED),
            other => panic!("expected Transport, got {other}"),
        }
        assert!(pending.register("req-2", REGISTRY).is_err());
    }

    #[tokio::test]
    async fn a_panicking_demux_task_is_reported() {
        let pending = PendingReplies::new();
        let monitor = InboundMonitor::new(pending.clone(), TransportKind::Didcomm);
        let task = tokio::spawn(async move {
            let _monitor = monitor;
            panic!("demux bug");
        });
        assert!(task.await.is_err());
        assert_eq!(pending.inbound_error().as_deref(), Some(DEMUX_STOPPED));
    }

    #[test]
    fn backoff_grows_and_is_capped() {
        assert!(backoff(1) >= BACKOFF_INITIAL);
        assert!(backoff(1) < BACKOFF_INITIAL * 2);
        assert!(backoff(3) >= BACKOFF_INITIAL * 4);
        for n in [10, 100, u32::MAX] {
            let delay = backoff(n);
            assert!(delay >= BACKOFF_MAX, "{delay:?}");
            assert!(delay <= BACKOFF_MAX + BACKOFF_MAX / 4, "{delay:?}");
        }
    }
}
