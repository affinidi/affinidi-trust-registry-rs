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
//! Two signals say whether replies can arrive: the demux task's polls of the
//! stream ([`InboundMonitor`]), and the profile's websocket connection state,
//! followed by [`watch_connection`]. The SDK keeps reconnecting a websocket
//! whose mediator is unreachable or rejects the profile's credentials, and a
//! poll during that time returns "no message" rather than an error, so the
//! polls alone would look healthy; the connection state does not.
//!
//! Once the stream has been failing (poll errors, or the websocket not
//! connected) without a break for [`UNAVAILABLE_AFTER`], it is marked
//! unavailable: every waiter is failed at once with the reason, and new
//! exchanges are refused up front, rather than each waiting out the full
//! reply window and reporting a timeout that points at the registry. The
//! threshold is time, not a count, so a brief blip (a reconnect, a few quick
//! errors) does not fail queries. The state clears as soon as both signals
//! are good again (it is never latched). When the demux task ends (panic or
//! abort) the monitor's `Drop` marks the transport stopped and closes every
//! waiter.

use std::collections::HashMap;
use std::future::Future;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use affinidi_messaging_core::ConnState;
use affinidi_tdk::did_common::scid::same_reference;
use affinidi_tdk::messaging::profiles::ATMProfile;
use serde_json::Value;
use tokio::sync::{oneshot, watch};
use tracing::{debug, error, info, warn};
use trust_tasks_rs::TrustTask;

use crate::error::TrqlError;
use crate::transport::TransportKind;

/// How long the inbound side must have been failing without a break (poll
/// errors, or the websocket not connected) before the stream is reported
/// unavailable and in-flight and new exchanges fail fast.
pub(crate) const UNAVAILABLE_AFTER: Duration = Duration::from_secs(10);
/// First retry delay after an inbound-stream failure.
const BACKOFF_INITIAL: Duration = Duration::from_millis(500);
/// Ceiling on the retry delay.
const BACKOFF_MAX: Duration = Duration::from_secs(5);
/// While polls keep failing, repeat the warning every this many failures.
const WARN_EVERY: u32 = 20;
/// How often the connection watcher re-checks the websocket state when it
/// has not changed, so the time threshold is noticed.
const CONNECTION_RECHECK: Duration = Duration::from_secs(1);

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
    /// Receiving normally (or not failing for long enough to matter).
    Healthy,
    /// The stream has been failing for [`UNAVAILABLE_AFTER`]; carries why.
    /// Cleared once polls succeed and the websocket is connected again.
    Unavailable(String),
    /// The demux task has ended; nothing will ever be routed again.
    Stopped,
}

/// Something the demux task or the connection watcher observed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum InboundEvent {
    /// A poll of the stream returned (with or without a message).
    PollOk,
    /// A poll of the stream failed.
    PollFailed(String),
    /// The profile's websocket is connected.
    Connected,
    /// The profile's websocket is not connected (dropped, still connecting,
    /// or not running at all).
    Disconnected,
    /// Nothing new; re-evaluate the time threshold (tests; the watcher
    /// re-reports the connection state instead).
    #[cfg(test)]
    Tick,
}

/// The two failure signals and since when each has held.
#[derive(Default)]
struct InboundSignals {
    /// When the current run of poll errors began, and the latest error.
    poll_failing: Option<(Instant, String)>,
    /// Since when the websocket has not been connected.
    disconnected_since: Option<Instant>,
}

impl InboundSignals {
    /// Why the stream counts as unavailable at `now`, if it does.
    fn verdict(&self, now: Instant) -> Option<String> {
        if let Some((since, detail)) = &self.poll_failing {
            let failing = now.saturating_duration_since(*since);
            if failing >= UNAVAILABLE_AFTER {
                return Some(format!(
                    "{detail} (polls failing for {}s)",
                    failing.as_secs()
                ));
            }
        }
        if let Some(since) = self.disconnected_since {
            let down = now.saturating_duration_since(since);
            if down >= UNAVAILABLE_AFTER {
                return Some(format!(
                    "the mediator websocket has not been connected for {}s \
                     (mediator unreachable, credentials rejected, or live delivery not enabled)",
                    down.as_secs()
                ));
            }
        }
        None
    }
}

#[derive(Default)]
struct State {
    waiters: HashMap<String, Waiter>,
    health: Option<Health>,
    signals: InboundSignals,
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
                waited_secs: crate::error::whole_secs_rounded_up(reply_timeout),
            }),
        }
    }

    /// Record an inbound observation made at `now`, and move between healthy
    /// and unavailable when the verdict changes: becoming unavailable fails
    /// every waiter with the reason (logged at `error`); recovering is logged
    /// at `info`.
    pub(crate) fn observe(&self, kind: TransportKind, event: InboundEvent, now: Instant) {
        enum Transition {
            Down(String, HashMap<String, Waiter>),
            Up,
        }
        let transition = {
            let mut state = self.lock();
            if state.health() == &Health::Stopped {
                return;
            }
            let signals = &mut state.signals;
            match event {
                InboundEvent::PollOk => signals.poll_failing = None,
                InboundEvent::PollFailed(detail) => match &mut signals.poll_failing {
                    Some((_, last)) => *last = detail,
                    None => signals.poll_failing = Some((now, detail)),
                },
                InboundEvent::Connected => signals.disconnected_since = None,
                InboundEvent::Disconnected => {
                    signals.disconnected_since.get_or_insert(now);
                }
                #[cfg(test)]
                InboundEvent::Tick => {}
            }
            let verdict = state.signals.verdict(now);
            match (state.health().clone(), verdict) {
                (Health::Healthy, Some(reason)) => {
                    state.health = Some(Health::Unavailable(reason.clone()));
                    Some(Transition::Down(reason, std::mem::take(&mut state.waiters)))
                }
                (Health::Unavailable(_), Some(reason)) => {
                    // Keep the reported reason current.
                    state.health = Some(Health::Unavailable(reason));
                    None
                }
                (Health::Unavailable(_), None) => {
                    state.health = Some(Health::Healthy);
                    Some(Transition::Up)
                }
                _ => None,
            }
        };
        match transition {
            Some(Transition::Down(reason, waiters)) => {
                error!(
                    transport = %kind,
                    in_flight = waiters.len(),
                    "trql-client reply stream unavailable; failing in-flight and new registry \
                     queries until it recovers: {reason}"
                );
                for waiter in waiters.into_values() {
                    let _ = waiter
                        .tx
                        .send(Err(format!("inbound stream unavailable: {reason}")));
                }
            }
            Some(Transition::Up) => {
                info!(transport = %kind, "trql-client reply stream recovered");
            }
            None => {}
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

/// The demux task's view of its own polls: counts consecutive failures for
/// the backoff and the logging, and reports each poll to the shared health.
/// Owned by the demux task; its `Drop` (which also runs when the task panics
/// or is aborted) marks the transport stopped.
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

    /// A poll of the stream returned (with or without a message). A poll
    /// that returns nothing while the websocket is down is not proof of
    /// health; the connection watcher reports that side.
    pub(crate) fn succeeded(&mut self) {
        if self.consecutive_failures > 0 {
            info!(
                transport = %self.kind,
                failures = self.consecutive_failures,
                "trql-client reply stream polls succeed again"
            );
            self.consecutive_failures = 0;
        }
        self.pending
            .observe(self.kind, InboundEvent::PollOk, Instant::now());
    }

    /// A poll of the stream failed with `detail`. Returns how long to wait
    /// before polling again.
    pub(crate) fn failed(&mut self, detail: &str) -> Duration {
        self.consecutive_failures = self.consecutive_failures.saturating_add(1);
        let n = self.consecutive_failures;
        let kind = self.kind;
        if n == 1 {
            warn!(transport = %kind, "trql-client reply stream poll failed (retrying): {detail}");
        } else if n.is_multiple_of(WARN_EVERY) {
            warn!(transport = %kind, failures = n, "trql-client reply stream polls still failing: {detail}");
        } else {
            debug!(transport = %kind, failures = n, "trql-client reply stream poll failed: {detail}");
        }
        self.pending.observe(
            kind,
            InboundEvent::PollFailed(detail.to_string()),
            Instant::now(),
        );
        backoff(n)
    }
}

/// Follow `profile`'s websocket connection state for the life of the
/// transport and report it to `pending`'s health (see the module docs).
///
/// Spawned beside the demux task and aborted with it. While no websocket
/// transport is running for the profile, the stream counts as disconnected.
pub(crate) async fn watch_connection(
    profile: Arc<ATMProfile>,
    pending: PendingReplies,
    kind: TransportKind,
) {
    let mut last = None;
    loop {
        match profile.connection_state().await {
            Some(rx) => follow_connection(rx, &pending, kind, &mut last).await,
            None => {
                note_connection(
                    &pending,
                    kind,
                    false,
                    &mut last,
                    "no websocket is running for the profile",
                );
                tokio::time::sleep(CONNECTION_RECHECK).await;
            }
        }
    }
}

/// Report every state `rx` takes until its sender goes away (the SDK's
/// websocket task ended), re-checking at least every [`CONNECTION_RECHECK`]
/// so the time threshold is noticed.
async fn follow_connection(
    mut rx: watch::Receiver<ConnState>,
    pending: &PendingReplies,
    kind: TransportKind,
    last: &mut Option<bool>,
) {
    loop {
        let state = *rx.borrow_and_update();
        let connected = state == ConnState::Connected;
        note_connection(pending, kind, connected, last, &format!("{state:?}"));
        tokio::select! {
            changed = rx.changed() => {
                if changed.is_err() {
                    note_connection(pending, kind, false, last, "the websocket task ended");
                    return;
                }
            }
            () = tokio::time::sleep(CONNECTION_RECHECK) => {}
        }
    }
}

/// Report one connection observation, logging a change of state.
fn note_connection(
    pending: &PendingReplies,
    kind: TransportKind,
    connected: bool,
    last: &mut Option<bool>,
    detail: &str,
) {
    match (*last, connected) {
        (Some(true), false) => {
            warn!(transport = %kind, "trql-client mediator websocket disconnected: {detail}");
        }
        (Some(false), true) => {
            info!(transport = %kind, "trql-client mediator websocket connected");
        }
        _ => {}
    }
    *last = Some(connected);
    let event = if connected {
        InboundEvent::Connected
    } else {
        InboundEvent::Disconnected
    };
    pending.observe(kind, event, Instant::now());
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
        // A 20 ms window reports 1 second, not "timed out after 0s".
        assert!(
            matches!(err, TrqlError::Timeout { waited_secs: 1, .. }),
            "{err}"
        );
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

    /// Spawn an exchange that waits for a reply, once its waiter exists.
    async fn waiting_exchange(
        pending: &PendingReplies,
    ) -> tokio::task::JoinHandle<Result<TrustTask<Value>, TrqlError>> {
        let handle = {
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
        handle
    }

    /// The waiter fails fast with a Transport error naming `needle`.
    async fn fails_fast_naming(
        waiting: tokio::task::JoinHandle<Result<TrustTask<Value>, TrqlError>>,
        needle: &str,
    ) {
        let err = tokio::time::timeout(Duration::from_secs(5), waiting)
            .await
            .expect("the waiter must fail fast, not wait out the reply window")
            .unwrap()
            .unwrap_err();
        match &err {
            TrqlError::Transport { detail, .. } => {
                assert!(detail.contains("inbound stream unavailable"), "{detail}");
                assert!(detail.contains(needle), "{detail}");
            }
            other => panic!("expected Transport, got {other}"),
        }
    }

    const KIND: TransportKind = TransportKind::Didcomm;

    #[tokio::test]
    async fn polls_failing_for_the_threshold_fail_waiters_fast_and_refuse_new_ones() {
        let pending = PendingReplies::new();
        let waiting = waiting_exchange(&pending).await;
        let t0 = Instant::now();
        let failed = || InboundEvent::PollFailed("websocket closed".into());

        // Many quick failures inside the threshold change nothing.
        for ms in [0, 100, 200, 500, 1500] {
            pending.observe(KIND, failed(), t0 + Duration::from_millis(ms));
        }
        assert_eq!(pending.waiting(), 1);
        assert_eq!(pending.inbound_error(), None);

        // Still failing once the threshold has passed.
        pending.observe(KIND, failed(), t0 + UNAVAILABLE_AFTER);
        fails_fast_naming(waiting, "websocket closed").await;

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
        pending.observe(KIND, InboundEvent::PollOk, t0 + UNAVAILABLE_AFTER * 2);
        assert_eq!(pending.inbound_error(), None);
        assert!(pending.register("req-3", REGISTRY).is_ok());
    }

    #[test]
    fn a_poll_success_breaks_a_run_of_failures() {
        let pending = PendingReplies::new();
        let t0 = Instant::now();
        pending.observe(KIND, InboundEvent::PollFailed("x".into()), t0);
        pending.observe(KIND, InboundEvent::PollOk, t0 + UNAVAILABLE_AFTER / 2);
        pending.observe(
            KIND,
            InboundEvent::PollFailed("x".into()),
            t0 + UNAVAILABLE_AFTER,
        );
        assert_eq!(pending.inbound_error(), None, "the run restarted");
    }

    /// The reviewer's case: a mediator that is unreachable or rejects the
    /// credentials leaves the SDK reconnecting, and every poll returns
    /// "nothing" rather than an error. The connection state still trips it.
    #[tokio::test]
    async fn a_disconnected_websocket_trips_even_though_polls_return_ok() {
        let pending = PendingReplies::new();
        let waiting = waiting_exchange(&pending).await;
        let t0 = Instant::now();
        pending.observe(KIND, InboundEvent::Disconnected, t0);
        for secs in 1..UNAVAILABLE_AFTER.as_secs() {
            let now = t0 + Duration::from_secs(secs);
            pending.observe(KIND, InboundEvent::PollOk, now);
            pending.observe(KIND, InboundEvent::Disconnected, now);
        }
        assert_eq!(pending.inbound_error(), None, "not yet");
        pending.observe(KIND, InboundEvent::PollOk, t0 + UNAVAILABLE_AFTER);
        fails_fast_naming(waiting, "websocket has not been connected").await;

        // Reconnecting clears it.
        pending.observe(KIND, InboundEvent::Connected, t0 + UNAVAILABLE_AFTER * 2);
        assert_eq!(pending.inbound_error(), None);
    }

    /// A reconnect inside the threshold is a blip, not an outage.
    #[test]
    fn a_brief_disconnect_changes_nothing() {
        let pending = PendingReplies::new();
        let t0 = Instant::now();
        pending.observe(KIND, InboundEvent::Disconnected, t0);
        pending.observe(KIND, InboundEvent::Connected, t0 + Duration::from_secs(2));
        pending.observe(KIND, InboundEvent::Tick, t0 + UNAVAILABLE_AFTER * 3);
        assert_eq!(pending.inbound_error(), None);
    }

    /// The watcher follows a real `watch` channel of the SDK's `ConnState`.
    #[tokio::test]
    async fn the_connection_watcher_reports_the_websocket_state() {
        let pending = PendingReplies::new();
        let (tx, rx) = watch::channel(ConnState::Connecting);
        let follower = {
            let pending = pending.clone();
            tokio::spawn(async move {
                let mut last = None;
                follow_connection(rx, &pending, KIND, &mut last).await;
                last
            })
        };
        // Give the follower its first look: not connected yet.
        while pending.lock().signals.disconnected_since.is_none() {
            tokio::task::yield_now().await;
        }
        pending.observe(KIND, InboundEvent::Tick, Instant::now() + UNAVAILABLE_AFTER);
        assert!(pending.inbound_error().is_some(), "never connected");

        tx.send(ConnState::Connected).unwrap();
        while pending.inbound_error().is_some() {
            tokio::task::yield_now().await;
        }

        tx.send(ConnState::Disconnected).unwrap();
        while pending.lock().signals.disconnected_since.is_none() {
            tokio::task::yield_now().await;
        }

        // The SDK's websocket task ends: the follower returns, disconnected.
        drop(tx);
        let last = tokio::time::timeout(Duration::from_secs(5), follower)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(last, Some(false));
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
