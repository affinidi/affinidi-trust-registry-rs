//! Delivery semantics for the pickup listener: when a message is acked
//! (deleted at the mediator), when it is left queued for redelivery, and how a
//! message seen on both the live stream and the offline sync is dispatched only
//! once.
//!
//! # The contract
//!
//! - **Ack after handling (R1.6).** Both the live stream and the offline sync
//!   pull with `auto_delete = false`. A message is deleted at the mediator only
//!   once its handler has returned — for a registry write, once the
//!   [`TaskHandler`](crate::trust_tasks::TaskHandler) has applied it and
//!   recorded the outcome in its dedup store.
//! - **Poison is acked, transient is not.** A failure that is a property of the
//!   bytes is acked at once so it does not stall the queue. Anything else — a
//!   handler error, a timeout, a panic, an unpack failure whose class the SDK
//!   does not report — leaves the message queued, so the offline sync offers
//!   it again. That redelivery is bounded: after [`GIVE_UP_ATTEMPTS`] failures
//!   spread over at least [`GIVE_UP_MIN_AGE`] the message is acked as poison
//!   and logged at `error`, so one bad message cannot loop forever.
//! - **Dispatched once (R1.4).** The live stream and the offline sync drain the
//!   same mediator queue, and a message stays queued until its ack lands. The
//!   [`DeliveryLedger`] remembers, by mediator message id, what is in flight
//!   and what has been handled: a message already in flight is skipped, and a
//!   message already handled whose ack did not land is acked again rather than
//!   handled again. Registry writes are additionally idempotent on the Trust
//!   Task id in the `TaskHandler`; the ledger is what keeps reads (and their
//!   replies) from being answered twice.
//!
//! The ledger lives in memory. A restart forgets it, so a message handled but
//! not yet acked when the process stopped is handled again after the restart;
//! writes are replayed rather than reapplied while the Trust Task dedup store
//! remembers them (see [`crate::dedup`]).

use std::collections::{HashMap, VecDeque};
use std::time::Duration;

use affinidi_tdk::messaging::errors::ATMError;
use tokio::time::Instant;

/// Handlers allowed to run at once on the pickup path. The receive loop waits
/// for a permit before taking the next message off the socket, so a burst
/// queues at the mediator instead of in this process. The same bound as the
/// delivery-layer path (`messaging::service`).
pub(crate) const MAX_INFLIGHT_HANDLERS: usize = 32;

/// Longest a single handler may run (DID resolution, the repository, packing
/// and sending the reply). A handler that overruns is abandoned and its message
/// left queued for redelivery.
pub(crate) const HANDLER_TIMEOUT: Duration = Duration::from_secs(30);

/// Longest an ack (queueing the delete with the SDK's deletion handler) may
/// take. The SDK bounds its own enqueue at 5 s; this is a backstop.
pub(crate) const ACK_TIMEOUT: Duration = Duration::from_secs(10);

/// Failures after which a message that keeps failing is acked as poison…
pub(crate) const GIVE_UP_ATTEMPTS: u32 = 5;
/// …provided it has also been failing for at least this long. Failures that
/// repeat for this long are not a passing resolver hiccup.
pub(crate) const GIVE_UP_MIN_AGE: Duration = Duration::from_secs(10 * 60);

/// How long the ledger remembers an id. Longer than [`GIVE_UP_MIN_AGE`] so a
/// failing message's count survives until it can be given up on, and many
/// offline-sync intervals long so a handled message whose ack is slow to land
/// is re-acked rather than re-handled.
pub(crate) const LEDGER_TTL: Duration = Duration::from_secs(30 * 60);

/// Most ids the ledger holds; past this the oldest is forgotten.
pub(crate) const LEDGER_CAPACITY: usize = 4_096;

/// Backoff after a failed receive: starts here…
pub(crate) const RECEIVE_BACKOFF_INITIAL: Duration = Duration::from_millis(250);
/// …and doubles up to here.
pub(crate) const RECEIVE_BACKOFF_MAX: Duration = Duration::from_secs(5);

/// How one attempt at handling a message ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Outcome {
    /// The handler returned. For a write, the outcome is recorded.
    Handled,
    /// The message can never be handled: a property of its bytes.
    Poison,
    /// It may succeed on redelivery: a handler error, a timeout, a panic, or
    /// an unpack failure the SDK did not classify.
    Retry,
}

/// What to do about the message at the mediator.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Ack {
    /// Delete it: handled, or poison.
    Now,
    /// Leave it queued; the offline sync offers it again.
    Retain,
    /// Delete it although it never succeeded: it has failed
    /// [`GIVE_UP_ATTEMPTS`] times over [`GIVE_UP_MIN_AGE`].
    GiveUp,
}

/// What a newly received copy of a message calls for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Claim {
    /// Not seen, or seen and failed: handle it.
    Dispatch,
    /// Being handled right now (the other consumer got it first): skip it, and
    /// do not ack — its handler acks when it finishes.
    InFlight,
    /// Already handled, but still queued, so the earlier ack did not land:
    /// ack it again without handling it again.
    AlreadyHandled,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Phase {
    InFlight,
    Handled,
    Failed,
}

#[derive(Debug, Clone, Copy)]
struct Entry {
    phase: Phase,
    /// Failed attempts so far; kept while a retried message is in flight again.
    attempts: u32,
    /// When it first failed, for the [`GIVE_UP_MIN_AGE`] bound.
    first_failed: Option<Instant>,
    touched: Instant,
}

/// Bounded, TTL'd memory of mediator message ids the listener has dispatched.
#[derive(Debug)]
pub(crate) struct DeliveryLedger {
    entries: HashMap<String, Entry>,
    /// Insertion order, for capacity eviction. May hold ids already removed;
    /// eviction skips those.
    order: VecDeque<String>,
    capacity: usize,
    ttl: Duration,
}

impl Default for DeliveryLedger {
    fn default() -> Self {
        Self::new(LEDGER_CAPACITY, LEDGER_TTL)
    }
}

impl DeliveryLedger {
    pub(crate) fn new(capacity: usize, ttl: Duration) -> Self {
        Self {
            entries: HashMap::new(),
            order: VecDeque::new(),
            capacity: capacity.max(1),
            ttl,
        }
    }

    /// A copy of message `id` arrived. Marks it in flight when it should be
    /// dispatched.
    pub(crate) fn claim(&mut self, id: &str, now: Instant) -> Claim {
        self.expire(now);
        let Some(entry) = self.entries.get_mut(id) else {
            self.insert(
                id,
                Entry {
                    phase: Phase::InFlight,
                    attempts: 0,
                    first_failed: None,
                    touched: now,
                },
            );
            return Claim::Dispatch;
        };
        entry.touched = now;
        match entry.phase {
            Phase::InFlight => Claim::InFlight,
            Phase::Handled => Claim::AlreadyHandled,
            Phase::Failed => {
                entry.phase = Phase::InFlight;
                Claim::Dispatch
            }
        }
    }

    /// The attempt claimed with [`claim`](Self::claim) ended with `outcome`.
    /// Returns whether to delete the message at the mediator.
    pub(crate) fn finish(&mut self, id: &str, outcome: Outcome, now: Instant) -> Ack {
        if !self.entries.contains_key(id) {
            // Evicted while in flight; remember the result anyway.
            self.insert(
                id,
                Entry {
                    phase: Phase::InFlight,
                    attempts: 0,
                    first_failed: None,
                    touched: now,
                },
            );
        }
        let Some(entry) = self.entries.get_mut(id) else {
            // Capacity 1 and inserting evicted it: nothing to remember.
            return match outcome {
                Outcome::Retry => Ack::Retain,
                _ => Ack::Now,
            };
        };
        entry.touched = now;
        match outcome {
            Outcome::Handled | Outcome::Poison => {
                entry.phase = Phase::Handled;
                Ack::Now
            }
            Outcome::Retry => {
                entry.attempts = entry.attempts.saturating_add(1);
                let first_failed = *entry.first_failed.get_or_insert(now);
                if entry.attempts >= GIVE_UP_ATTEMPTS
                    && now.saturating_duration_since(first_failed) >= GIVE_UP_MIN_AGE
                {
                    entry.phase = Phase::Handled;
                    Ack::GiveUp
                } else {
                    entry.phase = Phase::Failed;
                    Ack::Retain
                }
            }
        }
    }

    /// Undo a claim that was never attempted (shutdown while waiting for a
    /// handler slot), so a redelivery is dispatched normally.
    pub(crate) fn release(&mut self, id: &str) {
        let Some(entry) = self.entries.get_mut(id) else {
            return;
        };
        if entry.phase != Phase::InFlight {
            return;
        }
        if entry.attempts == 0 {
            self.entries.remove(id);
        } else {
            entry.phase = Phase::Failed;
        }
    }

    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.entries.len()
    }

    fn insert(&mut self, id: &str, entry: Entry) {
        self.entries.insert(id.to_string(), entry);
        self.order.push_back(id.to_string());
        while self.entries.len() > self.capacity {
            let Some(oldest) = self.order.pop_front() else {
                break;
            };
            self.entries.remove(&oldest);
        }
        // Keep `order` from growing without bound on ids already removed.
        if self.order.len() > self.capacity.saturating_mul(2) {
            let entries = &self.entries;
            let mut seen = std::collections::HashSet::new();
            self.order
                .retain(|id| entries.contains_key(id) && seen.insert(id.clone()));
        }
    }

    fn expire(&mut self, now: Instant) {
        let ttl = self.ttl;
        self.entries
            .retain(|_, entry| now.saturating_duration_since(entry.touched) < ttl);
    }
}

/// Exponential backoff for the receive loop.
#[derive(Debug)]
pub(crate) struct Backoff {
    next: Duration,
    initial: Duration,
    max: Duration,
}

impl Backoff {
    pub(crate) fn new(initial: Duration, max: Duration) -> Self {
        Self {
            next: initial,
            initial,
            max,
        }
    }

    /// The delay to wait now; the following one doubles, up to the cap.
    pub(crate) fn next_delay(&mut self) -> Duration {
        let delay = self.next;
        self.next = (self.next * 2).min(self.max);
        delay
    }

    pub(crate) fn reset(&mut self) {
        self.next = self.initial;
    }
}

/// Is this receive error one the listener can never recover from?
///
/// The SDK returns [`ATMError::ProfileError`] when the profile has no mediator
/// or its websocket has been torn down (`stop_websocket`). A reconnect keeps the
/// same channel, so nothing short of re-enabling the websocket refills it; the
/// SDK's own `DidCommTransport::inbound` ends its stream on exactly this error.
/// Retrying it would poll a dead profile for the life of the process.
pub(crate) fn is_terminal_receive_error(err: &ATMError) -> bool {
    matches!(err, ATMError::ProfileError(_))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn t0() -> Instant {
        Instant::now()
    }

    #[test]
    fn a_new_message_is_dispatched_then_skipped_while_in_flight() {
        let mut ledger = DeliveryLedger::default();
        let now = t0();
        assert_eq!(ledger.claim("m1", now), Claim::Dispatch);
        // The offline sync fetches the same id before the live handler acks.
        assert_eq!(ledger.claim("m1", now), Claim::InFlight);
    }

    #[test]
    fn a_handled_message_is_acked_and_a_redelivery_is_reacked_not_rehandled() {
        let mut ledger = DeliveryLedger::default();
        let now = t0();
        assert_eq!(ledger.claim("m1", now), Claim::Dispatch);
        assert_eq!(ledger.finish("m1", Outcome::Handled, now), Ack::Now);
        // The ack did not land; the next sync offers it again.
        let later = now + Duration::from_secs(30);
        assert_eq!(ledger.claim("m1", later), Claim::AlreadyHandled);
        assert_eq!(ledger.claim("m1", later), Claim::AlreadyHandled);
    }

    #[test]
    fn poison_is_acked_at_once() {
        let mut ledger = DeliveryLedger::default();
        let now = t0();
        ledger.claim("p", now);
        assert_eq!(ledger.finish("p", Outcome::Poison, now), Ack::Now);
        assert_eq!(ledger.claim("p", now), Claim::AlreadyHandled);
    }

    #[test]
    fn a_failed_message_is_retained_and_dispatched_again_on_redelivery() {
        let mut ledger = DeliveryLedger::default();
        let now = t0();
        ledger.claim("m", now);
        let ack = ledger.finish("m", Outcome::Retry, now);
        assert_eq!(ack, Ack::Retain);
        assert_eq!(
            ledger.claim("m", now + Duration::from_secs(30)),
            Claim::Dispatch
        );
    }

    #[test]
    fn retries_are_bounded_by_count_and_age() {
        let mut ledger = DeliveryLedger::default();
        let start = t0();
        let mut now = start;
        // Many quick failures are not enough on their own…
        for _ in 0..(GIVE_UP_ATTEMPTS * 2) {
            assert_eq!(ledger.claim("m", now), Claim::Dispatch);
            assert_eq!(ledger.finish("m", Outcome::Retry, now), Ack::Retain);
            now += Duration::from_secs(1);
        }
        // …once it has also been failing for long enough, it is given up on.
        now = start + GIVE_UP_MIN_AGE;
        assert_eq!(ledger.claim("m", now), Claim::Dispatch);
        let ack = ledger.finish("m", Outcome::Retry, now);
        assert_eq!(ack, Ack::GiveUp);
        assert_eq!(ledger.claim("m", now), Claim::AlreadyHandled);
    }

    #[test]
    fn a_success_after_failures_is_acked() {
        let mut ledger = DeliveryLedger::default();
        let now = t0();
        ledger.claim("m", now);
        ledger.finish("m", Outcome::Retry, now);
        ledger.claim("m", now);
        assert_eq!(ledger.finish("m", Outcome::Handled, now), Ack::Now);
    }

    #[test]
    fn released_claims_are_dispatched_again() {
        let mut ledger = DeliveryLedger::default();
        let now = t0();
        ledger.claim("m", now);
        ledger.release("m");
        assert_eq!(ledger.claim("m", now), Claim::Dispatch);
    }

    #[test]
    fn released_retry_keeps_its_failure_count() {
        let mut ledger = DeliveryLedger::default();
        let start = t0();
        for i in 0..GIVE_UP_ATTEMPTS - 1 {
            ledger.claim("m", start + Duration::from_secs(i.into()));
            ledger.finish("m", Outcome::Retry, start);
        }
        ledger.claim("m", start);
        ledger.release("m");
        let now = start + GIVE_UP_MIN_AGE;
        assert_eq!(ledger.claim("m", now), Claim::Dispatch);
        assert_eq!(ledger.finish("m", Outcome::Retry, now), Ack::GiveUp);
    }

    #[test]
    fn entries_expire_after_the_ttl() {
        let mut ledger = DeliveryLedger::new(16, Duration::from_secs(60));
        let now = t0();
        ledger.claim("m", now);
        ledger.finish("m", Outcome::Handled, now);
        assert_eq!(
            ledger.claim("m", now + Duration::from_secs(61)),
            Claim::Dispatch
        );
    }

    #[test]
    fn the_ledger_is_bounded() {
        let mut ledger = DeliveryLedger::new(3, LEDGER_TTL);
        let now = t0();
        for id in ["a", "b", "c", "d"] {
            ledger.claim(id, now);
            ledger.finish(id, Outcome::Handled, now);
        }
        assert_eq!(ledger.len(), 3);
        // The oldest was forgotten.
        assert_eq!(ledger.claim("a", now), Claim::Dispatch);
        assert_eq!(ledger.claim("d", now), Claim::AlreadyHandled);
    }

    #[test]
    fn finishing_an_evicted_claim_still_records_it() {
        let mut ledger = DeliveryLedger::new(1, LEDGER_TTL);
        let now = t0();
        ledger.claim("a", now);
        ledger.claim("b", now); // evicts "a" while it is in flight
        assert_eq!(ledger.finish("a", Outcome::Handled, now), Ack::Now);
        assert_eq!(ledger.claim("a", now), Claim::AlreadyHandled);
    }

    #[test]
    fn backoff_doubles_to_a_cap_and_resets() {
        let mut b = Backoff::new(Duration::from_millis(250), Duration::from_secs(1));
        assert_eq!(b.next_delay(), Duration::from_millis(250));
        assert_eq!(b.next_delay(), Duration::from_millis(500));
        assert_eq!(b.next_delay(), Duration::from_secs(1));
        assert_eq!(b.next_delay(), Duration::from_secs(1));
        b.reset();
        assert_eq!(b.next_delay(), Duration::from_millis(250));
    }

    #[test]
    fn only_a_dead_profile_ends_the_receive_loop() {
        assert!(is_terminal_receive_error(&ATMError::ProfileError(
            "No WebSocket channel set for profile".into()
        )));
        assert!(!is_terminal_receive_error(&ATMError::TransportError(
            "reconnecting".into()
        )));
        assert!(!is_terminal_receive_error(&ATMError::MsgReceiveError(
            "Error receiving frame".into()
        )));
    }
}
