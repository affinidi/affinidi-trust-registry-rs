//! The pickup listener's delivery semantics, driven through
//! [`Listener::dispatch`] with a fake handler and an ATM that has no mediator
//! (so nothing reaches a network; acks are attempted and fail, which the
//! listener tolerates by design).

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use affinidi_tdk::common::{TDKSharedState, config::TDKConfig};
use affinidi_tdk::messaging::config::ATMConfig;
use serde_json::json;
use tokio::sync::Notify;
use tokio::time::Instant;

use super::delivery::Claim;
use super::mediator_functions::{Work, lock_ledger};
use super::*;

/// What the fake handler does with each message.
#[derive(Clone, Copy)]
enum Behaviour {
    Succeed,
    Fail,
    /// Wait for `release` before succeeding.
    Block,
}

struct Fake {
    behaviour: Behaviour,
    calls: AtomicUsize,
    running: AtomicUsize,
    release: Notify,
}

impl Fake {
    fn new(behaviour: Behaviour) -> Self {
        Self {
            behaviour,
            calls: AtomicUsize::new(0),
            running: AtomicUsize::new(0),
            release: Notify::new(),
        }
    }
}

#[async_trait]
impl MessageHandler for Fake {
    async fn handle(
        &self,
        _atm: &Arc<ATM>,
        _profile: &Arc<ATMProfile>,
        _message: Message,
        _meta: UnpackMetadata,
    ) -> Result<(), Box<dyn std::error::Error>> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.running.fetch_add(1, Ordering::SeqCst);
        if let Behaviour::Block = self.behaviour {
            self.release.notified().await;
        }
        self.running.fetch_sub(1, Ordering::SeqCst);
        match self.behaviour {
            Behaviour::Fail => Err("repository unavailable".into()),
            _ => Ok(()),
        }
    }
}

async fn listener(behaviour: Behaviour, max_inflight: usize) -> (Arc<Listener<Fake>>, Arc<Fake>) {
    let tdk = TDKSharedState::new(
        TDKConfig::builder()
            .with_load_environment(false)
            .build()
            .unwrap(),
    )
    .await
    .unwrap();
    let atm = Arc::new(
        ATM::new(ATMConfig::builder().build().unwrap(), Arc::new(tdk))
            .await
            .unwrap(),
    );
    let profile = Arc::new(
        ATMProfile::new(
            &atm,
            Some("registry".into()),
            "did:example:registry".into(),
            None,
        )
        .await
        .unwrap(),
    );
    let fake = Arc::new(Fake::new(behaviour));
    let listener = Listener::new(atm, profile, fake.clone(), CancellationToken::new())
        .with_max_inflight(max_inflight);
    (Arc::new(listener), fake)
}

fn work() -> Work {
    let message = Message::build(
        "m".to_string(),
        "https://example.org/x".to_string(),
        json!({}),
    )
    .finalize();
    Work::DidComm(Box::new(message), Box::default())
}

/// What a fresh copy of `id` would get, without disturbing it for long: a
/// `Dispatch` answer is a claim, so it is released again.
fn peek(listener: &Listener<Fake>, id: &str) -> Claim {
    let mut ledger = lock_ledger(&listener.ledger);
    let claim = ledger.claim(id, Instant::now());
    if claim == Claim::Dispatch {
        ledger.release(id);
    }
    claim
}

async fn until(what: &str, mut done: impl FnMut() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(5);
    while !done() {
        assert!(Instant::now() < deadline, "timed out waiting for {what}");
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
}

#[tokio::test]
async fn a_handled_message_is_marked_for_ack_and_not_handled_again() {
    let (listener, fake) = listener(Behaviour::Succeed, 4).await;
    listener.dispatch("m1".into(), work()).await;
    until("the handler to finish", || {
        peek(&listener, "m1") == Claim::AlreadyHandled
    })
    .await;
    // The offline sync fetches it again because the ack has not landed.
    listener.dispatch("m1".into(), work()).await;
    assert_eq!(fake.calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn a_failing_handler_leaves_the_message_queued_for_redelivery() {
    let (listener, fake) = listener(Behaviour::Fail, 4).await;
    listener.dispatch("m1".into(), work()).await;
    until("the handler to run", || {
        fake.calls.load(Ordering::SeqCst) == 1
    })
    .await;
    // Not acked: a redelivery is dispatched again.
    until("the failure to be recorded", || {
        peek(&listener, "m1") == Claim::Dispatch
    })
    .await;
    listener.dispatch("m1".into(), work()).await;
    until("the retry", || fake.calls.load(Ordering::SeqCst) == 2).await;
}

#[tokio::test]
async fn a_message_fetched_by_both_consumers_is_handled_once() {
    let (listener, fake) = listener(Behaviour::Block, 4).await;
    // The live stream takes it…
    listener.dispatch("m1".into(), work()).await;
    until("the handler to start", || {
        fake.running.load(Ordering::SeqCst) == 1
    })
    .await;
    // …and the offline sync fetches it before the ack.
    listener.dispatch("m1".into(), work()).await;
    assert_eq!(peek(&listener, "m1"), Claim::InFlight);
    fake.release.notify_waiters();
    until("the handler to finish", || {
        peek(&listener, "m1") == Claim::AlreadyHandled
    })
    .await;
    assert_eq!(fake.calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn a_message_beyond_the_handler_limit_waits_for_a_slot() {
    let (listener, fake) = listener(Behaviour::Block, 1).await;
    listener.dispatch("m1".into(), work()).await;
    until("the first handler to start", || {
        fake.running.load(Ordering::SeqCst) == 1
    })
    .await;

    let second = tokio::spawn({
        let listener = listener.clone();
        async move { listener.dispatch("m2".into(), work()).await }
    });
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert!(
        !second.is_finished(),
        "the second message was taken while the only slot was busy"
    );
    assert_eq!(fake.calls.load(Ordering::SeqCst), 1);

    fake.release.notify_waiters();
    second.await.unwrap();
    until("the second handler to start", || {
        fake.calls.load(Ordering::SeqCst) == 2
    })
    .await;
    fake.release.notify_waiters();
}

#[tokio::test]
async fn shutdown_while_waiting_for_a_slot_leaves_the_message_unclaimed() {
    let (listener, fake) = listener(Behaviour::Block, 1).await;
    listener.dispatch("m1".into(), work()).await;
    until("the first handler to start", || {
        fake.running.load(Ordering::SeqCst) == 1
    })
    .await;
    let second = tokio::spawn({
        let listener = listener.clone();
        async move { listener.dispatch("m2".into(), work()).await }
    });
    tokio::time::sleep(Duration::from_millis(20)).await;
    listener.shutdown.cancel();
    second.await.unwrap();
    assert_eq!(peek(&listener, "m2"), Claim::Dispatch);
    fake.release.notify_waiters();
}

#[tokio::test]
async fn the_receive_loop_ends_on_shutdown() {
    let (listener, _) = listener(Behaviour::Succeed, 1).await;
    listener.shutdown.cancel();
    let result = tokio::time::timeout(Duration::from_secs(5), listener.receive_until_shutdown())
        .await
        .expect("the receive loop observes the shutdown token");
    assert!(result.is_ok(), "{result:?}");
}

#[tokio::test]
async fn a_profile_without_a_live_transport_ends_the_receive_loop_with_an_error() {
    // No mediator, so no websocket: the SDK answers `ProfileError` at once.
    // Retrying that would spin for the life of the process.
    let (listener, _) = listener(Behaviour::Succeed, 1).await;
    let result = tokio::time::timeout(Duration::from_secs(5), listener.receive_until_shutdown())
        .await
        .expect("a dead profile ends the receive loop instead of spinning");
    assert!(result.is_err());
}

/// A queued message the SDK could not unpack (`(None, id)`) is not acked at
/// once: the SDK does not say whether the failure was transient (R1.6). It is
/// kept for the next sync until it has failed often enough, for long enough,
/// and then deleted as undeliverable.
#[cfg(feature = "tsp")]
#[tokio::test]
async fn an_unpackable_queued_message_is_kept_then_given_up_on() {
    use super::delivery::{Ack, GIVE_UP_ATTEMPTS, GIVE_UP_MIN_AGE};

    let (listener, fake) = listener(Behaviour::Succeed, 1).await;
    let start = Instant::now();
    let mut now = start;
    for _ in 0..GIVE_UP_ATTEMPTS {
        assert_eq!(
            listener.undeliverable_at("bad", now).await,
            Some(Ack::Retain),
            "kept before the age bound"
        );
        now += Duration::from_secs(30);
    }
    // Failed often enough; once it has also been failing long enough, it goes.
    let late = start + GIVE_UP_MIN_AGE;
    assert_eq!(
        listener.undeliverable_at("bad", late).await,
        Some(Ack::GiveUp)
    );
    // A copy still queued (the delete did not land) is deleted again.
    assert_eq!(listener.undeliverable_at("bad", late).await, Some(Ack::Now));
    // Nothing reached a handler.
    assert_eq!(fake.calls.load(Ordering::SeqCst), 0);
}

/// An undecodable copy of a message another copy of which is being handled
/// is left to that handler.
#[cfg(feature = "tsp")]
#[tokio::test]
async fn an_unpackable_copy_of_an_in_flight_message_is_left_alone() {
    let (listener, fake) = listener(Behaviour::Block, 1).await;
    listener.dispatch("m1".into(), work()).await;
    until("the handler to start", || {
        fake.running.load(Ordering::SeqCst) == 1
    })
    .await;
    assert_eq!(listener.undeliverable_at("m1", Instant::now()).await, None);
    fake.release.notify_waiters();
}

/// A handled message's id is kept for the shutdown flush, which sends its
/// deletion directly rather than trusting the background handler's queue to
/// be sent before the connection closes.
#[tokio::test]
async fn a_handled_message_is_kept_for_the_shutdown_flush() {
    let (listener, _fake) = listener(Behaviour::Succeed, 4).await;
    listener.dispatch("m1".into(), work()).await;
    until("the ack to be recorded", || {
        let ids = listener.acks.take_recent(Instant::now());
        let found = ids.iter().any(|id| id == "m1");
        for id in ids {
            listener.acks.record(&id, Instant::now());
        }
        found
    })
    .await;

    // The flush takes them (its direct deletes fail here: no mediator).
    listener.flush_acks().await;
    assert!(listener.acks.take_recent(Instant::now()).is_empty());
}

#[test]
fn recent_acks_forget_ids_outside_the_window() {
    let acks = mediator_functions::RecentAcks::default();
    let start = Instant::now();
    acks.record("old", start);
    acks.record("new", start + mediator_functions::RECENT_ACK_WINDOW);
    let later = start + mediator_functions::RECENT_ACK_WINDOW + Duration::from_secs(1);
    assert_eq!(acks.take_recent(later), vec!["new".to_string()]);
}

/// Closing the registry's own connection is bounded, even when there is no
/// mediator to say goodbye to.
#[tokio::test]
async fn closing_an_owned_connection_is_bounded() {
    let (listener, _fake) = listener(Behaviour::Succeed, 4).await;
    tokio::time::timeout(
        CONNECTION_CLOSE_TIMEOUT + Duration::from_secs(5),
        close_owned_connection(&listener.atm),
    )
    .await
    .expect("bounded");
}
