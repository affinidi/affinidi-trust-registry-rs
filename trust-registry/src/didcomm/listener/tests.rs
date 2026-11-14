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
