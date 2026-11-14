//! The delivery-layer receive loop's delivery semantics, driven through
//! [`InboundLoop`] with an in-memory transport and a fake sink.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};

use affinidi_messaging_core::{
    ConnState, InboundAck, MessagingError, ReceivedMessage, SendReceipt, TransportKind,
};
use futures::stream::BoxStream;
use tokio::sync::{Notify, mpsc, watch};

use super::*;

/// A transport whose inbound stream yields what the test sends it, and which
/// (as the loop's [`Acker`]) records every ack: queued in the background, or
/// deleted directly.
struct MockTransport {
    inbound: Mutex<Option<mpsc::UnboundedReceiver<Inbound>>>,
    /// Messages taken off the inbound stream.
    taken: Arc<AtomicUsize>,
    acked: Mutex<Vec<String>>,
    direct: Mutex<Vec<Vec<String>>>,
    conn: watch::Sender<ConnState>,
}

impl MockTransport {
    fn new() -> (Arc<Self>, mpsc::UnboundedSender<Inbound>) {
        let (tx, rx) = mpsc::unbounded_channel();
        let (conn, _) = watch::channel(ConnState::Connected);
        let transport = Arc::new(Self {
            inbound: Mutex::new(Some(rx)),
            taken: Arc::default(),
            acked: Mutex::default(),
            direct: Mutex::default(),
            conn,
        });
        (transport, tx)
    }

    /// Acks queued in the background.
    fn acked(&self) -> Vec<String> {
        self.acked.lock().unwrap().clone()
    }

    /// Batches deleted directly.
    fn direct(&self) -> Vec<Vec<String>> {
        self.direct.lock().unwrap().clone()
    }

    fn taken(&self) -> usize {
        self.taken.load(Ordering::SeqCst)
    }
}

#[async_trait]
impl MessageTransport for MockTransport {
    fn kind(&self) -> TransportKind {
        TransportKind::Didcomm
    }

    async fn send(&self, _dest: &str, _packed: Vec<u8>) -> Result<SendReceipt, MessagingError> {
        Err(MessagingError::Transport(
            "the mock transport sends nothing".into(),
        ))
    }

    fn connection_state(&self) -> watch::Receiver<ConnState> {
        self.conn.subscribe()
    }

    fn inbound(&self) -> BoxStream<'static, Inbound> {
        let rx = self
            .inbound
            .lock()
            .unwrap()
            .take()
            .expect("inbound taken once");
        let taken = self.taken.clone();
        Box::pin(futures::stream::unfold(rx, move |mut rx| {
            let taken = taken.clone();
            async move {
                let inbound = rx.recv().await?;
                taken.fetch_add(1, Ordering::SeqCst);
                Some((inbound, rx))
            }
        }))
    }

    async fn ack(&self, _ack: InboundAck) -> Result<(), MessagingError> {
        panic!("the loop acks through its Acker, not the transport");
    }
}

#[async_trait]
impl Acker for MockTransport {
    async fn queue(&self, id: &str) -> Result<(), String> {
        self.acked.lock().unwrap().push(id.to_string());
        Ok(())
    }

    async fn delete_now(&self, ids: &[String]) -> Result<(), String> {
        self.direct.lock().unwrap().push(ids.to_vec());
        Ok(())
    }
}

/// What the fake sink does with a message, keyed by its payload.
struct FakeSink {
    calls: AtomicUsize,
    running: AtomicUsize,
    release: Notify,
}

impl FakeSink {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            calls: AtomicUsize::new(0),
            running: AtomicUsize::new(0),
            release: Notify::new(),
        })
    }

    fn calls(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }
}

#[async_trait]
impl InboundSink for FakeSink {
    async fn handle(&self, inbound: Inbound) -> Outcome {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.running.fetch_add(1, Ordering::SeqCst);
        let outcome = match inbound.message.payload.as_slice() {
            b"ok" => Outcome::Handled,
            b"poison" => Outcome::Poison,
            b"retry" => Outcome::Retry,
            b"block" => {
                self.release.notified().await;
                Outcome::Handled
            }
            b"hang" => {
                tokio::time::sleep(Duration::from_secs(60)).await;
                Outcome::Handled
            }
            b"panic" => panic!("handler panicked"),
            other => panic!("unexpected payload {other:?}"),
        };
        self.running.fetch_sub(1, Ordering::SeqCst);
        outcome
    }
}

fn message(id: &str, payload: &str) -> Inbound {
    let received = ReceivedMessage {
        id: id.to_string(),
        sender: Some("did:example:peer".to_string()),
        recipient: "did:example:registry".to_string(),
        payload: payload.as_bytes().to_vec(),
        protocol: Protocol::DIDComm,
        verified: true,
        encrypted: true,
    };
    Inbound::new(received, None, InboundAck(id.to_string()))
}

struct Running {
    transport: Arc<MockTransport>,
    tx: mpsc::UnboundedSender<Inbound>,
    sink: Arc<FakeSink>,
    shutdown: CancellationToken,
    task: tokio::task::JoinHandle<LoopEnd>,
}

fn start_with(
    transport: Arc<MockTransport>,
    tx: mpsc::UnboundedSender<Inbound>,
    max: usize,
    timeout: Duration,
) -> Running {
    let sink = FakeSink::new();
    let shutdown = CancellationToken::new();
    let task = tokio::spawn({
        let inbound_loop = InboundLoop::new(
            transport.clone(),
            transport.clone(),
            sink.clone(),
            "t",
            shutdown.clone(),
        )
        .with_limits(max, timeout);
        async move { inbound_loop.run().await }
    });
    Running {
        transport,
        tx,
        sink,
        shutdown,
        task,
    }
}

fn start(max: usize) -> Running {
    let (transport, tx) = MockTransport::new();
    start_with(transport, tx, max, Duration::from_secs(5))
}

async fn until(what: &str, mut done: impl FnMut() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(5);
    while !done() {
        assert!(Instant::now() < deadline, "timed out waiting for {what}");
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
}

/// The TSP-enabled registry answered no DIDComm message: the delivery crate's
/// dispatcher started taking messages off the socket when it was built, found
/// no subscriber yet, and left them unanswered. A message already waiting when
/// the loop starts must be handled and acked.
#[tokio::test]
async fn a_message_waiting_before_the_loop_starts_is_handled_and_acked() {
    let (transport, tx) = MockTransport::new();
    tx.send(message("m1", "ok")).unwrap();
    tokio::time::sleep(Duration::from_millis(20)).await;
    let running = start_with(transport, tx, 4, Duration::from_secs(5));
    until("the ack", || running.transport.acked() == ["m1"]).await;
    assert_eq!(running.sink.calls(), 1);
    running.shutdown.cancel();
    assert_eq!(running.task.await.unwrap(), LoopEnd::Shutdown);
}

/// R1.6: the ack follows the handler, and only a handled (or poison) message
/// is acked.
#[tokio::test]
async fn only_handled_or_poison_messages_are_acked() {
    let running = start(4);
    running.tx.send(message("ok", "ok")).unwrap();
    running.tx.send(message("poison", "poison")).unwrap();
    running.tx.send(message("retry", "retry")).unwrap();
    running.tx.send(message("panic", "panic")).unwrap();
    until("all four handled", || running.sink.calls() == 4).await;
    until("the two acks", || running.transport.acked().len() == 2).await;
    // Give a wrongly-acked failure time to show up.
    tokio::time::sleep(Duration::from_millis(50)).await;
    let mut acked = running.transport.acked();
    acked.sort();
    assert_eq!(acked, ["ok", "poison"]);
    running.shutdown.cancel();
    running.task.await.unwrap();
}

/// A message is not acked before its handler returns, so a handler still
/// running holds its message at the mediator.
#[tokio::test]
async fn a_running_handler_has_not_acked_its_message() {
    let running = start(4);
    running.tx.send(message("m1", "block")).unwrap();
    until("the handler to start", || {
        running.sink.running.load(Ordering::SeqCst) == 1
    })
    .await;
    assert!(running.transport.acked().is_empty());
    running.sink.release.notify_waiters();
    until("the ack", || running.transport.acked() == ["m1"]).await;
    running.shutdown.cancel();
    running.task.await.unwrap();
}

/// A handler that overruns its time limit is abandoned, its message left
/// queued, and its slot returned: later messages are still received.
#[tokio::test]
async fn a_hung_handler_is_abandoned_and_does_not_stop_later_messages() {
    let (transport, tx) = MockTransport::new();
    let running = start_with(transport, tx, 1, Duration::from_millis(50));
    running.tx.send(message("hung", "hang")).unwrap();
    running.tx.send(message("next", "ok")).unwrap();
    until("the next message to be acked", || {
        running.transport.acked() == ["next"]
    })
    .await;
    running.shutdown.cancel();
    running.task.await.unwrap();
}

/// The loop takes the next message off the transport only once a handler
/// slot is free, so a burst waits at the mediator, unacked, not in memory.
#[tokio::test]
async fn no_message_is_taken_while_every_slot_is_busy() {
    let running = start(1);
    running.tx.send(message("m1", "block")).unwrap();
    running.tx.send(message("m2", "ok")).unwrap();
    until("the first handler to start", || {
        running.sink.running.load(Ordering::SeqCst) == 1
    })
    .await;
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert_eq!(
        running.transport.taken(),
        1,
        "took a message with no free slot"
    );
    running.sink.release.notify_waiters();
    until("both acked", || running.transport.acked().len() == 2).await;
    running.shutdown.cancel();
    running.task.await.unwrap();
}

/// R1.4: the mediator pushes the queued inbox again on every reconnect. A copy
/// that arrives while the first is being handled is skipped; one that arrives
/// after it was handled is acked again without being handled again.
#[tokio::test]
async fn a_message_pushed_again_is_handled_once() {
    let running = start(4);
    running.tx.send(message("m1", "block")).unwrap();
    until("the handler to start", || {
        running.sink.running.load(Ordering::SeqCst) == 1
    })
    .await;
    running.tx.send(message("m1", "block")).unwrap();
    until("the copy to be taken", || running.transport.taken() == 2).await;
    tokio::time::sleep(Duration::from_millis(20)).await;
    assert_eq!(
        running.sink.calls(),
        1,
        "an in-flight copy was handled again"
    );
    running.sink.release.notify_waiters();
    until("the ack", || running.transport.acked() == ["m1"]).await;

    running.tx.send(message("m1", "ok")).unwrap();
    until("the second ack", || running.transport.acked().len() == 2).await;
    assert_eq!(running.sink.calls(), 1, "a handled copy was handled again");
    running.shutdown.cancel();
    running.task.await.unwrap();
}

/// A message whose handler failed is handled again when it is pushed again.
#[tokio::test]
async fn a_failed_message_is_handled_again_when_pushed_again() {
    let running = start(4);
    running.tx.send(message("m1", "retry")).unwrap();
    until("the first attempt", || running.sink.calls() == 1).await;
    running.tx.send(message("m1", "ok")).unwrap();
    until("the ack", || running.transport.acked() == ["m1"]).await;
    assert_eq!(running.sink.calls(), 2);
    running.shutdown.cancel();
    running.task.await.unwrap();
}

/// Shutdown waits for running handlers, and a message one finishes after
/// shutdown began is deleted directly — the SDK's background deletion queue
/// is dropped when the ATM shuts down, so queueing it there would lose the
/// ack and have the message re-handled after a restart.
#[tokio::test]
async fn shutdown_waits_for_running_handlers_to_ack() {
    let running = start(4);
    running.tx.send(message("m1", "block")).unwrap();
    until("the handler to start", || {
        running.sink.running.load(Ordering::SeqCst) == 1
    })
    .await;
    running.shutdown.cancel();
    tokio::time::sleep(Duration::from_millis(20)).await;
    assert!(
        !running.task.is_finished(),
        "returned before the handler acked"
    );
    running.sink.release.notify_waiters();
    assert_eq!(running.task.await.unwrap(), LoopEnd::Shutdown);
    assert!(
        running.transport.acked().is_empty(),
        "an ack made during shutdown went to the background queue"
    );
    assert_eq!(running.transport.direct(), [vec!["m1".to_string()]]);
}

/// An ack queued in the background shortly before shutdown may not have been
/// served when the ATM shuts down, so shutdown deletes it again directly.
#[tokio::test]
async fn recent_background_acks_are_deleted_directly_at_shutdown() {
    let running = start(4);
    running.tx.send(message("m1", "ok")).unwrap();
    running.tx.send(message("m2", "retry")).unwrap();
    until("the ack", || running.transport.acked() == ["m1"]).await;
    until("both handled", || running.sink.calls() == 2).await;
    running.shutdown.cancel();
    assert_eq!(running.task.await.unwrap(), LoopEnd::Shutdown);
    // The failed message is not acked either way.
    assert_eq!(running.transport.direct(), [vec!["m1".to_string()]]);
}

/// Nothing handled, nothing to delete at shutdown.
#[tokio::test]
async fn an_idle_shutdown_deletes_nothing() {
    let running = start(4);
    running.shutdown.cancel();
    running.task.await.unwrap();
    assert!(running.transport.direct().is_empty());
}

/// The shutdown flush sends each id once, in batches the mediator accepts.
#[test]
fn the_shutdown_flush_is_deduplicated_and_windowed() {
    let start = Instant::now();
    let mut state = AckState::default();
    assert!(state.take("old", start));
    let now = start + RECENT_ACK_WINDOW + Duration::from_secs(1);
    assert!(state.take("a", now));
    state.draining = true;
    assert!(!state.take("a", now), "held once shutdown has begun");
    assert!(!state.take("b", now));
    assert_eq!(state.take_flush(now), ["a", "b"]);
    assert!(state.take_flush(now).is_empty());
}

/// A stream that ends (the profile's websocket is gone) ends the loop with an
/// error, so `/health` reports it instead of "exited cleanly".
#[tokio::test]
async fn the_end_of_the_inbound_stream_is_an_error() {
    let running = start(4);
    drop(running.tx);
    let end = running.task.await.unwrap();
    assert_eq!(end, LoopEnd::StreamEnded);
    assert!(end.into_result().is_err());
    assert!(LoopEnd::Shutdown.into_result().is_ok());
}

/// Application frames and accepted requests keep a relationship alive;
/// cancellations and requests that need no answer do not.
#[test]
fn activity_is_stamped_for_application_frames_and_accepts_only() {
    assert!(shows_activity(None));
    assert!(shows_activity(Some(&ControlDecision::Accept)));
    assert!(!shows_activity(Some(&ControlDecision::Cancel("x"))));
    assert!(!shows_activity(Some(&ControlDecision::Nothing)));
}

/// A failed accept says whether the relationship was recorded, since
/// that decides whether the peer's traffic is admitted.
#[test]
fn a_failed_accept_says_whether_the_relationship_was_recorded() {
    assert!(accept_failure_note(Some(RelationshipState::None)).contains("not recorded"));
    assert!(
        accept_failure_note(Some(RelationshipState::InviteReceived)).contains("stays recorded")
    );
    assert!(accept_failure_note(None).contains("host"));
}

/// On the delivery-layer path `/health` follows the transport's connection
/// state, both ways, rather than reporting `unknown` (R6.2), and shows the
/// given-up counter.
#[tokio::test]
async fn health_follows_the_connection_state() {
    let (transport, _tx) = MockTransport::new();
    let health = Arc::new(RegistryHealth::new(true));
    let shutdown = CancellationToken::new();
    let task = tokio::spawn({
        let inbound_loop = InboundLoop::new(
            transport.clone(),
            transport.clone(),
            FakeSink::new(),
            "t",
            shutdown.clone(),
        )
        .with_health(Some(health.clone()));
        async move { inbound_loop.run().await }
    });

    let writes = || {
        health.to_json()["writes"]
            .as_str()
            .unwrap_or_default()
            .to_string()
    };
    assert_eq!(health.to_json()["givenUpMessages"], 0);
    transport.conn.send_replace(ConnState::Connected);
    until("writes ok", || writes() == "ok").await;
    transport.conn.send_replace(ConnState::Disconnected);
    until("writes unavailable", || writes() == "unavailable").await;
    assert_eq!(health.to_json()["status"], "degraded");
    transport.conn.send_replace(ConnState::Connected);
    until("writes ok again", || writes() == "ok").await;

    shutdown.cancel();
    assert_eq!(task.await.unwrap(), LoopEnd::Shutdown);
}
