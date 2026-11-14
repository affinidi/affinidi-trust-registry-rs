//! The delivery-layer receive path of a TSP-enabled registry.
//!
//! Builds a [`TDKSharedState`] seeded with the registry's secrets, an [`ATM`]
//! carrying a **durable** TSP relationship store, a profile against the
//! mediator, then a bounded `profile_enable_websocket` before the SDK's
//! [`DidCommTransport`] is bound to it. The receive loop then drives the
//! transport's inbound stream.
//!
//! # Delivery semantics
//!
//! The transport pulls each frame with `auto_delete = false` and leaves the ack
//! (the delete at the mediator) to its caller. The loop acks a message
//! only once it has been handled, with the same rules and the same
//! `DeliveryLedger` as the pickup listener
//! (`didcomm::listener::delivery`): poison is acked at once, a handler
//! error, panic or timeout leaves the message queued, and a message that
//! arrives again while in flight or after it was handled is not handled twice.
//!
//! The registry does not use `affinidi-messaging-delivery`'s
//! `MessagingService` for this: its dispatcher acks each message as soon as it
//! is in a broadcast buffer, before the registry's handler has run, and starts
//! taking messages off the socket when it is built, before anything has
//! subscribed — it left the first messages unanswered until a reconnect.
//!
//! A message left queued is offered again when the mediator next pushes the
//! stored inbox, which it does whenever live delivery is switched on (each
//! websocket (re)connect, and each start). Unlike the pickup listener this
//! path has no periodic offline sync: the SDK's offline fetch would hand TSP
//! frames back still packed, where relationship-control frames cannot be
//! recorded.
//!
//! Acks are normally handed to the SDK's background deletion handler, which
//! deletes at the mediator shortly after. That queue does not survive
//! `ATM::graceful_shutdown`, so from the moment shutdown begins the loop holds
//! acks back and, once its handlers have finished, deletes them — and the
//! acks queued in the last minute — directly at the mediator,
//! waiting for its answer, before the caller shuts the ATM down.
//!
//! Replies are sent once, synchronously, from the handler (`atm.tsp().send`,
//! `atm.forward_and_send_message`); a reply that cannot be sent is logged. A
//! client that retries a write with the same document id gets the recorded
//! outcome replayed (see [`crate::dedup`]), so a lost reply costs a retry, not
//! a second application.

use std::sync::Arc;
use std::time::Duration;

use std::collections::{HashSet, VecDeque};

use affinidi_messaging_core::{ConnState, Inbound, InboundKind, MessageTransport, Protocol};
use affinidi_messaging_sdk::messages::DeleteMessageRequest;
use affinidi_tdk::common::TDKSharedState;
use affinidi_tdk::common::config::TDKConfig;
use affinidi_tdk::didcomm::Message;
use affinidi_tdk::messaging::config::ATMConfig;
use affinidi_tdk::messaging::messages::compat::UnpackMetadata;
use affinidi_tdk::messaging::profiles::ATMProfile;
use affinidi_tdk::messaging::{ATM, DidCommTransport};
use affinidi_tdk::secrets_resolver::SecretsResolver;
use affinidi_tdk::secrets_resolver::secrets::Secret;
use async_trait::async_trait;
use tokio::sync::Semaphore;
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info, warn};

use crate::configs::{DidcommConfig, ProfileConfig};
use crate::didcomm::error::DIDCommError;
use crate::didcomm::listener::MessageHandler;
use crate::didcomm::listener::delivery::{
    ACK_TIMEOUT, Ack, Claim, DeliveryLedger, GIVE_UP_ATTEMPTS, GIVE_UP_MIN_AGE, HANDLER_TIMEOUT,
    MAX_INFLIGHT_HANDLERS, Outcome,
};
use crate::didcomm::listener::mediator_functions::{
    ACK_FLUSH_TIMEOUT, acl_failure_outcome, bounded_value_within, lock_ledger,
    set_mediator_acl_mode,
};
use crate::health::RegistryHealth;
use crate::messaging::kv::MessagingStore;
use crate::messaging::relationship_store::{
    FjallRelationshipKv, RegistryRelationshipStore, mark_active,
};
use crate::messaging::tsp_inbound::{ControlDecision, decide_control};
use crate::trust_tasks::TaskHandler;
use affinidi_messaging_sdk::RelationshipStore as _;
use affinidi_messaging_sdk::protocols::tsp::RelationshipState;

/// Resolve the on-disk path for the messaging store, namespaced per profile so
/// two DIDs never share one fjall database. The base is
/// [`DidcommConfig::messaging_store_path`], set from `TR_MESSAGING_STORE_PATH`
/// (or `TR_SECRETS_DATA_DIR`) when the configuration loads.
fn messaging_store_path(config: &DidcommConfig, alias: &str) -> std::path::PathBuf {
    let base = config.messaging_store_path();
    let safe: String = alias
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '_' })
        .collect();
    base.join(safe)
}

/// The `Managed`-source receive path of a TSP-enabled registry: open the
/// durable messaging store, connect an ATM with a persistent relationship
/// store, apply the mediator ACL mode, run the relationship-maintenance sweep,
/// and receive until `shutdown`.
///
/// Returns `Ok(())` after `shutdown`, and `Err` when the inbound stream ended
/// on its own (the profile's websocket is gone), so `/health` reports why.
/// Either way it stops the sweep, waits for running handlers, shuts the ATM
/// down (releasing the mediator's one-socket-per-DID slot) and closes the
/// store before returning, so a registry rebuilt in the same process can
/// connect and open the store again.
pub async fn start_managed_delivery<H: MessageHandler>(
    profile_config: ProfileConfig,
    config: Arc<DidcommConfig>,
    handler: Arc<H>,
    tasks: TaskHandler,
    health: Option<Arc<RegistryHealth>>,
    shutdown: CancellationToken,
) -> Result<(), DIDCommError> {
    let limits = config.relationship_limits;
    let path = messaging_store_path(&config, &profile_config.alias);
    let path_str = path.to_str().ok_or_else(|| {
        DIDCommError::Messaging(format!("non-UTF-8 messaging store path: {path:?}"))
    })?;
    let store = MessagingStore::open(path_str).map_err(DIDCommError::Messaging)?;

    // Bounded: any VID TSP authenticates can form a relationship. Admins'
    // relationships are kept out of the bound, so a full store never costs an
    // admin its relationship.
    let relationships = FjallRelationshipKv::open(
        store.relationships.clone(),
        limits,
        config.admin_config.admin_dids.clone(),
        health.clone(),
    )
    .await
    .map_err(|e| DIDCommError::Messaging(format!("open the TSP relationship store: {e}")))?;

    let messaging = build_messaging(
        profile_config.secrets,
        &profile_config.did,
        &profile_config.alias,
        &config.mediator_did,
        relationships,
    )
    .await
    .map_err(DIDCommError::Messaging)?;

    // Apply the same ACL mode the pickup path does: a private registry whose
    // mode was not applied does not start serving (`acl_failure_outcome`). The
    // ATM holds a live socket by now, so it is shut down before returning.
    if let Err(e) =
        set_mediator_acl_mode(&messaging.atm, &messaging.profile, config.acl_mode.clone()).await
        && let Err(refused) = acl_failure_outcome(&config.acl_mode, &e.to_string())
    {
        messaging.atm.graceful_shutdown().await;
        return Err(refused);
    }

    // The relationship-store maintenance sweep runs once per start — never on
    // the connect path, which would leak one sweep per reconnect — and stops
    // with the receive loop.
    let stop_maintenance = CancellationToken::new();
    let maintenance = tokio::spawn({
        let store = messaging.relationship_store.clone();
        let stop = stop_maintenance.clone();
        async move {
            tokio::select! {
                _ = crate::messaging::relationship_store::maintenance_loop(store, limits) => {}
                _ = stop.cancelled() => {}
            }
        }
    });

    info!(
        "[profile = {}] TSP relationship management active; receiving through the delivery layer",
        &profile_config.alias
    );
    let sink = Arc::new(RegistryInbound {
        atm: messaging.atm.clone(),
        profile: messaging.profile.clone(),
        relationships: Some(messaging.relationship_store.clone()),
        handler,
        tasks,
    });
    let acker = Arc::new(AtmAcker {
        atm: messaging.atm.clone(),
        profile: messaging.profile.clone(),
    });
    let end = InboundLoop::new(
        messaging.transport.clone(),
        acker,
        sink,
        &profile_config.alias,
        shutdown,
    )
    .with_health(health)
    .run()
    .await;

    // Teardown, in order: nothing may still use the store when it closes.
    // `run` has waited for the handlers and deleted their messages directly
    // at the mediator (the background deletion queue dies with the ATM); the
    // sweep is stopped here; the ATM (which holds the relationship store) is
    // shut down and every handle on it dropped before the store is.
    stop_maintenance.cancel();
    if let Err(e) = maintenance.await {
        warn!(error = %e, "the TSP relationship maintenance task did not stop cleanly");
    }
    // Bounded, so the stop stays within the server's shutdown grace.
    let close = crate::didcomm::listener::CONNECTION_CLOSE_TIMEOUT;
    if tokio::time::timeout(close, messaging.atm.graceful_shutdown())
        .await
        .is_err()
    {
        warn!("closing the mediator connection took longer than {close:?}");
    }
    drop(messaging);
    drop(store);
    info!(
        "[profile = {}] delivery-layer receive path stopped; mediator connection closed",
        &profile_config.alias
    );
    end.into_result()
}

/// The `SharedAtm`-source receive path of a TSP-enabled registry: receive
/// through a [`DidCommTransport`] bound to the host's ATM and profile until
/// `shutdown`.
///
/// The pickup loop cannot serve TSP here: it cannot record inbound
/// relationship-control frames, so under the SDK's default §7.2.2 gating
/// every TSP Trust Task from a peer would be dropped. The transport records
/// them, in the **host's** ATM relationship store: the registry cannot replace
/// a lent ATM's store, so its durability and bound are the host's (configure
/// them with `ATMConfigBuilder::with_relationship_store`). The registry does
/// not stamp or evict those relationships.
///
/// The host's ATM and websocket are left running on return; they are the
/// host's to shut down.
///
/// `health`, when given, follows the host connection's state and counts the
/// messages given up on, as on the registry's own connection.
pub async fn start_shared_delivery<H: MessageHandler>(
    atm: Arc<ATM>,
    profile: Arc<ATMProfile>,
    config: Arc<DidcommConfig>,
    handler: Arc<H>,
    tasks: TaskHandler,
    health: Option<Arc<RegistryHealth>>,
    shutdown: CancellationToken,
) -> Result<(), DIDCommError> {
    if let Err(e) = set_mediator_acl_mode(&atm, &profile, config.acl_mode.clone()).await {
        acl_failure_outcome(&config.acl_mode, &e.to_string())?;
    }
    let transport: Arc<dyn MessageTransport> = Arc::new(
        DidCommTransport::new((*atm).clone(), profile.clone())
            .await
            .map_err(|e| {
                DIDCommError::Messaging(format!(
                    "TSP over a host-provided connection needs the host's websocket enabled \
                     for this profile: {e}"
                ))
            })?,
    );
    info!(
        "[profile = {}] TSP enabled on a host-provided connection; receiving through the \
         delivery layer (relationships are kept in the host ATM's relationship store)",
        &profile.inner.alias
    );
    let alias = profile.inner.alias.clone();
    let acker = Arc::new(AtmAcker {
        atm: atm.clone(),
        profile: profile.clone(),
    });
    let sink = Arc::new(RegistryInbound {
        atm,
        profile,
        relationships: None,
        handler,
        tasks,
    });
    InboundLoop::new(transport, acker, sink, &alias, shutdown)
        .with_health(health)
        .run()
        .await
        .into_result()
}

/// The live delivery-layer wiring for the registry's mediator socket.
pub struct RegistryMessaging {
    /// The SDK transport bound to the profile's websocket.
    pub transport: Arc<dyn MessageTransport>,
    pub atm: Arc<ATM>,
    pub profile: Arc<ATMProfile>,
    /// The durable relationship store — kept so the caller can spawn the
    /// maintenance loop over it exactly once, at startup.
    pub relationship_store: Arc<RegistryRelationshipStore>,
}

/// Connect the registry's ATM to its mediator with a durable TSP relationship
/// store injected, and bind a [`DidCommTransport`] to the profile's websocket.
///
/// Every error path after `profile_add` must `graceful_shutdown` the ATM — there
/// is no `Drop` impl, and an abandoned socket keeps auto-reconnecting while
/// holding the mediator's one-socket-per-DID slot. So must the caller, when it
/// is done with the returned [`RegistryMessaging`].
pub async fn build_messaging(
    secrets: Vec<Secret>,
    did: &str,
    alias: &str,
    mediator_did: &str,
    relationships: FjallRelationshipKv,
) -> Result<RegistryMessaging, String> {
    let tdk_config = TDKConfig::builder()
        .with_load_environment(false)
        .build()
        .map_err(|e| format!("build TDK config: {e}"))?;

    let tdk = TDKSharedState::new(tdk_config)
        .await
        .map_err(|e| format!("create TDK shared state: {e}"))?;
    for secret in secrets {
        tdk.secrets_resolver().insert(secret).await;
    }

    // Persist TSP relationship state so it survives a restart. Without it, a
    // restarted registry forgets every peer and — by Rev 3 §7.2.2 — silently
    // drops their traffic until each re-handshakes.
    let relationship_store = Arc::new(RegistryRelationshipStore::new(relationships));
    let atm_config = ATMConfig::builder()
        .with_relationship_store(relationship_store.clone())
        .build()
        .map_err(|e| format!("build ATM config: {e}"))?;

    let atm = Arc::new(
        ATM::new(atm_config, Arc::new(tdk))
            .await
            .map_err(|e| format!("create ATM: {e}"))?,
    );

    let profile = ATMProfile::new(
        &atm,
        Some(alias.to_string()),
        did.to_string(),
        Some(mediator_did.to_string()),
    )
    .await
    .map_err(|e| format!("create ATM profile: {e}"))?;

    // Register with the ATM (`live_stream: false` — the websocket is enabled
    // explicitly and bounded, just below). Registering is what makes stopping
    // the socket possible: `graceful_shutdown` iterates the profile map.
    let profile = atm
        .profile_add(&profile, false)
        .await
        .map_err(|e| format!("register ATM profile: {e}"))?;

    // ── Past this point the ATM owns a registered profile and a live (or
    // half-open) mediator websocket, so every error path MUST tear it down. ──
    let transport = match connect_transport(&atm, &profile).await {
        Ok(transport) => transport,
        Err(e) => {
            atm.graceful_shutdown().await;
            return Err(e);
        }
    };

    Ok(RegistryMessaging {
        transport,
        atm,
        profile,
        relationship_store,
    })
}

/// Enable the mediator websocket (bounded) and bind the [`DidCommTransport`].
async fn connect_transport(
    atm: &Arc<ATM>,
    profile: &Arc<ATMProfile>,
) -> Result<Arc<dyn MessageTransport>, String> {
    match tokio::time::timeout(
        Duration::from_secs(30),
        atm.profile_enable_websocket(profile),
    )
    .await
    {
        Ok(res) => res.map_err(|e| format!("enable websocket: {e}"))?,
        Err(_) => {
            return Err(
                "timeout enabling websocket to mediator after 30s — mediator may be unreachable"
                    .to_string(),
            );
        }
    }

    Ok(Arc::new(
        DidCommTransport::new((**atm).clone(), profile.clone())
            .await
            .map_err(|e| format!("bind DidComm transport: {e}"))?,
    ))
}

/// How long an ack handed to the SDK's background deletion handler is
/// remembered, so that shutdown can delete it again directly in case the
/// queue had not reached it. A repeated delete of a message already gone is
/// harmless.
pub(crate) const RECENT_ACK_WINDOW: Duration = Duration::from_secs(60);
/// Most recently queued acks remembered for that.
const RECENT_ACK_CAPACITY: usize = 1_024;
/// Most ids the mediator deletes in one direct request.
const DIRECT_DELETE_BATCH: usize = 100;
/// Attempts at each direct delete batch on shutdown.
const DIRECT_DELETE_ATTEMPTS: u32 = 2;

/// Deletes messages at the mediator for [`InboundLoop`].
#[async_trait]
pub(crate) trait Acker: Send + Sync + 'static {
    /// Hand `id`'s delete to the SDK's background deletion handler. Returns
    /// once it is queued, not once it is deleted.
    async fn queue(&self, id: &str) -> Result<(), String>;

    /// Delete `ids` (at most [`DIRECT_DELETE_BATCH`]) at the mediator now,
    /// waiting for its answer.
    async fn delete_now(&self, ids: &[String]) -> Result<(), String>;
}

/// The [`Acker`] over the registry's ATM and profile.
struct AtmAcker {
    atm: Arc<ATM>,
    profile: Arc<ATMProfile>,
}

#[async_trait]
impl Acker for AtmAcker {
    async fn queue(&self, id: &str) -> Result<(), String> {
        self.atm
            .delete_message_background(&self.profile, id)
            .await
            .map_err(|e| e.to_string())
    }

    async fn delete_now(&self, ids: &[String]) -> Result<(), String> {
        let request = DeleteMessageRequest {
            message_ids: ids.to_vec(),
        };
        let response = self
            .atm
            .delete_messages_direct(&self.profile, &request)
            .await
            .map_err(|e| e.to_string())?;
        // An id the mediator names as an error is one it no longer holds —
        // typically one the background queue already deleted.
        for (id, error) in &response.errors {
            debug!("direct delete of message {id} reported: {error}");
        }
        Ok(())
    }
}

/// Where the loop's acks go: queued in the background while it runs, held
/// for a direct delete once shutdown has begun.
#[derive(Debug, Default)]
struct AckState {
    /// Shutdown has begun: hold acks for [`InboundLoop::flush_acks`].
    draining: bool,
    held: Vec<String>,
    /// Acks queued in the background lately, for a direct delete at
    /// shutdown in case the queue did not reach them.
    recent: VecDeque<(String, Instant)>,
}

impl AckState {
    /// Whether to queue `id` now (`true`), or hold it for the shutdown flush.
    fn take(&mut self, id: &str, now: Instant) -> bool {
        if self.draining {
            self.held.push(id.to_string());
            return false;
        }
        self.recent.push_back((id.to_string(), now));
        while self.recent.len() > RECENT_ACK_CAPACITY
            || self
                .recent
                .front()
                .is_some_and(|(_, at)| now.saturating_duration_since(*at) > RECENT_ACK_WINDOW)
        {
            self.recent.pop_front();
        }
        true
    }

    /// Every id to delete directly at shutdown, each once.
    fn take_flush(&mut self, now: Instant) -> Vec<String> {
        let mut seen = HashSet::new();
        let recent = self
            .recent
            .drain(..)
            .filter(|(_, at)| now.saturating_duration_since(*at) <= RECENT_ACK_WINDOW)
            .map(|(id, _)| id);
        let held = std::mem::take(&mut self.held);
        held.into_iter()
            .chain(recent)
            .filter(|id| seen.insert(id.clone()))
            .collect()
    }
}

/// Handles one inbound message for [`InboundLoop`], and says how it ended.
#[async_trait]
pub(crate) trait InboundSink: Send + Sync + 'static {
    async fn handle(&self, inbound: Inbound) -> Outcome;
}

/// Why [`InboundLoop::run`] returned.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum LoopEnd {
    /// The shutdown token was cancelled.
    Shutdown,
    /// The transport's inbound stream ended: the profile has no live websocket
    /// any more, and nothing will be received again.
    StreamEnded,
}

impl LoopEnd {
    fn into_result(self) -> Result<(), DIDCommError> {
        match self {
            Self::Shutdown => Ok(()),
            Self::StreamEnded => Err(DIDCommError::Messaging(
                "the mediator inbound stream ended: the profile's websocket is gone".to_string(),
            )),
        }
    }
}

/// Receives from a [`MessageTransport`] and acks each message only after it
/// has been handled (R1.6), at most [`MAX_INFLIGHT_HANDLERS`] at a time.
///
/// The loop takes the next message off the transport only once a handler
/// slot is free, so a burst waits at the mediator (beyond the few frames the
/// SDK's websocket task caches ahead of the stream, up to its fetch cache
/// limit), and nothing is lost while it waits: no message has
/// been acked before its handler returns.
pub(crate) struct InboundLoop<S: InboundSink> {
    transport: Arc<dyn MessageTransport>,
    acker: Arc<dyn Acker>,
    acks: Arc<std::sync::Mutex<AckState>>,
    sink: Arc<S>,
    ledger: Arc<std::sync::Mutex<DeliveryLedger>>,
    permits: Arc<Semaphore>,
    max_inflight: usize,
    handler_timeout: Duration,
    alias: String,
    shutdown: CancellationToken,
    /// Where the connection's state and given-up messages are reported.
    health: Option<Arc<RegistryHealth>>,
}

impl<S: InboundSink> InboundLoop<S> {
    pub(crate) fn new(
        transport: Arc<dyn MessageTransport>,
        acker: Arc<dyn Acker>,
        sink: Arc<S>,
        alias: &str,
        shutdown: CancellationToken,
    ) -> Self {
        Self {
            transport,
            acker,
            acks: Arc::default(),
            sink,
            ledger: Arc::default(),
            permits: Arc::new(Semaphore::new(MAX_INFLIGHT_HANDLERS)),
            max_inflight: MAX_INFLIGHT_HANDLERS,
            handler_timeout: HANDLER_TIMEOUT,
            alias: alias.to_string(),
            shutdown,
            health: None,
        }
    }

    /// Report the transport's connection state (`writes`) and the messages
    /// given up on (`givenUpMessages`) on `health`.
    pub(crate) fn with_health(mut self, health: Option<Arc<RegistryHealth>>) -> Self {
        if let Some(health) = &health {
            health.attach_pickup_listener();
        }
        self.health = health;
        self
    }

    /// Bound concurrent handlers to `max` and each to `timeout`.
    #[cfg(test)]
    fn with_limits(mut self, max: usize, timeout: Duration) -> Self {
        self.permits = Arc::new(Semaphore::new(max));
        self.max_inflight = max;
        self.handler_timeout = timeout;
        self
    }

    /// Receive until shutdown or until the inbound stream ends, then give
    /// running handlers time to finish, and delete what they and the recent
    /// background acks handled directly at the mediator.
    pub(crate) async fn run(&self) -> LoopEnd {
        use futures::StreamExt;

        // Taken here, when the loop is ready to handle what it yields: the
        // transport pulls from the socket only while this stream is polled.
        let mut stream = self.transport.inbound();
        // `/health` follows the transport's connection state, which changes on
        // every drop and reconnect (R6.2).
        let watcher = self.health.clone().map(|health| {
            tokio::spawn(report_connection_state(
                self.transport.connection_state(),
                health,
                self.alias.clone(),
            ))
        });
        info!(
            "[profile = {}] receiving from the mediator; each message is acked once handled",
            self.alias
        );
        let end = loop {
            let permit = tokio::select! {
                biased;
                _ = self.shutdown.cancelled() => break LoopEnd::Shutdown,
                permit = self.permits.clone().acquire_owned() => permit,
            };
            let Ok(permit) = permit else {
                // The semaphore is never closed; treat it like a shutdown.
                break LoopEnd::Shutdown;
            };
            let next = tokio::select! {
                biased;
                _ = self.shutdown.cancelled() => break LoopEnd::Shutdown,
                next = stream.next() => next,
            };
            let Some(inbound) = next else {
                error!(
                    "[profile = {}] the mediator inbound stream ended; nothing more will be \
                     received",
                    self.alias
                );
                break LoopEnd::StreamEnded;
            };
            self.dispatch(inbound, permit);
        };
        if end == LoopEnd::Shutdown {
            info!(
                "[profile = {}] receive loop stopping (shutdown signalled)",
                self.alias
            );
        }
        if let Some(watcher) = watcher {
            watcher.abort();
        }
        // From here acks are held, not queued: the background queue may not
        // be served again before the caller shuts the ATM down.
        lock_acks(&self.acks).draining = true;
        self.drain().await;
        if tokio::time::timeout(ACK_FLUSH_TIMEOUT, self.flush_acks())
            .await
            .is_err()
        {
            warn!(
                "[profile = {}] deleting handled messages directly took longer than \
                 {ACK_FLUSH_TIMEOUT:?}; the rest stay queued at the mediator and are handled \
                 again after a restart",
                self.alias
            );
        }
        end
    }

    /// Handle `inbound` on its own task, at most once per mediator message id,
    /// and ack it once the handler has finished.
    fn dispatch(&self, inbound: Inbound, permit: tokio::sync::OwnedSemaphorePermit) {
        let id = inbound.ack.0.clone();
        let claim = lock_ledger(&self.ledger).claim(&id, Instant::now());
        let acker = self.acker.clone();
        let acks = self.acks.clone();
        let alias = self.alias.clone();
        match claim {
            Claim::Dispatch => {}
            Claim::InFlight => {
                // Pushed again (a reconnect) while its first copy is being
                // handled; that handler acks it.
                debug!("[profile = {alias}] message {id} is already being handled; skipped");
                return;
            }
            Claim::AlreadyHandled => {
                // Handled, but pushed again: the earlier ack did not land. Ack
                // again; do not answer or apply it a second time.
                debug!("[profile = {alias}] message {id} was already handled; acking it again");
                tokio::spawn(async move {
                    let _permit = permit;
                    ack(acker.as_ref(), &acks, &alias, &id).await;
                });
                return;
            }
        }

        let sink = self.sink.clone();
        let ledger = self.ledger.clone();
        let limit = self.handler_timeout;
        let health = self.health.clone();
        tokio::spawn(async move {
            // Held until the ack is sent, so the shutdown drain waits for it.
            let _permit = permit;
            let attempt = async move { Ok::<_, String>(sink.handle(inbound).await) };
            let outcome = bounded_value_within(limit, &alias, "an inbound message", attempt)
                .await
                .unwrap_or(Outcome::Retry);
            let decision = lock_ledger(&ledger).finish(&id, outcome, Instant::now());
            match decision {
                Ack::Now => ack(acker.as_ref(), &acks, &alias, &id).await,
                Ack::Retain => warn!(
                    "[profile = {alias}] message {id} not handled; left queued at the mediator, \
                     to be offered again when the mediator next pushes the inbox"
                ),
                Ack::GiveUp => {
                    error!(
                        "[profile = {alias}] message {id} still failing after \
                         {GIVE_UP_ATTEMPTS} attempts over at least {GIVE_UP_MIN_AGE:?}; \
                         deleting it from the mediator as undeliverable"
                    );
                    if let Some(health) = &health {
                        health.record_given_up();
                    }
                    ack(acker.as_ref(), &acks, &alias, &id).await;
                }
            }
        });
    }

    /// Wait for running handlers (each bounded by the handler timeout) to
    /// finish and record their acks.
    async fn drain(&self) {
        let all = u32::try_from(self.max_inflight).unwrap_or(u32::MAX);
        let limit = self.handler_timeout + ACK_TIMEOUT;
        if tokio::time::timeout(limit, self.permits.acquire_many(all))
            .await
            .is_err()
        {
            warn!(
                "[profile = {}] handlers still running {limit:?} after the receive loop \
                 stopped; their messages stay queued at the mediator",
                self.alias
            );
        }
    }

    /// Delete, directly and waiting for the mediator's answer, every ack held
    /// since shutdown began and every ack queued in the background within
    /// [`RECENT_ACK_WINDOW`]. A batch that fails stays queued at the
    /// mediator: it is pushed again after a restart, re-handled, and a write
    /// replayed rather than re-applied while the dedup store remembers it.
    async fn flush_acks(&self) {
        let ids = lock_acks(&self.acks).take_flush(Instant::now());
        if ids.is_empty() {
            return;
        }
        let mut deleted = 0usize;
        for batch in ids.chunks(DIRECT_DELETE_BATCH) {
            // Twice: the first request can land on a pooled connection the
            // mediator has since closed.
            let mut last_error = String::new();
            for attempt in 1..=DIRECT_DELETE_ATTEMPTS {
                match tokio::time::timeout(ACK_TIMEOUT, self.acker.delete_now(batch)).await {
                    Ok(Ok(())) => {
                        deleted += batch.len();
                        last_error.clear();
                        break;
                    }
                    Ok(Err(e)) => last_error = e,
                    Err(_) => last_error = format!("timed out after {ACK_TIMEOUT:?}"),
                }
                if attempt < DIRECT_DELETE_ATTEMPTS {
                    tokio::time::sleep(Duration::from_millis(250)).await;
                }
            }
            if !last_error.is_empty() {
                warn!(
                    "[profile = {}] could not delete {} handled message(s) at the mediator on \
                     shutdown; they stay queued and are handled again after a restart: \
                     {last_error}",
                    self.alias,
                    batch.len()
                );
            }
        }
        info!(
            "[profile = {}] deleted {deleted} of {} handled message(s) directly at the mediator \
             on shutdown",
            self.alias,
            ids.len()
        );
    }
}

/// Mirror the transport's connection state on `health` until aborted:
/// connected is `ok`, dropped is `unavailable` until it reconnects, and
/// still connecting stays `starting` (which turns `unavailable` if it lasts).
async fn report_connection_state(
    mut state: tokio::sync::watch::Receiver<ConnState>,
    health: Arc<RegistryHealth>,
    alias: String,
) {
    loop {
        let current = *state.borrow_and_update();
        match current {
            ConnState::Connected => health.mark_writes_ok(),
            ConnState::Disconnected => {
                warn!("[profile = {alias}] the mediator connection dropped; reconnecting");
                health.mark_writes_unavailable(
                    "the mediator connection dropped; reconnecting (see the registry's log)",
                );
            }
            _ => {}
        }
        if state.changed().await.is_err() {
            // The transport is gone: nothing will report again.
            health.mark_writes_unavailable("the mediator connection closed");
            return;
        }
    }
}

fn lock_acks(acks: &std::sync::Mutex<AckState>) -> std::sync::MutexGuard<'_, AckState> {
    // Short, non-panicking critical sections only; a poisoned lock still
    // holds consistent state.
    acks.lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// Ack message `id`: queue its delete in the background while the loop runs,
/// or hold it for the direct delete at shutdown. A failure is not lost: the
/// message stays queued, is pushed again, and the ledger acks it again
/// without handling it again.
async fn ack(acker: &dyn Acker, acks: &std::sync::Mutex<AckState>, alias: &str, id: &str) {
    if !lock_acks(acks).take(id, Instant::now()) {
        debug!(
            "[profile = {alias}] message {id} handled during shutdown; held for a direct delete"
        );
        return;
    }
    match tokio::time::timeout(ACK_TIMEOUT, acker.queue(id)).await {
        Ok(Ok(())) => debug!("[profile = {alias}] message {id} queued for deletion"),
        Ok(Err(e)) => warn!(
            "[profile = {alias}] could not ack message {id} (it will be redelivered and acked \
             again): {e}"
        ),
        Err(_) => warn!(
            "[profile = {alias}] acking message {id} timed out (it will be redelivered and \
             acked again)"
        ),
    }
}

/// The registry's [`InboundSink`]: routes each message by protocol (and, for
/// TSP, by kind) to the DIDComm handler, the Trust Task handler, or the
/// relationship-control policy.
struct RegistryInbound<H: MessageHandler> {
    atm: Arc<ATM>,
    profile: Arc<ATMProfile>,
    /// The registry's own durable relationship store, which TSP activity is
    /// stamped on. `None` on a host-provided ATM, whose store is the host's.
    relationships: Option<Arc<RegistryRelationshipStore>>,
    handler: Arc<H>,
    tasks: TaskHandler,
}

#[async_trait]
impl<H: MessageHandler> InboundSink for RegistryInbound<H> {
    async fn handle(&self, inbound: Inbound) -> Outcome {
        match inbound.message.protocol {
            Protocol::DIDComm => {
                handle_didcomm(inbound, &self.atm, &self.profile, &self.handler).await
            }
            Protocol::TSP => {
                handle_tsp(
                    inbound,
                    &self.atm,
                    &self.profile,
                    self.relationships.as_deref(),
                    &self.tasks,
                )
                .await
            }
            // R1.6, deliberate ack without handling, for both arms below:
            // nothing in this process can ever handle these frames, so leaving
            // them queued would only have them pushed again until the
            // mediator's expiry.
            //
            // DIDComm v1 (Aries RFC 0019) shares no wire format with v2.1.
            Protocol::DIDCommV1 => {
                warn!(
                    "received an inbound DIDComm v1 frame; the registry speaks v2.1 only — \
                     dropping"
                );
                Outcome::Poison
            }
            // `Protocol` is `#[non_exhaustive]`; an unknown one is a minor
            // release away and must not take the listener down.
            _ => {
                warn!("received an inbound frame of an unknown protocol — dropping");
                Outcome::Poison
            }
        }
    }
}

/// DIDComm arm: rehydrate the plaintext [`Message`] from the transport's
/// payload, stamp the **cryptographically-authenticated** sender onto `from`,
/// synthesize the [`UnpackMetadata`] the handler reads, and dispatch through
/// the same [`MessageHandler`] the pickup listener uses.
///
/// The handler's result decides the ack exactly as on the pickup path: `Ok`
/// is handled, `Err` is left queued.
async fn handle_didcomm<H: MessageHandler>(
    inbound: Inbound,
    atm: &Arc<ATM>,
    profile: &Arc<ATMProfile>,
    handler: &Arc<H>,
) -> Outcome {
    let mut message: Message = match serde_json::from_slice(&inbound.message.payload) {
        Ok(m) => m,
        Err(e) => {
            // The SDK serialised this payload from a message it unpacked, so
            // a failure is a property of the bytes.
            warn!(error = %e, "dropping an inbound DIDComm frame that did not rehydrate");
            return Outcome::Poison;
        }
    };
    // The plaintext `from` header is sender-controlled; the proven sender is
    // `inbound.message.sender` (None when the envelope was anoncrypt or the
    // claimed `from` did not match the authcrypt key). Stamp it so the handler
    // reads the value the transport authenticated, not the one the sender chose.
    if let Some(sender) = &inbound.message.sender {
        message.from = Some(sender.clone());
    }
    // Only `authenticated` and `anonymous_sender` are read downstream (the
    // mediator-transport spoof guard, and which sender a reply may go to: a
    // message without a proven sender is not answered). The transport sets
    // `verified` only for a sender bound to the authcrypt key, so it maps onto
    // both flags. The other fields are left at their defaults: the transport
    // does not pass them on. `UnpackMetadata` is `#[non_exhaustive]`, so it is
    // built from `default()` + field assignment rather than a struct literal.
    let mut meta = UnpackMetadata::default();
    meta.authenticated = inbound.message.verified;
    meta.anonymous_sender = inbound.message.sender.is_none();
    meta.encrypted = inbound.message.encrypted;
    match handler.handle(atm, profile, message, meta).await {
        Ok(()) => Outcome::Handled,
        Err(e) => {
            warn!(error = %e, "registry DIDComm handler returned an error; message left queued");
            Outcome::Retry
        }
    }
}

/// TSP arm: answer a relationship-control frame, or dispatch an application
/// frame to the Trust Task handler.
///
/// When the registry owns the relationship store, an accepted relationship and
/// every application frame stamp the relationship active, so it is kept while
/// in use and evicted once idle.
async fn handle_tsp(
    inbound: Inbound,
    atm: &Arc<ATM>,
    profile: &Arc<ATMProfile>,
    relationships: Option<&RegistryRelationshipStore>,
    tasks: &TaskHandler,
) -> Outcome {
    let Some(sender_vid) = inbound.message.sender.clone() else {
        // The SDK always authenticates a TSP sender; a frame without one can
        // never be answered.
        warn!("inbound TSP frame has no authenticated sender VID — dropping");
        return Outcome::Poison;
    };

    // A relationship request is not traffic: it carries no envelope, and the
    // transport has already RECORDED it (which admits the application messages
    // that follow). What is left is the answer, and that is the registry's. A
    // failed answer is logged and the frame acked: the relationship is
    // recorded either way, and redelivery would only repeat the answer.
    if let InboundKind::RelationshipControl {
        request,
        thread_digest,
        reply_expected,
        ..
    } = inbound.kind
    {
        let decision = handle_tsp_control(
            atm,
            profile,
            relationships,
            &sender_vid,
            request,
            thread_digest,
            reply_expected,
        )
        .await;
        if shows_activity(Some(&decision)) {
            stamp(profile, relationships, &sender_vid).await;
        }
        return Outcome::Handled;
    }

    if shows_activity(None) {
        stamp(profile, relationships, &sender_vid).await;
    }

    // Application frame: the payload is the already-unpacked binding envelope.
    match crate::tsp::dispatch_tsp_application(
        atm,
        profile,
        tasks,
        &inbound.message.payload,
        &sender_vid,
    )
    .await
    {
        Ok(crate::tsp::TspDispatch::Answered) => Outcome::Handled,
        // The refusal sent was `retryable` (storage unavailable, an internal
        // error): leave the frame queued so it is tried again (R1.6).
        Ok(crate::tsp::TspDispatch::Retryable) => Outcome::Retry,
        // Decrypted cleanly but is not a Trust Task envelope.
        Err(_) => Outcome::Poison,
    }
}

/// Whether a TSP frame shows its sender's relationship in use: every
/// application frame (`None`), and a relationship request the registry
/// accepts. A cancellation or an unanswered request does not.
fn shows_activity(control: Option<&ControlDecision>) -> bool {
    matches!(control, None | Some(ControlDecision::Accept))
}

/// What to log when an accept could not be sent, given the relationship state
/// the registry's store holds afterwards (`None` when the store is the host's
/// and was not read): whether the relationship was recorded decides whether
/// the peer's traffic still flows.
fn accept_failure_note(recorded: Option<RelationshipState>) -> &'static str {
    match recorded {
        Some(RelationshipState::None) => {
            "could not accept a TSP relationship, and it is not recorded (the relationship \
             store refused or failed): the peer's messages are not admitted until it invites again"
        }
        Some(_) => {
            "could not send a TSP relationship accept; the relationship stays recorded, so \
             traffic still flows, but the peer sees no answer"
        }
        None => {
            "could not send a TSP relationship accept; whether the relationship is recorded is \
             up to the host ATM's relationship store"
        }
    }
}

/// Stamp the relationship with `their_vid` as active now, when the registry
/// owns the relationship store.
async fn stamp(
    profile: &ATMProfile,
    relationships: Option<&RegistryRelationshipStore>,
    their_vid: &str,
) {
    let Some(relationships) = relationships else {
        return;
    };
    match profile.dids() {
        Ok((our_vid, _)) => mark_active(relationships, our_vid, their_vid).await,
        Err(e) => warn!(error = %e, "no profile DID to stamp TSP relationship activity under"),
    }
}

/// Answer one inbound TSP relationship request (§7.2), or decline to. Returns
/// the decision made.
///
/// The policy is [`decide_control`] — a pure function — and it performs no ACL
/// check: the ACL gate lives at the Trust Task layer. Nothing here can fail the
/// listener; a reply that cannot be sent is logged and dropped. The store the
/// transport records relationships in is bounded
/// ([`crate::messaging::relationship_store`]) when the registry owns it.
async fn handle_tsp_control(
    atm: &Arc<ATM>,
    profile: &Arc<ATMProfile>,
    relationships: Option<&RegistryRelationshipStore>,
    sender_vid: &str,
    request: affinidi_messaging_core::RelationshipRequest,
    thread_digest: [u8; 32],
    reply_expected: bool,
) -> ControlDecision {
    let decision = decide_control(request, reply_expected);
    match &decision {
        ControlDecision::Accept => {
            match atm
                .tsp()
                .accept_relationship(profile, sender_vid, thread_digest)
                .await
            {
                Ok(state) => info!(
                    sender = %sender_vid, ?request, ?state,
                    "accepted an inbound TSP relationship request",
                ),
                Err(e) => {
                    let recorded = match relationships {
                        Some(relationships) => Some(match profile.dids() {
                            Ok((our_vid, _)) => relationships
                                .get(our_vid, sender_vid)
                                .await
                                .unwrap_or(RelationshipState::None),
                            Err(_) => RelationshipState::None,
                        }),
                        None => None,
                    };
                    warn!(
                        sender = %sender_vid, error = %e, ?recorded,
                        "{}", accept_failure_note(recorded),
                    );
                }
            }
        }
        // The SDK answers a mutual cancellation itself; `reply_expected` is
        // only still set when that send failed, and the relationship is
        // already gone, so this re-sends the answer without the state machine.
        ControlDecision::Cancel(why) => {
            match atm
                .tsp()
                .answer_cancellation(profile, sender_vid, thread_digest)
                .await
            {
                Ok(_) => info!(
                    sender = %sender_vid, ?request, reason = %why,
                    "answered an inbound TSP relationship request with a cancellation",
                ),
                Err(e) => warn!(
                    sender = %sender_vid, reason = %why, error = %e,
                    "could not send a TSP relationship cancellation",
                ),
            }
        }
        ControlDecision::Nothing => info!(
            sender = %sender_vid, ?request,
            "recorded an inbound TSP relationship request; no answer is due",
        ),
    }
    decision
}

#[cfg(test)]
mod tests;
