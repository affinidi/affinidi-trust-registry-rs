//! Delivery-layer messaging for a TSP-enabled registry.
//!
//! Mirrors `vta-service::messaging::service`: build a [`TDKSharedState`] seeded
//! with the registry's secrets, an [`ATM`] carrying a **durable** TSP
//! relationship store, a profile against the mediator, then a bounded
//! `profile_enable_websocket` before a [`DidCommTransport`] is bound and driven
//! by a [`MessagingService`].
//!
//! The point of the delivery layer here is its inbound stream: `DidCommTransport`
//! records inbound TSP relationship-control frames (Rev 3 §7.2.2) and tags each
//! [`Inbound`] with its [`InboundKind`], so the registry answers control frames
//! and never mistakes one for a Trust Task. A DIDComm-only registry does not use
//! this module at all — it keeps its own pickup loop.

use std::sync::Arc;
use std::time::Duration;

use affinidi_messaging_core::{Inbound, InboundKind, Protocol};
use affinidi_messaging_delivery::{MessagingService, OutboxStore};
use affinidi_tdk::common::TDKSharedState;
use affinidi_tdk::common::config::TDKConfig;
use affinidi_tdk::didcomm::Message;
use affinidi_tdk::messaging::config::ATMConfig;
use affinidi_tdk::messaging::messages::compat::UnpackMetadata;
use affinidi_tdk::messaging::profiles::ATMProfile;
use affinidi_tdk::messaging::{ATM, DidCommTransport};
use affinidi_tdk::secrets_resolver::SecretsResolver;
use affinidi_tdk::secrets_resolver::secrets::Secret;
use tokio_util::sync::CancellationToken;
use tracing::{info, warn};

use crate::configs::{DidcommConfig, ProfileConfig};
use crate::didcomm::error::DIDCommError;
use crate::didcomm::listener::MessageHandler;
use crate::didcomm::listener::mediator_functions::set_mediator_acl_mode;
use crate::messaging::kv::{KvKeyspace, MessagingStore};
use crate::messaging::outbox_store::FjallOutboxStore;
use crate::messaging::relationship_store::{FjallRelationshipKv, RegistryRelationshipStore};
use crate::messaging::tsp_inbound::{ControlDecision, decide_control};
use crate::trust_tasks::TaskHandler;

/// Resolve the on-disk path for the messaging store, namespaced per profile so
/// two DIDs never share one fjall database. `TR_MESSAGING_STORE_PATH` overrides
/// the base; otherwise it follows the secret store's data dir convention.
fn messaging_store_path(alias: &str) -> std::path::PathBuf {
    let base = std::env::var("TR_MESSAGING_STORE_PATH")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|_| {
            std::env::var("TR_SECRETS_DATA_DIR")
                .map(std::path::PathBuf::from)
                .unwrap_or_else(|_| std::path::PathBuf::from("./.trust-registry"))
                .join("messaging")
        });
    let safe: String = alias
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '_' })
        .collect();
    base.join(safe)
}

/// The Managed-source delivery-layer listener: open the durable messaging store,
/// build the [`MessagingService`] with a persistent relationship store, apply
/// the mediator ACL mode, spawn the relationship-maintenance sweep once, then
/// drive inbound off the delivery layer until shutdown.
///
/// This replaces the hand-rolled pickup loop for a TSP-enabled registry. It runs
/// until `shutdown`, mirroring `Listener::start_listening`.
pub async fn start_managed_delivery<H: MessageHandler>(
    profile_config: ProfileConfig,
    config: Arc<DidcommConfig>,
    handler: Arc<H>,
    tasks: TaskHandler,
    shutdown: CancellationToken,
) -> Result<(), DIDCommError> {
    let path = messaging_store_path(&profile_config.alias);
    let path_str = path.to_str().ok_or_else(|| {
        DIDCommError::Messaging(format!("non-UTF-8 messaging store path: {path:?}"))
    })?;
    // Keep the store (and its fjall DB handle + background threads) alive for the
    // whole life of the listener — bound here, dropped when the loop returns.
    let store = MessagingStore::open(path_str).map_err(DIDCommError::Messaging)?;

    let messaging = build_messaging(
        profile_config.secrets,
        &profile_config.did,
        &profile_config.alias,
        &config.mediator_did,
        store.relationships.clone(),
        store.outbox.clone(),
    )
    .await
    .map_err(DIDCommError::Messaging)?;

    // Apply the same ACL mode the pickup path would (advisory — logs, never
    // refuses to start).
    if let Err(e) =
        set_mediator_acl_mode(&messaging.atm, &messaging.profile, config.acl_mode.clone()).await
    {
        warn!("Failed to set ACL mode for Trust Registry DID. Error: {e}");
    }

    // The relationship-store maintenance sweep runs ONCE, here — never on the
    // connect path — because it holds the store and does not depend on the
    // socket (tying it to connect would leak one sweep task per reconnect).
    tokio::spawn(crate::messaging::relationship_store::maintenance_loop(
        messaging.relationship_store.clone(),
    ));

    info!(
        "[profile = {}] TSP relationship management active; driving inbound off the delivery layer",
        &profile_config.alias
    );
    run_inbound_loop(
        messaging.service.clone(),
        messaging.atm.clone(),
        messaging.profile.clone(),
        handler,
        tasks,
        shutdown,
    )
    .await;

    drop(store);
    Ok(())
}

/// The live delivery-layer wiring for the registry's mediator socket.
pub struct RegistryMessaging {
    pub service: Arc<MessagingService>,
    pub atm: Arc<ATM>,
    pub profile: Arc<ATMProfile>,
    /// The durable relationship store — kept so the caller can spawn the
    /// maintenance loop over it exactly once, at startup.
    pub relationship_store: Arc<RegistryRelationshipStore>,
}

/// Build the delivery-layer [`MessagingService`] over a [`DidCommTransport`]
/// bound to the registry's single mediator websocket, with a durable TSP
/// relationship store injected into the ATM.
///
/// Every error path after `profile_add` must `graceful_shutdown` the ATM — there
/// is no `Drop` impl, and an abandoned socket keeps auto-reconnecting while
/// holding the mediator's one-socket-per-DID slot.
pub async fn build_messaging(
    secrets: Vec<Secret>,
    did: &str,
    alias: &str,
    mediator_did: &str,
    relationships_ks: KvKeyspace,
    outbox_ks: KvKeyspace,
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
    let relationship_store = Arc::new(RegistryRelationshipStore::new(FjallRelationshipKv::new(
        relationships_ks,
    )));
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

    let outbox: Arc<dyn OutboxStore> = Arc::new(FjallOutboxStore::new(outbox_ks));
    let service = Arc::new(MessagingService::new(transport.clone(), outbox.clone()));

    // Durable outbox loops: drain due entries + retries, outbox-drain confirms
    // delivery on recipient pickup, confirmation sweep settles expired entries.
    // Dormant while the registry answers synchronously, but wired for restart
    // resilience.
    tokio::spawn(affinidi_messaging_delivery::drain_loop(
        outbox.clone(),
        service.primary_handle(),
        Duration::from_secs(2),
    ));
    tokio::spawn(affinidi_messaging_delivery::outbox_drain_loop(
        service.primary_handle(),
        outbox.clone(),
        Duration::from_secs(10),
    ));
    tokio::spawn(affinidi_messaging_delivery::confirmation_loop(
        outbox.clone(),
        Duration::from_secs(30),
    ));

    Ok(RegistryMessaging {
        service,
        atm,
        profile,
        relationship_store,
    })
}

/// Enable the mediator websocket (bounded) and bind the [`DidCommTransport`].
async fn connect_transport(
    atm: &Arc<ATM>,
    profile: &Arc<ATMProfile>,
) -> Result<Arc<dyn affinidi_messaging_core::MessageTransport>, String> {
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

/// Drive inbound dispatch off [`MessagingService::subscribe`] until shutdown.
///
/// DIDComm frames are rehydrated to the registry's existing [`MessageHandler`];
/// TSP application frames go to the shared Trust-Task spine; TSP
/// relationship-control frames are answered per [`decide_control`]. The service
/// owns ack timing (it deletes at the mediator on dispatch), and delivery is
/// at-least-once — the DIDComm handler and the Trust-Task handler both dedup on
/// message id, so a redelivery replays rather than duplicates.
pub async fn run_inbound_loop<H: MessageHandler>(
    service: Arc<MessagingService>,
    atm: Arc<ATM>,
    profile: Arc<ATMProfile>,
    handler: Arc<H>,
    tasks: TaskHandler,
    shutdown: CancellationToken,
) {
    use futures::StreamExt;

    let mut stream = service.subscribe();
    info!("registry messaging connected to mediator — inbound messages will be processed");

    // Bounded concurrency: a burst (or a hostile sender) must not turn into
    // unbounded task growth. At the cap the loop waits for a permit.
    const MAX_INFLIGHT_INBOUND: usize = 32;
    let inflight = Arc::new(tokio::sync::Semaphore::new(MAX_INFLIGHT_INBOUND));

    loop {
        tokio::select! {
            maybe = stream.next() => {
                let Some(inbound) = maybe else {
                    warn!("registry inbound stream ended — messaging dispatcher stopping");
                    break;
                };
                let permit = match Arc::clone(&inflight).acquire_owned().await {
                    Ok(p) => p,
                    Err(_) => {
                        warn!("inbound concurrency semaphore closed — stopping");
                        break;
                    }
                };
                let atm = atm.clone();
                let profile = profile.clone();
                let handler = handler.clone();
                let tasks = tasks.clone();
                tokio::spawn(async move {
                    let _permit = permit;
                    handle_inbound(inbound, &atm, &profile, &handler, &tasks).await;
                });
            }
            _ = shutdown.cancelled() => {
                info!("registry messaging stopping (shutdown signalled)");
                break;
            }
        }
    }
    info!("registry messaging stopped");
}

/// Route one inbound frame by protocol (and, for TSP, by kind).
async fn handle_inbound<H: MessageHandler>(
    inbound: Inbound,
    atm: &Arc<ATM>,
    profile: &Arc<ATMProfile>,
    handler: &Arc<H>,
    tasks: &TaskHandler,
) {
    match inbound.message.protocol {
        Protocol::DIDComm => handle_didcomm(inbound, atm, profile, handler).await,
        Protocol::TSP => handle_tsp(inbound, atm, profile, tasks).await,
        // DIDComm v1 (Aries RFC 0019) shares no wire format with v2.1; drop it.
        Protocol::DIDCommV1 => {
            warn!("received an inbound DIDComm v1 frame; the registry speaks v2.1 only — dropping");
        }
        // `Protocol` is `#[non_exhaustive]`; an unknown one is a minor release
        // away and must not take the listener down.
        _ => warn!("received an inbound frame of an unknown protocol — dropping"),
    }
}

/// DIDComm arm: rehydrate the plaintext [`Message`] from the delivery-layer
/// payload, stamp the **cryptographically-authenticated** sender onto `from`,
/// synthesize the minimal [`UnpackMetadata`] the handler reads, and dispatch
/// through the registry's existing handler — behaviourally identical to the
/// pickup-loop path.
async fn handle_didcomm<H: MessageHandler>(
    inbound: Inbound,
    atm: &Arc<ATM>,
    profile: &Arc<ATMProfile>,
    handler: &Arc<H>,
) {
    let mut message: Message = match serde_json::from_slice(&inbound.message.payload) {
        Ok(m) => m,
        Err(e) => {
            warn!(error = %e, "dropping an inbound DIDComm frame that did not rehydrate");
            return;
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
    // mediator-transport spoof guard); the rest default. `verified` means a
    // cryptographically-bound sender, so it maps onto both flags. `UnpackMetadata`
    // is `#[non_exhaustive]`, so it is built from `default()` + field assignment
    // rather than a struct literal.
    let mut meta = UnpackMetadata::default();
    meta.authenticated = inbound.message.verified;
    meta.anonymous_sender = inbound.message.sender.is_none();
    meta.encrypted = inbound.message.encrypted;
    if let Err(e) = handler.handle(atm, profile, message, meta).await {
        warn!(error = %e, "registry DIDComm handler returned an error");
    }
}

/// TSP arm: answer a relationship-control frame, or dispatch an application
/// frame on the shared Trust-Task spine.
async fn handle_tsp(
    inbound: Inbound,
    atm: &Arc<ATM>,
    profile: &Arc<ATMProfile>,
    tasks: &TaskHandler,
) {
    let Some(sender_vid) = inbound.message.sender.clone() else {
        warn!("inbound TSP frame has no authenticated sender VID — dropping");
        return;
    };

    // A relationship request is not traffic: it carries no envelope, and the
    // transport has already RECORDED it (which admits the application messages
    // that follow). What is left is the answer, and that is the registry's.
    if let InboundKind::RelationshipControl {
        request,
        thread_digest,
        reply_expected,
        ..
    } = inbound.kind
    {
        handle_tsp_control(
            atm,
            profile,
            &sender_vid,
            request,
            thread_digest,
            reply_expected,
        )
        .await;
        return;
    }

    // Application frame: the payload is the already-unpacked binding envelope.
    crate::tsp::dispatch_tsp_application(
        atm,
        profile,
        tasks,
        &inbound.message.payload,
        &sender_vid,
    )
    .await;
}

/// Answer one inbound TSP relationship request (§7.2), or decline to.
///
/// The policy is [`decide_control`] — a pure function — and it performs no ACL
/// check: the ACL gate lives at the Trust Task layer. Nothing here can fail the
/// listener; a reply that cannot be sent is logged and dropped.
async fn handle_tsp_control(
    atm: &Arc<ATM>,
    profile: &Arc<ATMProfile>,
    sender_vid: &str,
    request: affinidi_messaging_core::RelationshipRequest,
    thread_digest: [u8; 32],
    reply_expected: bool,
) {
    match decide_control(request, reply_expected) {
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
                Err(e) => warn!(
                    sender = %sender_vid, error = %e,
                    "could not send a TSP relationship accept; the relationship stays recorded, \
                     so traffic still flows, but the peer sees no answer",
                ),
            }
        }
        ControlDecision::Cancel(why) => {
            match atm
                .tsp()
                .cancel_relationship(profile, sender_vid, thread_digest)
                .await
            {
                Ok(state) => info!(
                    sender = %sender_vid, ?request, ?state, reason = %why,
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
}
