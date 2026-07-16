//! DIDComm binding: the `trust-tasks-didcomm` envelope over an ATM mediator.
//!
//! The request document travels as the body of a DIDComm message of type
//! [`trust_tasks_didcomm::ENVELOPE_TYPE`], authcrypt-packed and forwarded via
//! the profile's mediator — the same wire the registry's own DIDComm binding
//! speaks. Replies come back on the profile's pickup stream; a single demux
//! task routes them to waiters by the reply document's `threadId` (the
//! registry sets it to the request id).
//!
//! ### Profile requirements
//!
//! The [`ATMProfile`] must have a mediator configured and websocket live
//! delivery enabled before the first exchange. Give this transport a profile
//! of its own: replies are picked from the profile's inbound stream, and a
//! second consumer on the same stream would steal them.
//!
//! ### Delivery semantics
//!
//! Inbound envelope frames are acked (deleted from the mediator) only after
//! the reply has been handed to its waiter; frames that are not Trust Task
//! envelopes, or that correlate to no in-flight request, are left untouched.
//!
//! Once the TDK delivery layer (architecture decision D1, phase 2) is
//! consumable, this arm's internals move onto it; the [`TrqlTransport`] seam
//! keeps that swap invisible to callers.

use std::sync::Arc;
use std::time::Duration;

use affinidi_tdk::didcomm::Message;
use affinidi_tdk::messaging::{ATM, profiles::ATMProfile};
use serde_json::Value;
use tracing::{debug, warn};
use trust_tasks_didcomm::ENVELOPE_TYPE;
use trust_tasks_rs::TrustTask;

use crate::error::TrqlError;
use crate::pending::PendingReplies;
use crate::transport::{TransportKind, TrqlTransport};

/// How long each inbound pickup poll waits before looping.
const INBOUND_POLL_WAIT: Duration = Duration::from_secs(10);
/// Backoff after a transient inbound error so the demux loop doesn't spin.
const INBOUND_ERROR_BACKOFF: Duration = Duration::from_millis(500);

/// Configuration for [`DidcommTransport`].
#[derive(Debug, Clone)]
pub struct DidcommTransportConfig {
    /// How long to wait for the registry's reply before failing the exchange.
    pub reply_timeout: Duration,
}

impl Default for DidcommTransportConfig {
    /// 60s, the stack-wide DIDComm reply default.
    fn default() -> Self {
        Self {
            reply_timeout: Duration::from_secs(60),
        }
    }
}

/// [`TrqlTransport`] over the `trust-tasks-didcomm` binding.
pub struct DidcommTransport {
    atm: ATM,
    profile: Arc<ATMProfile>,
    pending: PendingReplies,
    reply_timeout: Duration,
    demux: tokio::task::JoinHandle<()>,
}

impl DidcommTransport {
    /// Bind the transport to `profile` and start its reply-demux task.
    ///
    /// Fails if the profile has no mediator — without one there is no route
    /// to the registry and no pickup stream for replies.
    pub fn new(
        atm: ATM,
        profile: Arc<ATMProfile>,
        config: DidcommTransportConfig,
    ) -> Result<Self, TrqlError> {
        if profile.to_tdk_profile().mediator.is_none() {
            return Err(TrqlError::Config(
                "profile has no mediator configured (required for the DIDComm binding)".to_string(),
            ));
        }
        let pending = PendingReplies::new();
        let demux = tokio::spawn(demux_loop(atm.clone(), profile.clone(), pending.clone()));
        Ok(Self {
            atm,
            profile,
            pending,
            reply_timeout: config.reply_timeout,
            demux,
        })
    }
}

impl Drop for DidcommTransport {
    fn drop(&mut self) {
        self.demux.abort();
    }
}

#[async_trait::async_trait]
impl TrqlTransport for DidcommTransport {
    fn kind(&self) -> TransportKind {
        TransportKind::Didcomm
    }

    async fn exchange(&self, request: TrustTask<Value>) -> Result<TrustTask<Value>, TrqlError> {
        let dest = request.recipient.clone().ok_or_else(|| {
            TrqlError::Config("request document has no recipient to route to".to_string())
        })?;
        let request_id = request.id.clone();
        let body = serde_json::to_value(&request)
            .map_err(|e| TrqlError::Contract(format!("request did not serialize: {e}")))?;

        // Register the waiter before sending so a fast reply cannot be lost.
        let receiver = self.pending.register(&request_id);

        let send_result = self.send_envelope(&dest, &request_id, body).await;
        if let Err(error) = send_result {
            self.pending.abandon(&request_id);
            return Err(error);
        }

        match tokio::time::timeout(self.reply_timeout, receiver).await {
            Ok(Ok(document)) => Ok(document),
            Ok(Err(_closed)) => {
                self.pending.abandon(&request_id);
                Err(TrqlError::Transport {
                    kind: TransportKind::Didcomm,
                    detail: "reply demux task stopped".to_string(),
                })
            }
            Err(_elapsed) => {
                self.pending.abandon(&request_id);
                Err(TrqlError::Timeout {
                    kind: TransportKind::Didcomm,
                    waited_secs: self.reply_timeout.as_secs(),
                })
            }
        }
    }
}

impl DidcommTransport {
    /// Pack the envelope and hand it to the mediator. `Ok` means the mediator
    /// accepted the frame — not that the registry received it; end-to-end
    /// confirmation is the awaited reply itself.
    async fn send_envelope(
        &self,
        dest: &str,
        request_id: &str,
        body: Value,
    ) -> Result<(), TrqlError> {
        let my_did = self.profile.inner.did.clone();
        let envelope_id = uuid::Uuid::new_v4().to_string();
        let envelope = Message::build(envelope_id.clone(), ENVELOPE_TYPE.to_string(), body)
            .from(my_did.clone())
            .to(dest.to_string())
            .thid(request_id.to_string())
            .finalize();

        let packed = self
            .atm
            .pack_encrypted(&envelope, dest, Some(&my_did), Some(&my_did))
            .await
            .map_err(|e| TrqlError::Transport {
                kind: TransportKind::Didcomm,
                detail: format!("packing failed: {e}"),
            })?;

        let mediator = self
            .profile
            .to_tdk_profile()
            .mediator
            .clone()
            .ok_or_else(|| {
                TrqlError::Config("profile lost its mediator configuration".to_string())
            })?;

        self.atm
            .forward_and_send_message(
                &self.profile,
                false,
                &packed.0,
                Some(&envelope_id),
                &mediator,
                dest,
                None,
                None,
                false,
            )
            .await
            .map_err(|e| TrqlError::Transport {
                kind: TransportKind::Didcomm,
                detail: format!("send via mediator failed: {e}"),
            })?;
        Ok(())
    }
}

/// The single owner of the profile's inbound pickup stream. Routes Trust Task
/// envelope replies to waiters; survives transient stream errors.
async fn demux_loop(atm: ATM, profile: Arc<ATMProfile>, pending: PendingReplies) {
    loop {
        match atm
            .message_pickup()
            .live_stream_next(&profile, Some(INBOUND_POLL_WAIT), false)
            .await
        {
            Ok(Some((message, meta))) => {
                if message.typ != ENVELOPE_TYPE {
                    // Not a Trust Task envelope — not ours to consume or ack.
                    continue;
                }
                let document: TrustTask<Value> = match serde_json::from_value(message.body) {
                    Ok(document) => document,
                    Err(e) => {
                        warn!("dropping malformed Trust Task envelope: {e}");
                        continue;
                    }
                };
                // Ack (mediator delete) only after the waiter holds the reply;
                // an unrouted reply stays queued rather than being destroyed.
                if pending.route(document)
                    && let Err(e) = atm
                        .delete_message_background(&profile, &meta.sha256_hash)
                        .await
                {
                    debug!("ack of handled reply failed (will redeliver): {e}");
                }
            }
            Ok(None) => {}
            Err(e) => {
                debug!("inbound stream error (backing off): {e}");
                tokio::time::sleep(INBOUND_ERROR_BACKOFF).await;
            }
        }
    }
}
