//! DIDComm binding: the `trust-tasks-didcomm` envelope over an ATM mediator.
//!
//! The request document travels as the body of a DIDComm message of type
//! [`trust_tasks_didcomm::ENVELOPE_TYPE`], authcrypt-packed and forwarded via
//! the profile's mediator — the same wire the registry's own DIDComm binding
//! speaks. Replies come back on the profile's pickup stream; a single demux
//! task routes them to waiters by the reply document's `threadId` (the
//! registry sets it to the request id).
//!
//! ### Sender binding
//!
//! A reply completes an exchange only if it was authcrypted by a key of the
//! DID the request was addressed to (the document's `recipient`): the
//! envelope must be authenticated, the DID owning the encrypting key must be
//! that DID, and the plaintext `from`, if present, must name it too. An
//! anoncrypted or plaintext reply, or one from any other party, is not handed
//! to the waiter, which keeps waiting for the registry's own reply.
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
//! envelopes, that correlate to no in-flight request, or that come from a
//! party other than the one addressed, are left untouched.
//!
//! Once the TDK delivery layer (architecture decision D1, phase 2) is
//! consumable, this arm's internals move onto it; the [`TrqlTransport`] seam
//! keeps that swap invisible to callers.

use std::sync::Arc;
use std::time::Duration;

use affinidi_tdk::did_common::scid::same_reference;
use affinidi_tdk::didcomm::Message;
use affinidi_tdk::messaging::messages::compat::UnpackMetadata;
use affinidi_tdk::messaging::{ATM, profiles::ATMProfile};
use serde_json::Value;
use tracing::{debug, warn};
use trust_tasks_didcomm::ENVELOPE_TYPE;
use trust_tasks_rs::TrustTask;

use crate::error::TrqlError;
use crate::pending::{PendingReplies, RouteOutcome};
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
        let receiver = self.pending.register(&request_id, &dest);

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

/// Route one unpacked DIDComm message to its waiter, bound to the sender
/// the envelope authenticated. Messages that are not Trust Task envelopes are
/// [`RouteOutcome::Unsolicited`] and left alone.
fn route_envelope(
    pending: &PendingReplies,
    message: Message,
    meta: &UnpackMetadata,
) -> RouteOutcome {
    if message.typ != ENVELOPE_TYPE {
        // Not a Trust Task envelope — not ours to consume or ack.
        return RouteOutcome::Unsolicited;
    }
    let sender = authenticated_sender(&message, meta);
    let document: TrustTask<Value> = match serde_json::from_value(message.body) {
        Ok(document) => document,
        Err(e) => {
            warn!("dropping malformed Trust Task envelope: {e}");
            return RouteOutcome::Unsolicited;
        }
    };
    let outcome = pending.route(document, sender.as_deref());
    if let RouteOutcome::WrongSender { expected } = &outcome {
        warn!(
            expected,
            sender = sender.as_deref().unwrap_or("<not authenticated>"),
            "ignoring a Trust Task reply that was not authcrypted by the party the request was addressed to"
        );
    }
    outcome
}

/// The DID that authcrypted `message`, or `None` when the envelope was not
/// authenticated (anoncrypt, signed-only or plaintext), names no key, or its
/// plaintext `from` names a different DID than the key's owner. The `from`
/// header alone is never trusted: it is whatever the sender wrote.
fn authenticated_sender(message: &Message, meta: &UnpackMetadata) -> Option<String> {
    if !meta.authenticated || meta.anonymous_sender {
        return None;
    }
    let kid = meta.encrypted_from_kid.as_deref()?;
    let (key_did, _fragment) = kid.split_once('#')?;
    match message.from.as_deref() {
        Some(from) if !same_reference(from, key_did) => None,
        _ => Some(key_did.to_string()),
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
                // Ack (mediator delete) only after the waiter holds the reply;
                // an unrouted reply stays queued rather than being destroyed.
                if route_envelope(&pending, message, &meta) == RouteOutcome::Delivered
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

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;
    use crate::pending::tests::{OTHER, REGISTRY, reply_to};
    use tokio::sync::oneshot::error::TryRecvError;

    /// The DIDComm message carrying `document`, with plaintext `from`.
    fn envelope(document: &TrustTask<Value>, from: Option<&str>) -> Message {
        let mut builder = Message::build(
            "urn:uuid:envelope".to_string(),
            ENVELOPE_TYPE.to_string(),
            serde_json::to_value(document).unwrap(),
        );
        if let Some(from) = from {
            builder = builder.from(from.to_string());
        }
        builder.finalize()
    }

    /// Metadata for an authcrypted envelope encrypted by `sender`'s key.
    fn authcrypt_by(sender: &str) -> UnpackMetadata {
        let mut meta = UnpackMetadata::default();
        meta.encrypted = true;
        meta.authenticated = true;
        meta.encrypted_from_kid = Some(format!("{sender}#key-2"));
        meta
    }

    /// Metadata for an anoncrypted envelope (no sender key).
    fn anoncrypt() -> UnpackMetadata {
        let mut meta = UnpackMetadata::default();
        meta.encrypted = true;
        meta.anonymous_sender = true;
        meta
    }

    #[test]
    fn a_reply_authcrypted_by_the_registry_completes_the_exchange() {
        let pending = PendingReplies::new();
        let mut rx = pending.register("req-1", REGISTRY);
        let outcome = route_envelope(
            &pending,
            envelope(&reply_to("req-1"), Some(REGISTRY)),
            &authcrypt_by(REGISTRY),
        );
        assert_eq!(outcome, RouteOutcome::Delivered);
        assert!(rx.try_recv().is_ok());
    }

    /// Another party that knows the request id and echoes the asked tuple,
    /// authcrypting with its own key, does not complete the exchange — not
    /// even when it writes the registry's DID in the plaintext `from`.
    #[test]
    fn a_correlated_reply_authcrypted_by_another_party_is_not_delivered() {
        let pending = PendingReplies::new();
        let mut rx = pending.register("req-1", REGISTRY);

        for from in [Some(OTHER), Some(REGISTRY), None] {
            let outcome = route_envelope(
                &pending,
                envelope(&reply_to("req-1"), from),
                &authcrypt_by(OTHER),
            );
            assert!(
                matches!(outcome, RouteOutcome::WrongSender { .. }),
                "from {from:?}: {outcome:?}"
            );
            assert!(matches!(rx.try_recv(), Err(TryRecvError::Empty)));
        }

        // The registry's reply still completes it.
        assert_eq!(
            route_envelope(
                &pending,
                envelope(&reply_to("req-1"), Some(REGISTRY)),
                &authcrypt_by(REGISTRY),
            ),
            RouteOutcome::Delivered
        );
        assert!(rx.try_recv().is_ok());
    }

    #[test]
    fn an_unauthenticated_reply_naming_the_registry_is_not_delivered() {
        let pending = PendingReplies::new();
        let mut rx = pending.register("req-1", REGISTRY);
        for meta in [anoncrypt(), UnpackMetadata::default()] {
            let outcome = route_envelope(
                &pending,
                envelope(&reply_to("req-1"), Some(REGISTRY)),
                &meta,
            );
            assert!(matches!(outcome, RouteOutcome::WrongSender { .. }));
        }
        assert!(matches!(rx.try_recv(), Err(TryRecvError::Empty)));
    }

    #[test]
    fn the_sender_is_the_owner_of_the_encrypting_key() {
        let msg = envelope(&reply_to("r"), Some(REGISTRY));
        assert_eq!(
            authenticated_sender(&msg, &authcrypt_by(REGISTRY)).as_deref(),
            Some(REGISTRY)
        );
        // `from` disagreeing with the key's owner authenticates no one.
        assert_eq!(authenticated_sender(&msg, &authcrypt_by(OTHER)), None);
        // A key id without a fragment names no key.
        let mut meta = authcrypt_by(REGISTRY);
        meta.encrypted_from_kid = Some(REGISTRY.to_string());
        assert_eq!(authenticated_sender(&msg, &meta), None);
    }

    #[test]
    fn other_message_types_are_left_alone() {
        let pending = PendingReplies::new();
        let mut rx = pending.register("req-1", REGISTRY);
        let mut msg = envelope(&reply_to("req-1"), Some(REGISTRY));
        msg.typ = "https://didcomm.org/trust-ping/2.0/ping".to_string();
        assert_eq!(
            route_envelope(&pending, msg, &authcrypt_by(REGISTRY)),
            RouteOutcome::Unsolicited
        );
        assert!(matches!(rx.try_recv(), Err(TryRecvError::Empty)));
    }
}
