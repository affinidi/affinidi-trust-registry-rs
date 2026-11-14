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
//! delivery enabled before the first exchange. **This transport owns the
//! profile's inbound DIDComm stream exclusively**: replies are picked from
//! it, a second consumer on the same stream would steal them, and every
//! message this transport cannot use is deleted (below). Give it a profile
//! of its own.
//!
//! ### Delivery semantics
//!
//! Every inbound message is deleted from the mediator once the demux task
//! has decided what to do with it:
//!
//! * a reply routed to its waiter is deleted only after the waiter holds it
//!   (ack after handoff);
//! * a reply that correlates to no in-flight query (a late answer to a query
//!   that timed out or was cancelled, or an unsolicited one) is deleted: it
//!   answers an idempotent read nobody is waiting for any more;
//! * a correlated reply from a party other than the one addressed is deleted:
//!   it can never complete the exchange, which goes on waiting for the
//!   registry's own reply;
//! * an envelope whose body is not a Trust Task document is poison (it will
//!   never parse) and is deleted;
//! * a message of any other DIDComm type is deleted: the profile belongs to
//!   this transport, so nothing else will ever consume it, and leaving it
//!   would grow the mediator queue without bound.
//!
//! None of these decisions depends on anything transient: the SDK has
//! already unpacked and authenticated the message (one that fails to unpack
//! surfaces as a stream error and is not deleted here), and the remaining
//! checks are pure functions of its content.
//!
//! ### Failure reporting
//!
//! Inbound-stream failures are retried with capped exponential backoff and
//! logged with escalation (the first failure at `warn`, then `error` once the
//! stream is declared unavailable). While it is unavailable, in-flight and
//! new exchanges fail at once with [`TrqlError::Transport`] naming the
//! stream's error instead of waiting out the reply window; see
//! [`DidcommTransport::inbound_error`]. If the demux task ever ends, every
//! exchange fails with "reply demux task stopped".
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
use crate::pending::{DEMUX_STOPPED, InboundMonitor, PendingReplies, RouteOutcome};
use crate::transport::{TransportKind, TrqlTransport};

/// How long each inbound pickup poll waits before looping.
const INBOUND_POLL_WAIT: Duration = Duration::from_secs(10);

/// Configuration for [`DidcommTransport`].
///
/// Build it with [`DidcommTransportConfig::new`] (or `default()`) and the
/// `with_*` setters, so options can be added without breaking callers.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct DidcommTransportConfig {
    /// How long to wait for the registry's reply before failing the exchange.
    pub reply_timeout: Duration,
}

impl DidcommTransportConfig {
    /// The defaults: a 60s reply window.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Wait up to `reply_timeout` for the registry's reply.
    #[must_use]
    pub fn with_reply_timeout(mut self, reply_timeout: Duration) -> Self {
        self.reply_timeout = reply_timeout;
        self
    }
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
        let monitor = InboundMonitor::new(pending.clone(), TransportKind::Didcomm);
        let demux = tokio::spawn(demux_loop(
            atm.clone(),
            profile.clone(),
            pending.clone(),
            monitor,
        ));
        Ok(Self {
            atm,
            profile,
            pending,
            reply_timeout: config.reply_timeout,
            demux,
        })
    }

    /// Why this transport cannot receive replies right now (its inbound
    /// stream has failed repeatedly, or its demux task has stopped), or
    /// `None` while it can. Exchanges fail fast with this reason meanwhile.
    pub fn inbound_error(&self) -> Option<String> {
        if self.demux.is_finished() {
            return Some(DEMUX_STOPPED.to_string());
        }
        self.pending.inbound_error()
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
        if self.demux.is_finished() {
            return Err(TrqlError::Transport {
                kind: TransportKind::Didcomm,
                detail: DEMUX_STOPPED.to_string(),
            });
        }
        let request_id = request.id.clone();
        let body = serde_json::to_value(&request)
            .map_err(|e| TrqlError::Contract(format!("request did not serialize: {e}")))?;

        // The waiter is registered before the send and removed however the
        // exchange ends, including by this future being dropped.
        self.pending
            .exchange(
                TransportKind::Didcomm,
                &request_id,
                &dest,
                self.reply_timeout,
                self.send_envelope(&dest, &request_id, body),
            )
            .await
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

/// What the demux task did with one inbound DIDComm message.
///
/// Every disposition ends with the message deleted from the mediator: the
/// transport owns the profile's stream exclusively (module docs), and each
/// case is decided from the message's own content, so none of them could
/// change on redelivery. [`Disposition::Delivered`] is deleted only after the
/// waiter holds the reply.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Disposition {
    /// Handed to the waiting exchange.
    Delivered,
    /// A Trust Task reply no exchange is waiting for: late (its query timed
    /// out or was cancelled) or unsolicited.
    Unrouted,
    /// A correlated reply not authcrypted by the party addressed.
    WrongSender,
    /// A Trust Task envelope whose body is not a Trust Task document.
    Malformed,
    /// A DIDComm message of another type.
    OtherType,
}

impl Disposition {
    /// Whether the demux task deletes the message from the mediator. True
    /// for every case; spelled out so the policy is stated and tested in one
    /// place, and a new case has to decide.
    fn deletes(self) -> bool {
        match self {
            Self::Delivered
            | Self::Unrouted
            | Self::WrongSender
            | Self::Malformed
            | Self::OtherType => true,
        }
    }
}

/// Route one unpacked DIDComm message to its waiter, bound to the sender
/// the envelope authenticated, and say what became of it.
fn route_envelope(
    pending: &PendingReplies,
    message: Message,
    meta: &UnpackMetadata,
) -> Disposition {
    if message.typ != ENVELOPE_TYPE {
        debug!(
            message_type = message.typ,
            "discarding a non-Trust-Task DIDComm message on the trql-client profile"
        );
        return Disposition::OtherType;
    }
    let sender = authenticated_sender(&message, meta);
    let document: TrustTask<Value> = match serde_json::from_value(message.body) {
        Ok(document) => document,
        Err(e) => {
            warn!(
                in_flight = pending.waiting(),
                "discarding a malformed Trust Task envelope (poison): {e}"
            );
            return Disposition::Malformed;
        }
    };
    match pending.route(document, sender.as_deref()) {
        RouteOutcome::Delivered => Disposition::Delivered,
        RouteOutcome::Unsolicited => {
            debug!("discarding a Trust Task reply no query is waiting for (late or unsolicited)");
            Disposition::Unrouted
        }
        RouteOutcome::WrongSender { expected } => {
            warn!(
                expected,
                sender = sender.as_deref().unwrap_or("<not authenticated>"),
                "discarding a Trust Task reply that was not authcrypted by the party the request was addressed to"
            );
            Disposition::WrongSender
        }
    }
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
/// envelope replies to waiters and deletes every message once it has been
/// dealt with; survives transient stream errors, reporting persistent ones
/// through `monitor` (whose `Drop` reports the task ending).
async fn demux_loop(
    atm: ATM,
    profile: Arc<ATMProfile>,
    pending: PendingReplies,
    mut monitor: InboundMonitor,
) {
    loop {
        match atm
            .message_pickup()
            // `auto_delete = false`: the delete below runs after routing, so
            // a routed reply is acked only once its waiter holds it.
            .live_stream_next(&profile, Some(INBOUND_POLL_WAIT), false)
            .await
        {
            Ok(Some((message, meta))) => {
                monitor.succeeded();
                // Deliberately deletes what cannot be used (late, foreign,
                // malformed or other-typed messages) as well as what was
                // delivered; see `Disposition`. None of those decisions is
                // transient, so nothing that could later succeed is
                // discarded (R1.6).
                let disposition = route_envelope(&pending, message, &meta);
                if disposition.deletes()
                    && let Err(e) = atm
                        .delete_message_background(&profile, &meta.sha256_hash)
                        .await
                {
                    debug!(?disposition, "mediator delete failed (will redeliver): {e}");
                }
            }
            Ok(None) => monitor.succeeded(),
            Err(e) => {
                let wait = monitor.failed(&e.to_string());
                tokio::time::sleep(wait).await;
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
    fn config_is_built_without_a_struct_literal() {
        let config = DidcommTransportConfig::new().with_reply_timeout(Duration::from_secs(5));
        assert_eq!(config.reply_timeout, Duration::from_secs(5));
        assert_eq!(
            DidcommTransportConfig::default().reply_timeout,
            Duration::from_secs(60)
        );
    }

    #[test]
    fn a_reply_authcrypted_by_the_registry_completes_the_exchange() {
        let pending = PendingReplies::new();
        let mut reg = pending.register("req-1", REGISTRY).unwrap();
        let outcome = route_envelope(
            &pending,
            envelope(&reply_to("req-1"), Some(REGISTRY)),
            &authcrypt_by(REGISTRY),
        );
        assert_eq!(outcome, Disposition::Delivered);
        assert!(outcome.deletes(), "a delivered reply is acked");
        assert!(reg.receiver().try_recv().unwrap().is_ok());
    }

    /// Another party that knows the request id and echoes the asked tuple,
    /// authcrypting with its own key, does not complete the exchange — not
    /// even when it writes the registry's DID in the plaintext `from`.
    #[test]
    fn a_correlated_reply_authcrypted_by_another_party_is_not_delivered() {
        let pending = PendingReplies::new();
        let mut reg = pending.register("req-1", REGISTRY).unwrap();

        for from in [Some(OTHER), Some(REGISTRY), None] {
            let outcome = route_envelope(
                &pending,
                envelope(&reply_to("req-1"), from),
                &authcrypt_by(OTHER),
            );
            assert_eq!(outcome, Disposition::WrongSender, "from {from:?}");
            assert!(matches!(
                reg.receiver().try_recv(),
                Err(TryRecvError::Empty)
            ));
        }

        // The registry's reply still completes it.
        assert_eq!(
            route_envelope(
                &pending,
                envelope(&reply_to("req-1"), Some(REGISTRY)),
                &authcrypt_by(REGISTRY),
            ),
            Disposition::Delivered
        );
        assert!(reg.receiver().try_recv().is_ok());
    }

    #[test]
    fn an_unauthenticated_reply_naming_the_registry_is_not_delivered() {
        let pending = PendingReplies::new();
        let mut reg = pending.register("req-1", REGISTRY).unwrap();
        for meta in [anoncrypt(), UnpackMetadata::default()] {
            let outcome = route_envelope(
                &pending,
                envelope(&reply_to("req-1"), Some(REGISTRY)),
                &meta,
            );
            assert_eq!(outcome, Disposition::WrongSender);
        }
        assert!(matches!(
            reg.receiver().try_recv(),
            Err(TryRecvError::Empty)
        ));
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

    // --- what the demux task deletes ---------------------------------------

    /// A reply that arrives after its query timed out or was cancelled finds
    /// no waiter, and is deleted rather than left queued for ever.
    #[test]
    fn a_late_reply_is_deleted() {
        let pending = PendingReplies::new();
        let reg = pending.register("req-1", REGISTRY).unwrap();
        drop(reg); // the query timed out or was cancelled
        let outcome = route_envelope(
            &pending,
            envelope(&reply_to("req-1"), Some(REGISTRY)),
            &authcrypt_by(REGISTRY),
        );
        assert_eq!(outcome, Disposition::Unrouted);
        assert!(outcome.deletes());
    }

    #[test]
    fn a_malformed_envelope_is_deleted_as_poison() {
        let pending = PendingReplies::new();
        let msg = Message::build(
            "urn:uuid:envelope".to_string(),
            ENVELOPE_TYPE.to_string(),
            serde_json::json!({ "not": "a trust task" }),
        )
        .finalize();
        let outcome = route_envelope(&pending, msg, &authcrypt_by(REGISTRY));
        assert_eq!(outcome, Disposition::Malformed);
        assert!(outcome.deletes());
    }

    #[test]
    fn a_reply_from_the_wrong_sender_is_deleted() {
        let pending = PendingReplies::new();
        let _reg = pending.register("req-1", REGISTRY).unwrap();
        let outcome = route_envelope(
            &pending,
            envelope(&reply_to("req-1"), Some(OTHER)),
            &authcrypt_by(OTHER),
        );
        assert_eq!(outcome, Disposition::WrongSender);
        assert!(outcome.deletes());
        assert_eq!(pending.waiting(), 1, "the waiter keeps waiting");
    }

    /// The profile belongs to this transport, so a message of another type
    /// is never routed and is deleted, not left to accumulate.
    #[test]
    fn other_message_types_are_not_routed_and_are_deleted() {
        let pending = PendingReplies::new();
        let mut reg = pending.register("req-1", REGISTRY).unwrap();
        let mut msg = envelope(&reply_to("req-1"), Some(REGISTRY));
        msg.typ = "https://didcomm.org/trust-ping/2.0/ping".to_string();
        let outcome = route_envelope(&pending, msg, &authcrypt_by(REGISTRY));
        assert_eq!(outcome, Disposition::OtherType);
        assert!(outcome.deletes());
        assert!(matches!(
            reg.receiver().try_recv(),
            Err(TryRecvError::Empty)
        ));
    }
}
