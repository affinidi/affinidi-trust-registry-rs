//! TSP binding: the `trust-tasks-tsp` envelope (`{type, document}`) sealed in
//! a TSP `Direct` message, multiplexed on the profile's mediator websocket —
//! the same wire the registry's `tsp` feature speaks. All TSP crypto and key
//! management is delegated to the SDK's `atm.tsp()` accessor; this module
//! never touches raw VID keys.
//!
//! ### Sender binding
//!
//! A reply completes an exchange only if the sender VID that TSP verified
//! when unsealing it is the VID the request was sent to (the document's
//! `recipient`). A reply from any other VID is dropped and the exchange keeps
//! waiting for the registry's own reply.
//!
//! ### Profile requirements
//!
//! The [`ATMProfile`] must have a mediator configured and websocket live
//! delivery enabled. This transport **must own its profile exclusively**: TSP
//! and DIDComm frames share one pickup socket, and the demux here consumes
//! frames with `auto_delete` — a co-resident consumer's messages would be
//! destroyed (and its DIDComm frames are discarded by this loop).
//!
//! ### Delivery semantics
//!
//! Frames are deleted from the mediator on receipt (`auto_delete = true`,
//! matching the registry's own live path): a TSP frame carries no ack handle,
//! so ack-after-handoff is not expressible on this wire yet. The deliberate
//! tradeoff: a reply lost between delete and handoff — including one whose
//! unsealing fails — surfaces as a timeout, and these are idempotent read
//! queries the caller can retry. Such a loss is logged at `warn` as a lost
//! reply.
//!
//! ### Failure reporting
//!
//! As for the DIDComm binding: poll failures are retried with capped
//! exponential backoff and escalating logs, the profile's websocket
//! connection state is followed too, and once either has been failing for 10
//! seconds without a break (or the demux task has stopped) exchanges fail at
//! once with [`TrqlError::Transport`]; see [`TspTransport::inbound_error`].

use std::sync::Arc;
use std::time::Duration;

use affinidi_tdk::messaging::protocols::message_pickup::InboundFrame;
use affinidi_tdk::messaging::{ATM, profiles::ATMProfile};
use serde_json::Value;
use tracing::{debug, warn};
use trust_tasks_rs::TrustTask;
use trust_tasks_tsp::ENVELOPE_TYPE;

use crate::error::TrqlError;
use crate::pending::{
    DEMUX_STOPPED, InboundMonitor, PendingReplies, RouteOutcome, watch_connection,
};
use crate::transport::{TransportKind, TrqlTransport};

/// How long each inbound pickup poll waits before looping.
const INBOUND_POLL_WAIT: Duration = Duration::from_secs(10);

/// Configuration for [`TspTransport`].
///
/// Build it with [`TspTransportConfig::new`] (or `default()`) and the
/// `with_*` setters, so options can be added without breaking callers.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct TspTransportConfig {
    /// How long to wait for the registry's reply before failing the exchange.
    pub reply_timeout: Duration,
}

impl TspTransportConfig {
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

impl Default for TspTransportConfig {
    /// 60s, aligned with the DIDComm reply default.
    fn default() -> Self {
        Self {
            reply_timeout: Duration::from_secs(60),
        }
    }
}

/// [`TrqlTransport`] over the `trust-tasks-tsp` binding.
pub struct TspTransport {
    atm: ATM,
    profile: Arc<ATMProfile>,
    pending: PendingReplies,
    reply_timeout: Duration,
    demux: tokio::task::JoinHandle<()>,
    /// Follows the profile's websocket connection state for the health check.
    watcher: tokio::task::JoinHandle<()>,
}

impl TspTransport {
    /// Bind the transport to `profile` and start its reply-demux task.
    ///
    /// Fails if the profile has no mediator. A TSP relationship with the
    /// registry must already be established on this profile (the SDK's
    /// `atm.tsp()` key material).
    pub fn new(
        atm: ATM,
        profile: Arc<ATMProfile>,
        config: TspTransportConfig,
    ) -> Result<Self, TrqlError> {
        if profile.to_tdk_profile().mediator.is_none() {
            return Err(TrqlError::Config(
                "profile has no mediator configured (required for the TSP binding)".to_string(),
            ));
        }
        let pending = PendingReplies::new();
        let monitor = InboundMonitor::new(pending.clone(), TransportKind::Tsp);
        let demux = tokio::spawn(demux_loop(
            atm.clone(),
            profile.clone(),
            pending.clone(),
            monitor,
        ));
        let watcher = tokio::spawn(watch_connection(
            profile.clone(),
            pending.clone(),
            TransportKind::Tsp,
        ));
        Ok(Self {
            atm,
            profile,
            pending,
            reply_timeout: config.reply_timeout,
            demux,
            watcher,
        })
    }

    /// Why this transport cannot receive replies right now (its polls have
    /// failed, or its mediator websocket has been disconnected, for longer
    /// than the health threshold; or its demux task has stopped), or `None`
    /// while it can. Exchanges fail fast with this reason meanwhile.
    pub fn inbound_error(&self) -> Option<String> {
        if self.demux.is_finished() {
            return Some(DEMUX_STOPPED.to_string());
        }
        self.pending.inbound_error()
    }
}

impl Drop for TspTransport {
    fn drop(&mut self) {
        self.demux.abort();
        self.watcher.abort();
    }
}

#[async_trait::async_trait]
impl TrqlTransport for TspTransport {
    fn kind(&self) -> TransportKind {
        TransportKind::Tsp
    }

    async fn exchange(&self, request: TrustTask<Value>) -> Result<TrustTask<Value>, TrqlError> {
        let dest = request.recipient.clone().ok_or_else(|| {
            TrqlError::Config("request document has no recipient to route to".to_string())
        })?;
        if self.demux.is_finished() {
            return Err(TrqlError::Transport {
                kind: TransportKind::Tsp,
                detail: DEMUX_STOPPED.to_string(),
            });
        }
        let request_id = request.id.clone();
        let envelope = build_envelope(&request)?;

        let send = async {
            self.atm
                .tsp()
                .send(&self.profile, &dest, &envelope)
                .await
                .map(|_| ())
                .map_err(|e| TrqlError::Transport {
                    kind: TransportKind::Tsp,
                    detail: format!("TSP send failed: {e}"),
                })
        };
        // The waiter is registered before the send and removed however the
        // exchange ends, including by this future being dropped.
        self.pending
            .exchange(
                TransportKind::Tsp,
                &request_id,
                &dest,
                self.reply_timeout,
                send,
            )
            .await
    }
}

/// Frame a document in the `trust-tasks-tsp` binding envelope.
fn build_envelope(document: &TrustTask<Value>) -> Result<Vec<u8>, TrqlError> {
    let document = serde_json::to_value(document)
        .map_err(|e| TrqlError::Contract(format!("request did not serialize: {e}")))?;
    let envelope = serde_json::json!({ "type": ENVELOPE_TYPE, "document": document });
    serde_json::to_vec(&envelope)
        .map_err(|e| TrqlError::Contract(format!("envelope did not serialize: {e}")))
}

/// Parse a `trust-tasks-tsp` binding envelope into a document. Rejects a wrong
/// or missing envelope type.
fn parse_envelope(payload: &[u8]) -> Result<TrustTask<Value>, String> {
    let envelope: Value =
        serde_json::from_slice(payload).map_err(|e| format!("invalid TSP envelope JSON: {e}"))?;
    match envelope.get("type").and_then(Value::as_str) {
        Some(t) if t == ENVELOPE_TYPE => {}
        other => return Err(format!("unexpected TSP envelope type: {other:?}")),
    }
    let document = envelope
        .get("document")
        .cloned()
        .ok_or_else(|| "TSP envelope missing `document`".to_string())?;
    serde_json::from_value(document).map_err(|e| format!("invalid Trust Task document: {e}"))
}

/// Route one unsealed TSP payload to its waiter, bound to `sender`, the VID
/// TSP verified as the message's sender.
fn route_payload(pending: &PendingReplies, payload: &[u8], sender: &str) -> RouteOutcome {
    match parse_envelope(payload) {
        Ok(document) => {
            let outcome = pending.route(document, Some(sender));
            match &outcome {
                RouteOutcome::Delivered => {}
                RouteOutcome::Unsolicited => {
                    debug!(
                        "discarding a TSP Trust Task from {sender} no query is waiting for (late or unsolicited)"
                    );
                }
                RouteOutcome::WrongSender { expected } => warn!(
                    expected,
                    sender,
                    "discarding a TSP Trust Task reply from a VID other than the one addressed"
                ),
            }
            outcome
        }
        Err(e) => {
            warn!("discarding a TSP message from {sender} (poison): {e}");
            RouteOutcome::Unsolicited
        }
    }
}

/// The single owner of the profile's inbound pickup stream. Unseals TSP
/// frames via `atm.tsp()` and routes reply documents to waiters; survives
/// transient stream errors, reporting persistent ones through `monitor`
/// (whose `Drop` reports the task ending).
async fn demux_loop(
    atm: ATM,
    profile: Arc<ATMProfile>,
    pending: PendingReplies,
    mut monitor: InboundMonitor,
) {
    loop {
        match atm
            .message_pickup()
            // `auto_delete = true`: deliberate, see the module docs. A TSP
            // frame has no ack handle to defer.
            .live_stream_next_frame(&profile, Some(INBOUND_POLL_WAIT), true)
            .await
        {
            Ok(Some(InboundFrame::Tsp(packed))) => {
                monitor.succeeded();
                let (payload, sender) = match atm.tsp().unpack(&profile, &packed).await {
                    Ok(unsealed) => unsealed,
                    Err(e) => {
                        // The frame is already deleted, so if it was a reply
                        // its query will time out: say so here, where the
                        // cause is known.
                        warn!(
                            in_flight = pending.waiting(),
                            "TSP unpack failed; the frame was already deleted from the mediator, \
                             so a registry reply it carried is lost and its query will time out: {e}"
                        );
                        continue;
                    }
                };
                route_payload(&pending, &payload, &sender);
            }
            // Other frame kinds (incl. DIDComm) are not this binding's; with a
            // dedicated profile there should be none. Already deleted.
            Ok(Some(_)) | Ok(None) => monitor.succeeded(),
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

    #[test]
    fn config_is_built_without_a_struct_literal() {
        let config = TspTransportConfig::new().with_reply_timeout(Duration::from_secs(5));
        assert_eq!(config.reply_timeout, Duration::from_secs(5));
        assert_eq!(
            TspTransportConfig::default().reply_timeout,
            Duration::from_secs(60)
        );
    }

    #[test]
    fn envelope_round_trips() {
        let doc = TrustTask::new(
            "urn:uuid:1".to_string(),
            "https://trusttasks.org/spec/registry/authorization/0.1"
                .parse()
                .unwrap(),
            serde_json::json!({"entity_id": "did:example:e"}),
        );
        let bytes = build_envelope(&doc).unwrap();
        let parsed = parse_envelope(&bytes).unwrap();
        assert_eq!(parsed.id, "urn:uuid:1");
        assert_eq!(parsed.payload["entity_id"], "did:example:e");
    }

    /// Another VID that knows the request id and echoes the asked tuple does
    /// not complete the exchange; the registry's reply still does.
    #[test]
    fn a_correlated_reply_from_another_vid_is_not_delivered() {
        let pending = PendingReplies::new();
        let mut reg = pending.register("req-1", REGISTRY).unwrap();
        let payload = build_envelope(&reply_to("req-1")).unwrap();

        assert!(matches!(
            route_payload(&pending, &payload, OTHER),
            RouteOutcome::WrongSender { .. }
        ));
        assert!(matches!(
            reg.receiver().try_recv(),
            Err(TryRecvError::Empty)
        ));

        assert_eq!(
            route_payload(&pending, &payload, REGISTRY),
            RouteOutcome::Delivered
        );
        assert!(reg.receiver().try_recv().is_ok());
    }

    #[test]
    fn a_late_reply_is_unsolicited() {
        let pending = PendingReplies::new();
        drop(pending.register("req-1", REGISTRY).unwrap());
        let payload = build_envelope(&reply_to("req-1")).unwrap();
        assert_eq!(
            route_payload(&pending, &payload, REGISTRY),
            RouteOutcome::Unsolicited
        );
    }

    #[test]
    fn wrong_envelope_type_is_rejected() {
        let bytes = serde_json::to_vec(
            &serde_json::json!({ "type": "https://example.org/other", "document": {} }),
        )
        .unwrap();
        assert!(parse_envelope(&bytes).is_err());
    }
}
