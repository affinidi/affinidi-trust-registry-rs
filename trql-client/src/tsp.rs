//! TSP binding: the `trust-tasks-tsp` envelope (`{type, document}`) sealed in
//! a TSP `Direct` message, multiplexed on the profile's mediator websocket —
//! the same wire the registry's `tsp` feature speaks. All TSP crypto and key
//! management is delegated to the SDK's `atm.tsp()` accessor; this module
//! never touches raw VID keys.
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
//! tradeoff: a reply lost between delete and handoff surfaces as a timeout,
//! and these are idempotent read queries the caller can retry.

use std::sync::Arc;
use std::time::Duration;

use affinidi_tdk::messaging::protocols::message_pickup::InboundFrame;
use affinidi_tdk::messaging::{ATM, profiles::ATMProfile};
use serde_json::Value;
use tracing::{debug, warn};
use trust_tasks_rs::TrustTask;
use trust_tasks_tsp::ENVELOPE_TYPE;

use crate::error::TrqlError;
use crate::pending::PendingReplies;
use crate::transport::{TransportKind, TrqlTransport};

/// How long each inbound pickup poll waits before looping.
const INBOUND_POLL_WAIT: Duration = Duration::from_secs(10);
/// Backoff after a transient inbound error so the demux loop doesn't spin.
const INBOUND_ERROR_BACKOFF: Duration = Duration::from_millis(500);

/// Configuration for [`TspTransport`].
#[derive(Debug, Clone)]
pub struct TspTransportConfig {
    /// How long to wait for the registry's reply before failing the exchange.
    pub reply_timeout: Duration,
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

impl Drop for TspTransport {
    fn drop(&mut self) {
        self.demux.abort();
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
        let request_id = request.id.clone();
        let envelope = build_envelope(&request)?;

        // Register the waiter before sending so a fast reply cannot be lost.
        let receiver = self.pending.register(&request_id);

        if let Err(e) = self.atm.tsp().send(&self.profile, &dest, &envelope).await {
            self.pending.abandon(&request_id);
            return Err(TrqlError::Transport {
                kind: TransportKind::Tsp,
                detail: format!("TSP send failed: {e}"),
            });
        }

        match tokio::time::timeout(self.reply_timeout, receiver).await {
            Ok(Ok(document)) => Ok(document),
            Ok(Err(_closed)) => {
                self.pending.abandon(&request_id);
                Err(TrqlError::Transport {
                    kind: TransportKind::Tsp,
                    detail: "reply demux task stopped".to_string(),
                })
            }
            Err(_elapsed) => {
                self.pending.abandon(&request_id);
                Err(TrqlError::Timeout {
                    kind: TransportKind::Tsp,
                    waited_secs: self.reply_timeout.as_secs(),
                })
            }
        }
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

/// The single owner of the profile's inbound pickup stream. Unseals TSP
/// frames via `atm.tsp()` and routes reply documents to waiters; survives
/// transient stream errors.
async fn demux_loop(atm: ATM, profile: Arc<ATMProfile>, pending: PendingReplies) {
    loop {
        match atm
            .message_pickup()
            .live_stream_next_frame(&profile, Some(INBOUND_POLL_WAIT), true)
            .await
        {
            Ok(Some(InboundFrame::Tsp(packed))) => {
                let (payload, sender) = match atm.tsp().unpack(&profile, &packed).await {
                    Ok(unsealed) => unsealed,
                    Err(e) => {
                        warn!("TSP unpack failed: {e}");
                        continue;
                    }
                };
                match parse_envelope(&payload) {
                    Ok(document) => {
                        if !pending.route(document) {
                            debug!("unsolicited TSP Trust Task from {sender} dropped");
                        }
                    }
                    Err(e) => warn!("dropping TSP message from {sender}: {e}"),
                }
            }
            // Other frame kinds (incl. DIDComm) are not this binding's; with a
            // dedicated profile there should be none.
            Ok(Some(_)) => {}
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

    #[test]
    fn wrong_envelope_type_is_rejected() {
        let bytes = serde_json::to_vec(
            &serde_json::json!({ "type": "https://example.org/other", "document": {} }),
        )
        .unwrap();
        assert!(parse_envelope(&bytes).is_err());
    }
}
