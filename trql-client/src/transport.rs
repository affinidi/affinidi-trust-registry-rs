//! The transport seam: one request document in, one reply document out.

use serde_json::Value;
use trust_tasks_rs::TrustTask;

use crate::error::TrqlError;

/// Which wire a [`TrqlTransport`] speaks.
///
/// Kept as an explicit tag (never inferred from endpoint shape — a TSP VID is
/// a DID too) so callers and logs can always name the protocol in use.
///
/// `#[non_exhaustive]`: a new binding may be added in a minor release, so a
/// `match` outside this crate needs a wildcard arm.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum TransportKind {
    /// `POST /trust-tasks` per the `trust-tasks-https` binding.
    Https,
    /// The `trust-tasks-didcomm` envelope over an ATM mediator.
    Didcomm,
    /// The `trust-tasks-tsp` envelope in a TSP `Direct` message.
    Tsp,
}

impl std::fmt::Display for TransportKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Https => write!(f, "https"),
            Self::Didcomm => write!(f, "didcomm"),
            Self::Tsp => write!(f, "tsp"),
        }
    }
}

/// A pipe that carries one Trust Task request and returns the peer's reply
/// document — either the `#response` success document or a `trust-task-error`
/// document. Interpretation of the reply (correlation, error mapping, payload
/// typing) belongs to [`crate::TrqlClient`], so bindings cannot diverge on
/// semantics.
///
/// Contract for implementations:
///
/// * The request's `recipient` is the destination party; transports that
///   route by DID read it from there.
/// * Only a reply from that party is returned. A transport that receives
///   replies on a shared inbound stream must check the sender it
///   authenticated against `recipient` and ignore a reply from anyone else;
///   the `threadId` is chosen by the sender and does not prove who answered.
/// * Every exchange has a finite wait: a peer that never answers is a
///   [`TrqlError::Timeout`], never a hang.
/// * A reply body that is not a Trust Task document is a
///   [`TrqlError::Contract`] (2xx / delivered) or [`TrqlError::Transport`]
///   (error status with a non-Trust-Task body) — never silently dropped.
/// * A transport whose wire carries its own success/failure signal (an HTTP
///   status) returns a document only when that signal agrees with it; see
///   `HttpsTransport`.
///
/// [`TrustTask`] is re-exported as [`crate::trust_tasks::TrustTask`], so an
/// implementation needs no direct `trust-tasks-rs` dependency.
#[async_trait::async_trait]
pub trait TrqlTransport: Send + Sync {
    /// The protocol this transport speaks.
    fn kind(&self) -> TransportKind;

    /// Send `request` to its `recipient` and return the peer's reply document.
    async fn exchange(&self, request: TrustTask<Value>) -> Result<TrustTask<Value>, TrqlError>;
}
