//! The client's error taxonomy.
//!
//! Variants separate the three failure classes an operator must be able to
//! tell apart: the transport failed (retry / check connectivity), the registry
//! rejected the task (act on the machine-readable code), or one side broke the
//! wire contract (a bug — never retried).

use chrono::{DateTime, Utc};
use trust_tasks_rs::TrustTaskCode;

use crate::transport::TransportKind;

/// Errors returned by [`crate::TrqlClient`] and [`crate::TrqlTransport`]
/// implementations.
#[derive(Debug, thiserror::Error)]
pub enum TrqlError {
    /// The client or transport was built with missing/invalid configuration.
    #[error("configuration error: {0}")]
    Config(String),

    /// The transport could not complete the exchange (connect, send, or
    /// receive failure). Retryable at the caller's discretion.
    #[error("{kind} transport error: {detail}")]
    Transport {
        /// Which binding failed.
        kind: TransportKind,
        /// What actually happened, named per failure (never a generic hint).
        detail: String,
    },

    /// No reply arrived within the transport's configured reply window.
    #[error("{kind} reply timed out after {waited_secs}s")]
    Timeout {
        /// Which binding timed out.
        kind: TransportKind,
        /// How long the transport waited.
        waited_secs: u64,
    },

    /// The registry answered with a `trust-task-error` document.
    #[error("registry rejected the task ({code}): {}", message.as_deref().unwrap_or("no detail"))]
    Rejected {
        /// Machine-readable trust-task error code.
        code: TrustTaskCode,
        /// Whether the registry marked the failure retryable.
        retryable: bool,
        /// Earliest retry instant, when the registry supplied one.
        retry_after: Option<DateTime<Utc>>,
        /// Human-readable detail from the registry, if any.
        message: Option<String>,
    },

    /// The peer's reply violated the Trust Task contract: it didn't parse,
    /// wasn't correlated to the request, or carried an unexpected type. This
    /// is a bug on one side of the wire, not a transient condition — it is
    /// never worth retrying.
    #[error("contract violation: {0}")]
    Contract(String),
}

impl TrqlError {
    /// Whether retrying the same query could plausibly succeed.
    ///
    /// Contract violations and configuration errors are never retryable; a
    /// registry rejection is retryable only when the registry said so.
    pub fn is_retryable(&self) -> bool {
        match self {
            Self::Transport { .. } | Self::Timeout { .. } => true,
            Self::Rejected { retryable, .. } => *retryable,
            Self::Config(_) | Self::Contract(_) => false,
        }
    }
}
