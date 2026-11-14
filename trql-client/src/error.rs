//! The client's error taxonomy.
//!
//! Variants separate the failure classes an operator must be able to tell
//! apart: the client was misconfigured; the transport failed or timed out
//! (retry / check connectivity); the registry rejected the task (act on the
//! machine-readable code); one side broke the wire contract (a bug — never
//! retried); the registry answered a different question, or an answer did not
//! close the referral that led to it; or the two sides share no transport.
//! [`TrqlError::is_retryable`] sorts them. The enum is `#[non_exhaustive]`:
//! match the variants you act on and keep a catch-all arm.

use chrono::{DateTime, Utc};
use trust_tasks_rs::TrustTaskCode;

use crate::transport::TransportKind;

/// Errors returned by [`crate::TrqlClient`] and [`crate::TrqlTransport`]
/// implementations.
///
/// `#[non_exhaustive]`: new failure classes may be added in a minor release,
/// so a `match` outside this crate needs a wildcard arm. The variants can
/// still be built (a [`crate::TrqlTransport`] implementation returns them).
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
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
        /// How long the transport waited, in whole seconds rounded up (a
        /// sub-second window reads as 1, never 0).
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

    /// The reply is correlated to our request but answers a *different*
    /// question than the one we asked: another TRQP tuple, or another
    /// evaluation time.
    ///
    /// Correlation proves the reply belongs to our exchange; it says nothing
    /// about what the reply is an answer to. A registry that echoes a
    /// different `entity_id`/`authority_id`/`action`/`resource` has answered
    /// someone else's question, and treating it as ours silently substitutes
    /// the subject of an authorization decision. Likewise a query that asked
    /// for evaluation as of a given time ([`crate::TrqpQuery::at`]) must be
    /// answered for that time: a reply that omits the time, or echoes another
    /// one, may be a "now" answer to an "as of then" question.
    #[error("registry answered for a different {field}: asked `{asked}`, answered `{answered}`")]
    AnswerMismatch {
        /// Which member of the question disagreed, as the wire spells it
        /// (`entityId`, `authorityId`, `action`, `resource`, `asOf`; the 0.1
        /// spellings `entity_id`, `authority_id`, `time_requested`).
        field: &'static str,
        /// The value we sent on the request.
        asked: String,
        /// The value the registry echoed back (`<absent>` when it echoed
        /// none).
        answered: String,
    },

    /// We followed a referral to this registry, and its answer does not claim
    /// the authority that referred us.
    ///
    /// A `TrustRegistry` referral in a VTC's DID document is a
    /// self-assertion — anyone may publish a document naming any registry.
    /// Authority flows registry → subject, so a referral is only closed when
    /// the registry answers *for* the DID we started from. Until then the
    /// referral has established where to ask and nothing about the answer.
    #[error(
        "referral from `{origin}` not closed: registry answered for authority `{answered}`, \
         which does not confirm the referral"
    )]
    ReferralNotClosed {
        /// The DID whose document referred us here.
        origin: String,
        /// The authority the registry actually answered for.
        answered: String,
    },

    /// The registry advertises no transport this client also speaks.
    ///
    /// Carries both sides' sets so an operator can see what to enable rather
    /// than guess. Never a silent downgrade to a transport the registry did
    /// not advertise.
    #[error(
        "no shared transport with the registry (we speak [{}], it advertises [{}])",
        format_kinds(ours),
        format_kinds(theirs)
    )]
    NoMatchingTransport {
        /// Transports this client can use (compiled in and offered).
        ours: Vec<TransportKind>,
        /// Transports the registry advertises in its DID document.
        theirs: Vec<TransportKind>,
    },
}

/// `duration` in whole seconds, rounded up, for
/// [`TrqlError::Timeout::waited_secs`]: a 300 ms window reports 1, not 0.
#[cfg_attr(
    not(any(feature = "https", feature = "didcomm", feature = "tsp")),
    allow(dead_code)
)]
pub(crate) fn whole_secs_rounded_up(duration: std::time::Duration) -> u64 {
    duration.as_secs() + u64::from(duration.subsec_nanos() > 0)
}

/// Render a transport list for an error message; `"none"` when empty, so a
/// registry advertising nothing reads clearly rather than as `[]`.
fn format_kinds(kinds: &[TransportKind]) -> String {
    if kinds.is_empty() {
        return "none".to_string();
    }
    kinds
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join(", ")
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
            // A capability mismatch is a deployment fact, not a transient
            // condition: retrying the same pair of DID documents cannot help.
            // Nor can it help a registry that answers the wrong question or a
            // referral that does not close: both are stable facts about the
            // deployment, and retrying only re-asks a question already
            // answered wrongly.
            Self::Config(_)
            | Self::Contract(_)
            | Self::NoMatchingTransport { .. }
            | Self::AnswerMismatch { .. }
            | Self::ReferralNotClosed { .. } => false,
        }
    }
}
