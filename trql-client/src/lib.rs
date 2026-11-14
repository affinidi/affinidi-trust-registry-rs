//! Transport-agnostic query client for a Trust Registry.
//!
//! **TRQP** (the ToIP Trust Registry Query Protocol) is the protocol: "is
//! this entity authorized / recognized by this authority for this action on
//! this resource?". This crate carries TRQP queries as **Trust Task
//! documents** (`registry/authorization/0.2` and `registry/recognition/0.2`,
//! falling back to 0.1 for a registry that answers `unsupportedVersion`; see
//! [`TrqlClient::authorization`]), the same contract the Affinidi Trust
//! Registry serves over every transport. (`trql` is only part of this
//! crate's name, not another protocol or query language.) The document is the
//! protocol; a transport is only a pipe that moves one request document and
//! returns the peer's reply document (see [`TrqlTransport`]).
//!
//! Three bindings are provided behind features:
//!
//! * `https` (default) — `HttpsTransport`: `POST <registry>/trust-tasks`,
//!   the `trust-tasks-https` wire contract. It requires `https` (plain `http`
//!   only to a loopback host unless opted in), follows no redirects, caps
//!   the reply size and, unless opted out, connects only to public
//!   addresses; see `HttpsTransportConfig`.
//! * `didcomm` — `DidcommTransport`: the `trust-tasks-didcomm` envelope over
//!   an ATM mediator websocket.
//! * `tsp` — `TspTransport`: the `trust-tasks-tsp` envelope sealed in a TSP
//!   `Direct` message, multiplexed on the same mediator websocket.
//!
//! [`ServiceCapabilities`] picks among them from the registry's DID document,
//! and [`registry_referral`] follows a VTC's referral to its registry.
//!
//! # What is checked on every reply
//!
//! The client fails closed: an answer is returned only when all of these
//! hold, and anything else is an error, never a `false` or a `true`.
//!
//! * **Correlation.** The reply's `threadId` is the request's `id`.
//! * **Sender.** The reply comes from the registry the request was addressed
//!   to. Over HTTPS that is the server of the TLS connection the request went
//!   out on; over DIDComm the reply must be authcrypted by a key of the
//!   registry DID; over TSP its verified sender VID must be the registry's. A
//!   correlated reply from any other party does not complete the query, which
//!   goes on waiting for the registry's answer (and times out if none comes).
//! * **Transport signal.** Over HTTPS an error status never carries an
//!   answer: a non-2xx reply must be a `trust-task-error` document.
//! * **Type.** The reply is the matching `#response` document, or a
//!   `trust-task-error` document, which becomes [`TrqlError::Rejected`]
//!   carrying the machine-readable code.
//! * **The question.** The answer echoes the tuple that was asked
//!   (entity, authority, action, resource) and, when the query asked for an
//!   evaluation time ([`TrqpQuery::at`]), that same time; otherwise it is a
//!   [`TrqlError::AnswerMismatch`].
//! * **The referral.** A client built with [`TrqlClient::referred_by`] accepts
//!   only an answer for the authority that referred it
//!   ([`TrqlError::ReferralNotClosed`]).
//! * **Shape.** The payload parses as the spec's response type; a reply that
//!   does not is a [`TrqlError::Contract`] error, never a transport failure.
//!
//! # Example
//!
//! ```no_run
//! # #[cfg(feature = "https")]
//! # async fn demo() -> Result<(), trql_client::TrqlError> {
//! use std::sync::Arc;
//! use trql_client::{HttpsTransport, HttpsTransportConfig, TrqlClient, TrqpQuery};
//!
//! let transport = HttpsTransport::new(HttpsTransportConfig::new("https://registry.example.com"))?;
//! let client = TrqlClient::new(Arc::new(transport), "did:webvh:...registry");
//!
//! let answer = client
//!     .authorization(TrqpQuery::new(
//!         "did:webvh:...signer",     // entity
//!         "did:webvh:...authority",  // authority
//!         "git.commit.sign",         // action
//!         "openvtc",                 // resource
//!     ))
//!     .await?;
//! if answer.authorized { /* ... */ }
//! # Ok(())
//! # }
//! ```

// The client still speaks `registry/authorization` and `registry/recognition`
// 0.1, now superseded by 0.2, as the fallback for registries that predate 0.2.
#![allow(deprecated)]

mod answer;
mod client;
mod discovery;
mod error;
mod transport;

#[cfg(feature = "didcomm")]
mod didcomm;
#[cfg(feature = "https")]
mod https;
#[cfg(any(feature = "didcomm", feature = "tsp"))]
mod pending;
#[cfg(feature = "tsp")]
mod tsp;

pub use answer::{AuthorizationAnswer, RecognitionAnswer, SpecVersion};
pub use client::{TrqlClient, TrqpQuery};
pub use discovery::{
    DIDCOMM_SERVICE_TYPE, PREFERENCE_ORDER, REST_SERVICE_TYPE, REST_SERVICE_TYPES,
    ServiceCapabilities, TRUST_REGISTRY_SERVICE_TYPE, TSP_SERVICE_TYPE, TransportChoice,
    VTA_REST_SERVICE_TYPE, registry_referral,
};
pub use error::TrqlError;
pub use transport::{TransportKind, TrqlTransport};

#[cfg(feature = "didcomm")]
pub use didcomm::{DidcommTransport, DidcommTransportConfig};
#[cfg(feature = "https")]
pub use https::{
    DEFAULT_MAX_RESPONSE_BYTES, HttpsTransport, HttpsTransportConfig, MAX_ERROR_DETAIL_CHARS,
};
#[cfg(feature = "tsp")]
pub use tsp::{TspTransport, TspTransportConfig};

/// The `trust-tasks-rs` types that appear in this crate's API, re-exported so
/// callers can match a rejection code ([`TrqlError::Rejected`]) or implement
/// [`TrqlTransport`] without depending on `trust-tasks-rs` at exactly the
/// version this crate was built against.
pub mod trust_tasks {
    pub use trust_tasks_rs::{StandardCode, TrustTask, TrustTaskCode};
}

/// The Trust Task specifications this crate speaks, generated at build time by
/// `trust-tasks-build` from the versions pinned in `trust-tasks.lock`.
///
/// Crate-private: regenerating it with a newer `trust-tasks-build` must not
/// change this crate's public API. [`payloads`] re-exports the request and
/// response types callers may want.
#[allow(
    clippy::all,
    clippy::unwrap_used,
    clippy::expect_used,
    missing_docs,
    dead_code,
    unreachable_pub
)]
pub(crate) mod specs {
    include!(concat!(env!("OUT_DIR"), "/trust_tasks_generated.rs"));
}

/// The generated request/response payload types this client speaks, per spec
/// version, re-exported so consumers don't need a direct `trust-tasks-rs`
/// dependency to inspect them. [`TrqlClient`] answers with
/// [`AuthorizationAnswer`] / [`RecognitionAnswer`], not these.
pub mod payloads {
    /// `registry/authorization/0.2` and `registry/recognition/0.2`.
    pub mod v0_2 {
        pub use crate::specs::registry::authorization::v0_2::{
            Payload as AuthorizationRequest, QueryContext as AuthorizationQueryContext,
            Response as AuthorizationResponse,
        };
        pub use crate::specs::registry::recognition::v0_2::{
            Payload as RecognitionRequest, QueryContext as RecognitionQueryContext,
            Response as RecognitionResponse,
        };
    }
    /// `registry/authorization/0.1` and `registry/recognition/0.1`, the
    /// fallback for registries that predate 0.2.
    pub mod v0_1 {
        pub use crate::specs::registry::authorization::v0_1::{
            Payload as AuthorizationRequest, QueryContext as AuthorizationQueryContext,
            Response as AuthorizationResponse,
        };
        pub use crate::specs::registry::recognition::v0_1::{
            Payload as RecognitionRequest, QueryContext as RecognitionQueryContext,
            Response as RecognitionResponse,
        };
    }
}
