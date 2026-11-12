//! Transport-agnostic query client for the Affinidi Trust Registry.
//!
//! Queries are TRQP authorization/recognition checks carried as **Trust Task
//! documents** (`registry/authorization/0.2` and `registry/recognition/0.2`,
//! falling back to 0.1 for a registry that answers `unsupportedVersion`; see
//! [`TrqlClient::authorization`]) — the same contract the registry
//! serves over every transport. The document is the protocol; a transport is
//! only a pipe that moves one request document and returns the peer's reply
//! document (see [`TrqlTransport`]).
//!
//! Three bindings are provided behind features:
//!
//! * `https` (default) — [`HttpsTransport`]: `POST <registry>/trust-tasks`,
//!   the `trust-tasks-https` wire contract. It requires `https` (plain `http`
//!   only to a loopback host unless opted in), follows no redirects, caps
//!   the reply size and, unless opted out, connects only to public
//!   addresses; see [`HttpsTransportConfig`].
//! * `didcomm` — [`DidcommTransport`]: the `trust-tasks-didcomm` envelope over
//!   an ATM mediator websocket.
//! * `tsp` — [`TspTransport`]: the `trust-tasks-tsp` envelope sealed in a TSP
//!   `Direct` message, multiplexed on the same mediator websocket.
//!
//! Every reply is correlated to its request (`threadId` == request `id`),
//! must echo the tuple that was asked, and must come from the registry the
//! request was addressed to. Over HTTPS that is the server of the TLS
//! connection the request went out on; over DIDComm the reply must be
//! authcrypted by a key of the registry DID, and over TSP its verified sender
//! VID must be the registry's. A correlated reply from any other party does
//! not complete the query, which goes on waiting for the registry's answer
//! (and times out if none comes). A reply that cannot be parsed is surfaced
//! as a contract error, never as a transport failure. A registry rejection arrives as a typed
//! [`TrqlError::Rejected`] carrying the machine-readable trust-task-error
//! code.
//!
//! ```rust,ignore
//! use std::sync::Arc;
//! use trql_client::{HttpsTransport, HttpsTransportConfig, TrqlClient, TrqpQuery};
//!
//! let transport = HttpsTransport::new(HttpsTransportConfig::new("https://registry.example.com"))?;
//! let client = TrqlClient::new(Arc::new(transport), "did:webvh:...registry");
//!
//! let response = client
//!     .authorization(TrqpQuery::new(
//!         "did:webvh:...signer",     // entity
//!         "did:webvh:...authority",  // authority
//!         "git.commit.sign",         // action
//!         "openvtc",                 // resource
//!     ))
//!     .await?;
//! if response.authorized { /* ... */ }
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

/// The generated request/response payload types this client speaks, per spec
/// version, re-exported so consumers don't need a direct `trust-tasks-rs`
/// dependency to inspect them. [`TrqlClient`] answers with
/// [`AuthorizationAnswer`] / [`RecognitionAnswer`], not these.
/// The Trust Task specifications this crate speaks, generated at build time by
/// `trust-tasks-build` from the versions pinned in `trust-tasks.lock`, at the
/// module paths `crate::specs` used (`specs::registry::recognition::v0_2`).
#[allow(clippy::all, clippy::unwrap_used, clippy::expect_used, missing_docs)]
pub mod specs {
    include!(concat!(env!("OUT_DIR"), "/trust_tasks_generated.rs"));
}

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
