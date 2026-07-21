//! Transport-agnostic query client for the Affinidi Trust Registry.
//!
//! Queries are TRQP authorization/recognition checks carried as **Trust Task
//! documents** (`registry/authorization/0.1`, `registry/recognition/0.1` from
//! [`trust_tasks_rs::specs::registry`]) — the same contract the registry
//! serves over every transport. The document is the protocol; a transport is
//! only a pipe that moves one request document and returns the peer's reply
//! document (see [`TrqlTransport`]).
//!
//! Three bindings are provided behind features:
//!
//! * `https` (default) — [`HttpsTransport`]: `POST <registry>/trust-tasks`,
//!   the `trust-tasks-https` wire contract.
//! * `didcomm` — [`DidcommTransport`]: the `trust-tasks-didcomm` envelope over
//!   an ATM mediator websocket.
//! * `tsp` — [`TspTransport`]: the `trust-tasks-tsp` envelope sealed in a TSP
//!   `Direct` message, multiplexed on the same mediator websocket.
//!
//! Every reply is correlated to its request (`threadId` == request `id`) and
//! a reply that cannot be parsed is surfaced as a contract error, never as a
//! transport failure. A registry rejection arrives as a typed
//! [`TrqlError::Rejected`] carrying the machine-readable trust-task-error
//! code.
//!
//! ```rust,ignore
//! use std::sync::Arc;
//! use trql_client::{HttpsTransport, HttpsTransportConfig, TrqlClient, TrqpQuery};
//!
//! let transport = HttpsTransport::new(HttpsTransportConfig::new("http://localhost:3232"))?;
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

pub use client::{TrqlClient, TrqpQuery};
pub use discovery::{
    DIDCOMM_SERVICE_TYPE, PREFERENCE_ORDER, REST_SERVICE_TYPE, REST_SERVICE_TYPES,
    ServiceCapabilities, TSP_SERVICE_TYPE, TransportChoice, VTA_REST_SERVICE_TYPE,
};
pub use error::TrqlError;
pub use transport::{TransportKind, TrqlTransport};

#[cfg(feature = "didcomm")]
pub use didcomm::{DidcommTransport, DidcommTransportConfig};
#[cfg(feature = "https")]
pub use https::{HttpsTransport, HttpsTransportConfig};
#[cfg(feature = "tsp")]
pub use tsp::{TspTransport, TspTransportConfig};

/// The generated request/response payload types this client speaks, re-exported
/// so consumers don't need a direct `trust-tasks-rs` dependency for the basics.
pub mod payloads {
    pub use trust_tasks_rs::specs::registry::authorization::v0_1::{
        Payload as AuthorizationRequest, QueryContext as AuthorizationQueryContext,
        Response as AuthorizationResponse,
    };
    pub use trust_tasks_rs::specs::registry::recognition::v0_1::{
        Payload as RecognitionRequest, QueryContext as RecognitionQueryContext,
        Response as RecognitionResponse,
    };
}
