//! Trust Task support for the Trust Registry.
//!
//! Models every Trust Registry protocol operation as a versioned Trust Task
//! (the `registry/*` family) and routes them through a single transport-
//! agnostic [`router::RegistryDispatcher`]. This module is the shared core;
//! the DIDComm, HTTPS and TSP bindings all decode their wire format into a
//! `TrustTask<serde_json::Value>` and feed it here. Trust Tasks are the
//! registry's only remote API: there is no separate REST or DIDComm query
//! protocol beside them.

pub mod handler;
pub mod payloads;
pub mod proof;
pub mod reply;
pub mod router;
#[cfg(test)]
pub(crate) mod test_support;

pub use handler::TaskHandler;
pub use payloads::type_uris;
pub use proof::{build_verifier, verify_write_proof};
pub use reply::ReplySigner;
pub use router::{
    RegistryDispatcher, TaskFuture, TaskOutcome, build_dispatcher, build_query_dispatcher,
    handle_document,
};
