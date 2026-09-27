//! Trust Task support for the Trust Registry.
//!
//! Models every Trust Registry protocol operation as a versioned Trust Task
//! (the `registry/*` family) and routes them through a single transport-
//! agnostic [`router::RegistryDispatcher`]. This module is the shared core;
//! DIDComm, HTTP, and TSP bindings (added in later changes) all decode their
//! wire format into a `TrustTask<serde_json::Value>` and feed it here.
//!
//! See `docs/design/vta-tsp-didcomm-trust-tasks.md` for the design and the
//! mapping from the legacy `trqp/1.0` and `tr-admin/1.0` DIDComm protocols.

pub mod handler;
pub mod payloads;
pub mod proof;
pub mod reply;
pub mod router;
// Fixtures for the per-transport query tests. Only the TSP binding's tests
// consume these today, so this is gated on that feature to avoid dead code in
// builds without it.
#[cfg(all(test, feature = "tsp"))]
pub(crate) mod test_support;

pub use handler::TaskHandler;
pub use payloads::type_uris;
pub use proof::{build_verifier, verify_write_proof};
pub use reply::ReplySigner;
pub use router::{
    RegistryDispatcher, TaskFuture, TaskOutcome, build_dispatcher, build_query_dispatcher,
    handle_document,
};
