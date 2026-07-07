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

pub mod payloads;
pub mod router;

pub use payloads::type_uris;
pub use router::{
    RegistryDispatcher, TaskFuture, TaskOutcome, build_dispatcher, build_query_dispatcher,
    handle_document,
};
