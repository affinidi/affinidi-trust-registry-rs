//! Trust Task support for the Trust Registry.
//!
//! Every Trust Registry protocol operation is a versioned Trust Task (the
//! `registry/*` family, plus the `governance/capability/*` surface and the
//! tasks of enabled capabilities). Every transport binding — DIDComm, TSP,
//! HTTP, or a host driving an embedded registry — decodes its wire format into
//! a `TrustTask<serde_json::Value>`, establishes which sender it
//! authenticated, and hands both to one [`TaskHandler`]. The handler applies
//! the checks every transport shares (party resolution, freshness, proofs, the
//! admin list, the authority binding, the replay record, the audit entry; see
//! [`handler`]) and routes the document to a [`RegistryDispatcher`]
//! ([`router`]). What each task needs of that pipeline is in one table,
//! [`descriptor`].

pub mod descriptor;
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
