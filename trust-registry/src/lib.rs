//! The Affinidi Trust Registry: a store of trust records that answers TRQP
//! queries.
//!
//! **TRQP** (the ToIP Trust Registry Query Protocol) asks whether an
//! *entity* is authorized, or recognized, by an *authority* for an *action*
//! on a *resource*. Each record here is one such 4-tuple with its
//! `authorized` / `recognized` flags and a validity window. Queries and record
//! management travel as **Trust Task** documents (`registry/authorization`,
//! `registry/recognition`, `registry/record/*`, …) over HTTPS
//! (`POST /trust-tasks`, read-only), DIDComm through a mediator, and, with the
//! `tsp` feature, TSP. The legacy REST TRQP endpoints (`/authorization`,
//! `/recognition`) are served as well.
//!
//! The client side is the separate `trql-client` crate (`trql` is only its
//! name; the protocol is TRQP).
//!
//! # Two ways to run it
//!
//! * **Standalone**: the `trust-registry` binary (`server::start`, under the
//!   `standalone` feature) reads its configuration from the environment and
//!   owns the process. See the repository README.
//! * **Embedded**: a host application builds a [`TrustRegistry`] with
//!   [`TrustRegistry::builder`], mounts [`TrustRegistry::router`] on its own
//!   axum server, and can feed Trust Tasks from its own transport through
//!   [`TrustRegistry::task_handler`] or a [`didcomm::listener::DidCommSource`].
//!   See [`embed`] for a worked example. A host should build this crate with
//!   `default-features = false` and enable only the storage backends it uses.
//!
//! # Map of the crate
//!
//! * [`trust_tasks`]: the Trust Task router and handlers, shared by every
//!   transport.
//! * [`http`], [`didcomm`] (and `tsp`, `messaging` with the `tsp` feature):
//!   the transport bindings.
//! * [`domain`]: the trust record model; [`storage`]: the repository trait and
//!   its backends.
//! * [`configs`]: configuration, from the environment or built in code.
//! * [`audit`], [`dedup`], [`health`], [`capabilities`], [`mediator_acl`]:
//!   the audit log, message-id deduplication, health reporting, runtime
//!   capability switches and the mediator access list.

use crate::storage::repository::TrustRecordRepository;
use std::{fmt, sync::Arc};

/// The error type the registry's fallible entry points return.
pub type BoxError = Box<dyn std::error::Error + Send + Sync>;

pub mod audit;
pub mod capabilities;
pub mod configs;
pub mod dedup;
pub mod didcomm;
pub mod domain;
pub mod embed;
pub mod health;
pub mod http;
pub mod mediator_acl;
pub mod server;
#[cfg(feature = "vta")]
pub mod setup;
pub mod storage;
/// The Trust Task specifications this crate speaks, generated at build time by
/// `trust-tasks-build` from the versions pinned in `trust-tasks.lock`, at the
/// module paths `crate::specs` used (`specs::registry::recognition::v0_2`).
#[allow(clippy::all, clippy::unwrap_used, clippy::expect_used, missing_docs)]
pub mod specs {
    include!(concat!(env!("OUT_DIR"), "/trust_tasks_generated.rs"));
}
pub mod trust_tasks;

pub use embed::{TrustRegistry, TrustRegistryBuilder};

#[cfg(feature = "tsp")]
pub mod messaging;
#[cfg(feature = "tsp")]
pub mod tsp;

/// State for the HTTP handlers, built by [`TrustRegistry`] and nowhere else.
pub(crate) struct SharedData<R>
where
    R: TrustRecordRepository + ?Sized,
{
    pub(crate) config: Arc<configs::TrustRegistryConfig>,
    pub(crate) repository: Arc<R>,
    /// The registry's one read-only Trust Task handler, shared with
    /// [`TrustRegistry::query_task_handler`], so its replay record and reply
    /// signer are built once rather than per request.
    pub(crate) query_tasks: trust_tasks::TaskHandler,
}

impl<R: TrustRecordRepository + ?Sized> fmt::Debug for SharedData<R> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SharedData")
            .field("config", &self.config)
            .finish_non_exhaustive()
    }
}

impl<R> Clone for SharedData<R>
where
    R: TrustRecordRepository + ?Sized,
{
    fn clone(&self) -> Self {
        Self {
            config: self.config.clone(),
            repository: Arc::clone(&self.repository),
            query_tasks: self.query_tasks.clone(),
        }
    }
}
