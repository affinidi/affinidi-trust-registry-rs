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
use chrono::{DateTime, Utc};
use std::{fmt, sync::Arc};

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

pub struct SharedData<R>
where
    R: TrustRecordRepository + ?Sized,
{
    pub config: Arc<configs::TrustRegistryConfig>,
    pub service_start_timestamp: DateTime<Utc>,
    pub repository: Arc<R>,
    /// Live read-only dispatcher (list + TRQP query tasks), owned by the
    /// CapabilitySet so capability enable/disable takes effect without a
    /// restart.
    pub query_dispatcher: capabilities::DispatcherHandle,
    /// Data-Integrity proof verifier, built once and shared with the DIDComm
    /// and TSP write paths. The HTTP surface is read-only and denies writes on
    /// the ACL before verification is reached, so it never exercises this —
    /// but it holds it so the surface stays correct if authenticated HTTP
    /// writes are ever wired up.
    pub verifier: Arc<dyn trust_tasks_rs::DynProofVerifier>,
    /// The registry's audit logger, shared with the DIDComm and TSP bindings,
    /// which records the write refusals this surface issues.
    pub audit: Arc<dyn audit::model::AuditLogger>,
}

impl<R: TrustRecordRepository> fmt::Debug for SharedData<R> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SharedData")
            .field("config", &self.config)
            .field("service_start_timestamp", &self.service_start_timestamp)
            .finish()
    }
}

impl<R> Clone for SharedData<R>
where
    R: TrustRecordRepository + ?Sized,
{
    fn clone(&self) -> Self {
        Self {
            config: self.config.clone(),
            service_start_timestamp: self.service_start_timestamp,
            repository: Arc::clone(&self.repository),
            query_dispatcher: self.query_dispatcher.clone(),
            verifier: self.verifier.clone(),
            audit: self.audit.clone(),
        }
    }
}
