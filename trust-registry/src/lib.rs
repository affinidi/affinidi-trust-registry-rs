use crate::storage::repository::TrustRecordRepository;
use chrono::{DateTime, Utc};
use std::{fmt, sync::Arc};

pub mod audit;
pub mod capabilities;
pub mod configs;
pub mod dedup;
pub mod didcomm;
pub mod domain;
pub mod health;
pub mod http;
pub mod server;
pub mod storage;
pub mod trust_tasks;

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
        }
    }
}
