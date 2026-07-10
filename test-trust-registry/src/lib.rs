//! Embedded Trust Registry fixture for integration tests.
//!
//! Mirrors `affinidi-messaging-test-mediator`'s `TestMediator::spawn()` model:
//! [`TestTrustRegistry::spawn`] boots an in-process Trust Registry on an
//! ephemeral `127.0.0.1:0` port over an in-memory store and hands back a
//! [`TestTrustRegistryHandle`] exposing the bound URL, the seed repository, and
//! a `shutdown()`. No environment variables, no external database, no ports to
//! reserve — a `#[tokio::test]` can stand one up, drive the REST/TRQP surface,
//! and tear it down.
//!
//! ```no_run
//! # async fn demo() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
//! use test_trust_registry::TestTrustRegistry;
//!
//! let tr = TestTrustRegistry::spawn().await?;
//! let recognition = format!("{}/recognition", tr.base_url());
//! // ... POST TRQP queries at `recognition` ...
//! tr.shutdown().await;
//! # Ok(())
//! # }
//! ```
//!
//! Record CRUD and the Trust Task protocols travel over DIDComm/TSP; a companion
//! `spawn_with_mediator(&TestMediatorHandle)` (added in a later change) wires
//! those transports against a spawned test mediator.

use std::net::SocketAddr;
use std::sync::Arc;

use tokio_util::sync::CancellationToken;
use trust_registry::configs::storage::StorageConfig;
use trust_registry::configs::{DidcommConfig, ServerConfig, TrustRegistryConfig};
use trust_registry::domain::TrustRecord;
use trust_registry::server::{ServerHandle, serve};
use trust_registry::storage::adapters::local_storage::LocalStorage;
use trust_registry::storage::repository::TrustRecordAdminRepository;

type BoxError = Box<dyn std::error::Error + Send + Sync>;

/// Entry point for spawning an embedded Trust Registry.
pub struct TestTrustRegistry;

impl TestTrustRegistry {
    /// Spawn an empty Trust Registry (no seed records) on an ephemeral port.
    pub async fn spawn() -> Result<TestTrustRegistryHandle, BoxError> {
        TestTrustRegistryBuilder::new().spawn().await
    }

    /// Spawn a Trust Registry pre-seeded with `records`.
    pub async fn with_records(
        records: Vec<TrustRecord>,
    ) -> Result<TestTrustRegistryHandle, BoxError> {
        TestTrustRegistryBuilder::new()
            .records(records)
            .spawn()
            .await
    }

    /// Start configuring a Trust Registry to spawn.
    pub fn builder() -> TestTrustRegistryBuilder {
        TestTrustRegistryBuilder::new()
    }
}

/// Fluent configuration for a [`TestTrustRegistry`].
#[derive(Default)]
pub struct TestTrustRegistryBuilder {
    records: Vec<TrustRecord>,
}

impl TestTrustRegistryBuilder {
    /// A builder with no seed records.
    pub fn new() -> Self {
        Self::default()
    }

    /// Replace the seed records.
    pub fn records(mut self, records: Vec<TrustRecord>) -> Self {
        self.records = records;
        self
    }

    /// Append a single seed record.
    pub fn record(mut self, record: TrustRecord) -> Self {
        self.records.push(record);
        self
    }

    /// Bind an ephemeral port and start the server.
    ///
    /// The registry runs REST-only (DIDComm disabled) over an in-memory
    /// [`LocalStorage`]; storage config is irrelevant because the repository is
    /// injected directly.
    pub async fn spawn(self) -> Result<TestTrustRegistryHandle, BoxError> {
        let repository = Arc::new(LocalStorage::with_records(self.records)?);

        let config = Arc::new(TrustRegistryConfig {
            server_config: ServerConfig {
                listen_address: "127.0.0.1:0".to_string(),
                cors_allowed_origins: Vec::new(),
            },
            storage_config: StorageConfig::default(),
            // is_enabled defaults to false -> REST-only.
            didcomm_config: DidcommConfig::default(),
        });

        let shutdown = CancellationToken::new();
        let admin_repository: Arc<dyn TrustRecordAdminRepository> = repository.clone();
        let handle = serve(config, admin_repository, shutdown).await?;

        Ok(TestTrustRegistryHandle { handle, repository })
    }
}

/// A running embedded Trust Registry. Dropping it leaves the server running to
/// the end of the process; call [`shutdown`](Self::shutdown) to stop it early.
pub struct TestTrustRegistryHandle {
    handle: ServerHandle,
    repository: Arc<LocalStorage>,
}

impl TestTrustRegistryHandle {
    /// The address the HTTP server bound to (with the OS-assigned port).
    pub fn http_addr(&self) -> SocketAddr {
        self.handle.http_addr()
    }

    /// `http://<addr>` base URL for the REST/TRQP surface.
    pub fn base_url(&self) -> String {
        self.handle.base_url()
    }

    /// The in-memory repository, so a test can seed further records or assert on
    /// state after spawn. It is the *same* store the server reads from.
    pub fn repository(&self) -> Arc<LocalStorage> {
        self.repository.clone()
    }

    /// Signal shutdown and await the server tasks.
    pub async fn shutdown(self) {
        self.handle.shutdown().await;
    }
}
