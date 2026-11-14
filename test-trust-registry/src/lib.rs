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
//! A REST-only registry also answers Trust Tasks on `POST /trust-tasks`
//! (read-only: queries, not record writes). Give it a DID with
//! [`TestTrustRegistryBuilder::did`] so a client such as `trql-client`, which
//! addresses every document to the registry's DID, can query it there.
//!
//! Record writes and the Trust Task protocols over DIDComm/TSP need a
//! mediator: with the `mediator` feature,
//! `TestTrustRegistryBuilder::spawn_with_mediator` wires the DIDComm (and,
//! with `tsp`, TSP) listeners against an `affinidi-messaging-test-mediator`.
//! `tests/mediator.rs` drives full routed round trips over both, by hand and
//! through `trql-client`'s `DidcommTransport` and `TspTransport`; see the
//! README for how to run them.

use std::net::SocketAddr;
use std::sync::Arc;

use tokio_util::sync::CancellationToken;
use trust_registry::configs::storage::StorageConfig;
use trust_registry::configs::{DidcommConfig, ServerConfig, TrustRegistryConfig};
use trust_registry::domain::TrustRecord;
use trust_registry::server::{ServerHandle, serve};
use trust_registry::storage::adapters::local_storage::LocalStorage;
use trust_registry::storage::repository::TrustRecordAdminRepository;

#[cfg(feature = "mediator")]
use affinidi_messaging_test_mediator::TestMediatorHandle;
#[cfg(feature = "mediator")]
use affinidi_tdk::messaging::protocols::mediator::acls::AccessListModeType;
#[cfg(feature = "mediator")]
use trust_registry::configs::{AdminConfig, ProfileConfig};

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
    did: Option<String>,
    #[cfg(feature = "mediator")]
    admin_dids: Vec<String>,
    #[cfg(feature = "tsp")]
    tsp: bool,
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

    /// The DID a REST-only registry ([`spawn`](Self::spawn)) answers as on
    /// `POST /trust-tasks`: a Trust Task document there must name it as its
    /// `recipient` (or name none). Without one the registry has no DID, and a
    /// document addressed to any DID is refused. Ignored by
    /// `spawn_with_mediator`, which mints the registry's DID on the mediator.
    pub fn did(mut self, did: impl Into<String>) -> Self {
        self.did = Some(did.into());
        self
    }

    /// DIDs authorised to send record-mutating (and DID-rotation) Trust Tasks.
    /// Only used by [`spawn_with_mediator`](Self::spawn_with_mediator); reads and
    /// TRQP queries need no authorisation.
    ///
    /// A listed DID may write only records under **its own** authority: a
    /// `registry/record/*` task must be issued (and its proof signed) by the
    /// admin DID, and every record it touches must have that DID as its
    /// `authority_id`. A write under another authority is refused with
    /// `permissionDenied`, admin or not.
    #[cfg(feature = "mediator")]
    pub fn admin_dids(mut self, admin_dids: Vec<String>) -> Self {
        self.admin_dids = admin_dids;
        self
    }

    /// Have [`spawn_with_mediator`](Self::spawn_with_mediator) answer Trust
    /// Tasks over TSP as well (the standalone service's `ENABLE_TSP=true`).
    /// Off by default: a `tsp` build alone ignores TSP frames.
    ///
    /// With it on, the registry drives its mediator socket through the
    /// delivery layer (which records TSP relationships) instead of the
    /// DIDComm pickup loop, and keeps its TSP relationships in a store in a
    /// temporary directory of this spawn's own. A client
    /// must form a TSP relationship with the registry before its first Trust
    /// Task (Spec Rev 3 §7.2.2), and client and registry share the test
    /// mediator, so it must allow direct delivery
    /// (`TestEnvironment::spawn_with_direct_delivery()`).
    #[cfg(feature = "tsp")]
    pub fn tsp(mut self, enabled: bool) -> Self {
        self.tsp = enabled;
        self
    }

    /// Bind an ephemeral port and start the server.
    ///
    /// The registry runs REST-only (DIDComm disabled) over an in-memory
    /// [`LocalStorage`]; storage config is irrelevant because the repository is
    /// injected directly.
    pub async fn spawn(self) -> Result<TestTrustRegistryHandle, BoxError> {
        let repository = Arc::new(LocalStorage::with_records(self.records)?);

        // REST-only. `disabled()` rather than `default()`: the derived
        // default leaves `transport_flags.didcomm` true while `is_enabled` is
        // false, so `/health` would advertise a transport nothing answers.
        let mut didcomm_config = DidcommConfig::disabled();
        // The DID `POST /trust-tasks` checks each document's `recipient`
        // against; nothing else uses it while DIDComm is off.
        if let Some(did) = &self.did {
            didcomm_config.profile_config.did = did.clone();
        }
        let config = Arc::new(TrustRegistryConfig {
            server_config: ServerConfig {
                listen_address: "127.0.0.1:0".to_string(),
                ..Default::default()
            },
            storage_config: StorageConfig::default(),
            didcomm_config,
        });

        let shutdown = CancellationToken::new();
        let admin_repository: Arc<dyn TrustRecordAdminRepository> = repository.clone();
        let handle = serve(config, admin_repository, shutdown).await?;
        let http_addr = handle
            .http_addr()
            .ok_or("the test registry serves REST, but no HTTP listener was bound")?;

        Ok(TestTrustRegistryHandle {
            handle,
            http_addr,
            repository,
            did: self.did,
            #[cfg(feature = "mediator")]
            _messaging_store: None,
        })
    }

    /// Bind an ephemeral HTTP port **and** connect the DIDComm (and, with the
    /// `tsp` feature and `tsp(true)`, TSP) Trust Task listeners
    /// to `mediator`.
    ///
    /// The Trust Registry's DIDComm/TSP identity is minted on the mediator via
    /// [`add_user`](affinidi_messaging_test_mediator::TestMediatorHandle::add_user):
    /// a `did:peer` whose service endpoint is the mediator DID, registered as a
    /// LOCAL `ALLOW_ALL` account. That DID (see
    /// [`TestTrustRegistryHandle::did`]) is where test clients address their
    /// Trust Task envelopes; the same `did:peer` doubles as the TR's TSP VID.
    ///
    /// Set [`admin_dids`](Self::admin_dids) to the client DID(s) that should be
    /// allowed to send record-mutating Trust Tasks (each under its own
    /// authority only).
    #[cfg(feature = "mediator")]
    pub async fn spawn_with_mediator(
        self,
        mediator: &TestMediatorHandle,
    ) -> Result<TestTrustRegistryHandle, BoxError> {
        let identity = mediator.add_user("trust-registry").await?;
        let did = identity.did.clone();

        let repository = Arc::new(LocalStorage::with_records(self.records)?);

        // With TSP on, the registry keeps its TSP relationships in a
        // messaging store. Each spawn gets its own, in a temporary directory
        // removed after `shutdown`, so registries in one test run never share
        // one and nothing is left in the working directory.
        let messaging_store = tempfile::TempDir::new()?;

        #[cfg_attr(not(feature = "tsp"), allow(unused_mut))]
        let mut didcomm_config = DidcommConfig {
            is_enabled: true,
            // Public mode: accept Trust Tasks from any client DID (the default
            // config mode is private/ExplicitAllow, which would deny test
            // clients). Writes are still gated by `admin_dids` + proof.
            acl_mode: AccessListModeType::ExplicitDeny,
            profile_config: ProfileConfig {
                did: did.clone(),
                alias: "Trust Registry".to_string(),
                secrets: identity.secrets,
            },
            mediator_did: mediator.did().to_string(),
            messaging_store_path: Some(messaging_store.path().to_path_buf()),
            admin_config: AdminConfig {
                admin_dids: self.admin_dids,
                ..Default::default()
            },
            ..Default::default()
        };
        // The standalone service's `ENABLE_TSP`: without it a `tsp` build
        // ignores TSP frames, so the feature alone starts nothing.
        #[cfg(feature = "tsp")]
        {
            didcomm_config.transport_flags.tsp = self.tsp;
        }

        let config = Arc::new(TrustRegistryConfig {
            server_config: ServerConfig {
                listen_address: "127.0.0.1:0".to_string(),
                ..Default::default()
            },
            storage_config: StorageConfig::default(),
            didcomm_config,
        });

        let shutdown = CancellationToken::new();
        let admin_repository: Arc<dyn TrustRecordAdminRepository> = repository.clone();
        let handle = serve(config, admin_repository, shutdown).await?;
        let http_addr = handle
            .http_addr()
            .ok_or("the test registry serves REST, but no HTTP listener was bound")?;

        Ok(TestTrustRegistryHandle {
            handle,
            http_addr,
            repository,
            did: Some(did),
            _messaging_store: Some(messaging_store),
        })
    }
}

/// A running embedded Trust Registry. Dropping it leaves the server running to
/// the end of the process; call [`shutdown`](Self::shutdown) to stop it early.
pub struct TestTrustRegistryHandle {
    handle: ServerHandle,
    http_addr: SocketAddr,
    repository: Arc<LocalStorage>,
    did: Option<String>,
    /// The registry's messaging store directory (mediator-wired spawns),
    /// removed when the handle goes away, after `shutdown` has stopped the
    /// server.
    #[cfg(feature = "mediator")]
    _messaging_store: Option<tempfile::TempDir>,
}

impl TestTrustRegistryHandle {
    /// The address the HTTP server bound to (with the OS-assigned port).
    pub fn http_addr(&self) -> SocketAddr {
        self.http_addr
    }

    /// The Trust Registry's DID — where clients address Trust Task documents.
    /// When spawned via `spawn_with_mediator`, the DIDComm/TSP DID minted on
    /// the mediator; for a REST-only registry, the DID given to
    /// [`did`](TestTrustRegistryBuilder::did), if any.
    pub fn did(&self) -> Option<&str> {
        self.did.as_deref()
    }

    /// `http://<addr>` base URL for the REST/TRQP surface.
    pub fn base_url(&self) -> String {
        format!("http://{}", self.http_addr)
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
