//! Embedding the Trust Registry in a host application.
//!
//! The registry runs two ways from the same code:
//!
//! - **Standalone** — it owns the process. `server::start()` reads the
//!   environment, binds a socket and never returns.
//! - **Embedded** — a host application owns the process, and the registry is a
//!   component inside it: routes mounted on the host's existing axum server,
//!   records in a repository the host chose, and Trust Tasks fed in from a
//!   transport the host already speaks.
//!
//! [`TrustRegistry`] is the embedded form. Build one with
//! [`TrustRegistry::builder`], injecting whatever the host already has; leave
//! the rest and it defaults to what the standalone service uses.
//!
//! ```no_run
//! # use std::sync::Arc;
//! # use trust_registry::{TrustRegistry, configs::TrustRegistryConfig};
//! # use trust_registry::storage::adapters::local_storage::LocalStorage;
//! # use trust_registry::storage::repository::TrustRecordAdminRepository;
//! # async fn example(host_app: axum::Router) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
//! let repository: Arc<dyn TrustRecordAdminRepository> = Arc::new(LocalStorage::new());
//!
//! let registry = TrustRegistry::builder(TrustRegistryConfig::embedded("/srv/app/registry"))
//!     .repository(repository)
//!     .build()
//!     .await?;
//!
//! // Mount into the host's own router — no CORS layer, no `/health`, both of
//! // which belong to the host.
//! let app = host_app.nest("/registry", registry.router());
//! # Ok(())
//! # }
//! ```
//!
//! A host that owns its own transport skips the router entirely and calls
//! [`TrustRegistry::task_handler`], feeding decoded documents straight in:
//!
//! ```no_run
//! # use trust_registry::TrustRegistry;
//! # use trust_tasks_rs::TrustTask;
//! # async fn example(registry: &TrustRegistry, doc: TrustTask<serde_json::Value>, sender: &str) {
//! let outcome = registry.task_handler().handle(doc, Some(sender)).await;
//! # }
//! ```
//!
//! ## What the registry never does to its host
//!
//! Nothing here touches process-global state. It does not read the environment
//! (see [`crate::configs`]), install a tracing subscriber, load a `.env` file,
//! or call `std::process::exit`. Only [`TrustRegistry::serve`] binds a socket,
//! and only when the host asks for it.

use std::sync::Arc;

use chrono::{DateTime, Utc};
use tokio_util::sync::CancellationToken;
use tracing::warn;

use crate::capabilities::{
    CapabilityDefinition, CapabilitySet, CapabilityStateStore, DispatcherHandle,
    FileCapabilityStore,
};
use crate::configs::TrustRegistryConfig;
use crate::dedup::{MemoryMessageIdStore, MessageIdStore};
use crate::didcomm::listener::DidCommSource;
use crate::health::RegistryHealth;
use crate::http::application_routes;
use crate::storage::repository::{TrustRecordAdminRepository, TrustRecordRepository};
use crate::trust_tasks::TaskHandler;
use crate::{SharedData, server::ServerHandle};

type BoxError = Box<dyn std::error::Error + Send + Sync>;

/// A Trust Registry assembled but not yet serving.
///
/// Cheap to hold and cheap to clone the pieces out of. Everything a host needs
/// is reachable: [`router`](Self::router) for HTTP, [`task_handler`](Self::task_handler)
/// for its own transport, [`health`](Self::health) to fold into its own
/// health surface, and [`repository`](Self::repository) to read records
/// directly.
pub struct TrustRegistry {
    config: Arc<TrustRegistryConfig>,
    repository: Arc<dyn TrustRecordAdminRepository>,
    capabilities: Arc<CapabilitySet>,
    verifier: Arc<dyn trust_tasks_rs::DynProofVerifier>,
    dedup: Arc<dyn MessageIdStore>,
    health: Arc<RegistryHealth>,
    didcomm_source: DidCommSource,
    shutdown: CancellationToken,
    service_start_timestamp: DateTime<Utc>,
}

impl TrustRegistry {
    /// Start building a registry over `config`.
    pub fn builder(config: impl Into<Arc<TrustRegistryConfig>>) -> TrustRegistryBuilder {
        TrustRegistryBuilder {
            config: config.into(),
            repository: None,
            capabilities: None,
            capability_store: None,
            dedup: None,
            verifier: None,
            didcomm_source: None,
            shutdown: None,
        }
    }

    /// The registry's HTTP surface, ready to mount.
    ///
    /// Carries the TRQP endpoints (`POST /recognition`, `POST /authorization`),
    /// the Trust Tasks HTTPS binding (`POST /trust-tasks`) and
    /// `/.well-known/did.json`, relative to wherever the host nests it.
    ///
    /// Deliberately **not** included, because both belong to the host and
    /// applying our own would silently override or conflict with theirs:
    ///
    /// - a CORS layer — see [`crate::server`]'s standalone wiring for what the
    ///   service applies to itself;
    /// - `/health` — available separately as [`health_router`](Self::health_router),
    ///   or fold [`health`](Self::health) into the host's own endpoint.
    ///
    /// Note `/.well-known/did.json` is only meaningful at the server root; a
    /// host nesting the registry under a prefix should serve the registry's DID
    /// document itself, or mount at the root.
    pub fn router(&self) -> axum::Router {
        application_routes("", self.shared_data())
    }

    /// A standalone `GET /health` router, for a host that wants to expose the
    /// registry's health as its own endpoint rather than merging the state.
    pub fn health_router(&self) -> axum::Router {
        use axum::{Json, routing::get};

        let health = self.health.clone();
        axum::Router::new().route(
            "/health",
            get(move || {
                let health = health.clone();
                async move { Json(health.to_json()) }
            }),
        )
    }

    /// The full Trust Task handler: admin dispatcher, write ACL, proof
    /// verification and message-id dedup.
    ///
    /// This is the entrypoint for a host that owns its own transport. The host
    /// is responsible for authenticating the sender and resolving the
    /// framework's parties before calling
    /// [`handle`](crate::trust_tasks::TaskHandler::handle) — only it knows how
    /// its transport establishes them. Pass `None` for `sender_did` on an
    /// unauthenticated caller; writes are then denied.
    pub fn task_handler(&self) -> TaskHandler {
        TaskHandler::new(
            self.capabilities.dispatcher(),
            self.config.didcomm_config.profile_config.did.clone(),
            self.config.didcomm_config.admin_config.admin_dids.clone(),
            self.verifier.clone(),
        )
        .with_dedup(self.dedup.clone())
    }

    /// Route a Trust Task that arrived over DIDComm on a socket the **host**
    /// owns ([`DidCommSource::HostDriven`]).
    ///
    /// `body` is the inbound message's body — the
    /// `trusttasks.org/binding/didcomm/0.1` envelope — and `sender_did` is the
    /// authcrypt-verified sender. Handles party resolution and the full apply
    /// path, and returns the document to pack and send back.
    ///
    /// `None` means the body was not a usable Trust Task document: there is no
    /// thread or issuer to address an error to, so drop it rather than reply.
    pub async fn route_didcomm_envelope(
        &self,
        body: serde_json::Value,
        sender_did: &str,
    ) -> Option<Result<trust_tasks_rs::TrustTask<serde_json::Value>, trust_tasks_rs::ErrorResponse>>
    {
        crate::didcomm::handlers::trust_tasks::route_envelope_body(
            &self.task_handler(),
            body,
            sender_did,
        )
        .await
    }

    /// A read-only Trust Task handler over the query dispatcher, with no dedup
    /// store — the shape the HTTP surface uses. For a host exposing queries to
    /// callers it does not authenticate.
    pub fn query_task_handler(&self) -> TaskHandler {
        TaskHandler::new(
            self.capabilities.query_dispatcher(),
            self.config.didcomm_config.profile_config.did.clone(),
            Vec::new(),
            self.verifier.clone(),
        )
    }

    /// The live admin dispatcher handle.
    pub fn dispatcher(&self) -> DispatcherHandle {
        self.capabilities.dispatcher()
    }

    /// The live read-only dispatcher handle.
    pub fn query_dispatcher(&self) -> DispatcherHandle {
        self.capabilities.query_dispatcher()
    }

    /// The capability set, so a host can enable or disable capabilities.
    pub fn capabilities(&self) -> &Arc<CapabilitySet> {
        &self.capabilities
    }

    /// The record repository, for direct reads and writes that bypass the Trust
    /// Task layer.
    pub fn repository(&self) -> &Arc<dyn TrustRecordAdminRepository> {
        &self.repository
    }

    pub fn config(&self) -> &Arc<TrustRegistryConfig> {
        &self.config
    }

    /// Shared health state, for folding into a host's own health endpoint.
    pub fn health(&self) -> &Arc<RegistryHealth> {
        &self.health
    }

    /// The shutdown token every background task observes.
    pub fn shutdown_token(&self) -> CancellationToken {
        self.shutdown.clone()
    }

    /// State for the axum handlers.
    fn shared_data(&self) -> SharedData<dyn TrustRecordRepository> {
        SharedData {
            config: self.config.clone(),
            service_start_timestamp: self.service_start_timestamp,
            repository: self.repository.clone() as Arc<dyn TrustRecordRepository>,
            query_dispatcher: self.capabilities.query_dispatcher(),
            verifier: self.verifier.clone(),
        }
    }

    /// Run as a service: bind `config.server_config.listen_address`, apply the
    /// CORS layer, serve `/health`, and start the DIDComm listener when
    /// `config.didcomm_config.is_enabled`.
    ///
    /// This is what the standalone binary does. A host mounting
    /// [`router`](Self::router) into its own server must not call this — it
    /// would bind a second socket.
    pub async fn serve(self) -> Result<ServerHandle, BoxError> {
        crate::server::serve_registry(self).await
    }

    // --- accessors used by `crate::server` when it drives the service form ---

    pub(crate) fn into_parts(self) -> RegistryParts {
        RegistryParts {
            config: self.config,
            repository: self.repository,
            capabilities: self.capabilities,
            verifier: self.verifier,
            dedup: self.dedup,
            health: self.health,
            didcomm_source: self.didcomm_source,
            shutdown: self.shutdown,
            service_start_timestamp: self.service_start_timestamp,
        }
    }
}

/// Destructured [`TrustRegistry`], so `crate::server` can consume the pieces
/// without making every field public.
pub(crate) struct RegistryParts {
    pub(crate) config: Arc<TrustRegistryConfig>,
    pub(crate) repository: Arc<dyn TrustRecordAdminRepository>,
    pub(crate) capabilities: Arc<CapabilitySet>,
    pub(crate) verifier: Arc<dyn trust_tasks_rs::DynProofVerifier>,
    pub(crate) dedup: Arc<dyn MessageIdStore>,
    pub(crate) health: Arc<RegistryHealth>,
    pub(crate) didcomm_source: DidCommSource,
    pub(crate) shutdown: CancellationToken,
    pub(crate) service_start_timestamp: DateTime<Utc>,
}

impl RegistryParts {
    /// Rebuild the axum state after `crate::server` has taken the pieces apart.
    pub(crate) fn shared_data(&self) -> SharedData<dyn TrustRecordRepository> {
        SharedData {
            config: self.config.clone(),
            service_start_timestamp: self.service_start_timestamp,
            repository: self.repository.clone() as Arc<dyn TrustRecordRepository>,
            query_dispatcher: self.capabilities.query_dispatcher(),
            verifier: self.verifier.clone(),
        }
    }
}

/// Builder for [`TrustRegistry`].
///
/// Only [`repository`](Self::repository) is required — and only because there
/// is no safe default for where records live. Everything else falls back to
/// what the standalone service uses.
pub struct TrustRegistryBuilder {
    config: Arc<TrustRegistryConfig>,
    repository: Option<Arc<dyn TrustRecordAdminRepository>>,
    capabilities: Option<Vec<CapabilityDefinition>>,
    capability_store: Option<Box<dyn CapabilityStateStore>>,
    dedup: Option<Arc<dyn MessageIdStore>>,
    verifier: Option<Arc<dyn trust_tasks_rs::DynProofVerifier>>,
    didcomm_source: Option<DidCommSource>,
    shutdown: Option<CancellationToken>,
}

impl TrustRegistryBuilder {
    /// Where trust records live. Required.
    ///
    /// Any [`TrustRecordAdminRepository`] works, including a host's own
    /// implementation over storage it already runs. To build one from
    /// `config.storage_config` instead, use
    /// [`crate::storage::factory::TrustStorageRepoFactory`].
    pub fn repository(mut self, repository: Arc<dyn TrustRecordAdminRepository>) -> Self {
        self.repository = Some(repository);
        self
    }

    /// The capabilities this registry can serve.
    ///
    /// Defaults to the same set the standalone service compiles in. Pass an
    /// empty vector to serve none, or add a host's own definitions. Capabilities
    /// are off until enabled regardless — this only decides what *can* be
    /// enabled.
    pub fn capabilities(mut self, capabilities: Vec<CapabilityDefinition>) -> Self {
        self.capabilities = Some(capabilities);
        self
    }

    /// Where capability enablement state is persisted.
    ///
    /// Defaults to a [`FileCapabilityStore`] at
    /// `config.server_config.capability_state_path()`. A host that already has
    /// durable storage should pass its own, or
    /// [`MemoryCapabilityStore`](crate::capabilities::MemoryCapabilityStore)
    /// for an ephemeral registry.
    pub fn capability_store(mut self, store: Box<dyn CapabilityStateStore>) -> Self {
        self.capability_store = Some(store);
        self
    }

    /// The write-path message-id dedup store (R1.4).
    ///
    /// Defaults to [`MemoryMessageIdStore`], which suppresses duplicates only
    /// while the process lives — a restart forgets them, so a redelivered
    /// mutation can be applied twice. A host with durable storage should pass
    /// its own implementation; that is the one injection point here that
    /// changes a correctness property rather than a convenience.
    pub fn dedup_store(mut self, dedup: Arc<dyn MessageIdStore>) -> Self {
        self.dedup = Some(dedup);
        self
    }

    /// The Data-Integrity proof verifier for write proofs.
    ///
    /// Defaults to [`crate::trust_tasks::build_verifier`], which is backed by
    /// the Affinidi DID-resolver cache. Pass a host's own to share a resolver
    /// cache it already maintains.
    pub fn verifier(mut self, verifier: Arc<dyn trust_tasks_rs::DynProofVerifier>) -> Self {
        self.verifier = Some(verifier);
        self
    }

    /// Where the DIDComm connection comes from.
    ///
    /// Defaults to [`DidCommSource::Managed`] — the registry opens its own
    /// mediator connection, as the standalone service does. A host that already
    /// holds a connection for the registry's DID **must** change this: the
    /// mediator permits one websocket per DID, so a second one cannot be
    /// opened. Lend the connection with [`DidCommSource::SharedAtm`], or keep
    /// the receive loop and use [`DidCommSource::HostDriven`].
    ///
    /// Only consulted when `config.didcomm_config.is_enabled`.
    pub fn didcomm_source(mut self, source: DidCommSource) -> Self {
        self.didcomm_source = Some(source);
        self
    }

    /// The cancellation token background tasks observe.
    ///
    /// Defaults to a fresh token. A host should pass its own so the registry
    /// stops when the host does.
    pub fn shutdown(mut self, shutdown: CancellationToken) -> Self {
        self.shutdown = Some(shutdown);
        self
    }

    /// Assemble the registry.
    ///
    /// Loads persisted capability state and composes the dispatchers, so an
    /// already-enabled capability is live before the first request. Binds no
    /// socket and starts no listener.
    pub async fn build(self) -> Result<TrustRegistry, BoxError> {
        let repository = self.repository.ok_or_else(|| {
            BoxError::from(
                "TrustRegistryBuilder needs a repository: call `.repository(...)`, or build one \
                 from the config with `storage::factory::TrustStorageRepoFactory`",
            )
        })?;

        let available = self
            .capabilities
            .map(Ok)
            .unwrap_or_else(|| default_capabilities(repository.clone()))?;

        let store = self.capability_store.unwrap_or_else(|| {
            Box::new(FileCapabilityStore::new(
                self.config.server_config.capability_state_path(),
            ))
        });

        // One set owns the live dispatchers every transport reads through, so
        // enabling a capability takes effect everywhere without a restart.
        let base_repository = repository.clone();
        let query_repository = repository.clone();
        let capabilities = CapabilitySet::new(
            available,
            store,
            Box::new(move || crate::trust_tasks::build_dispatcher(base_repository.clone())),
            Box::new(move || crate::trust_tasks::build_query_dispatcher(query_repository.clone())),
        )
        .map_err(BoxError::from)?;

        let verifier = match self.verifier {
            Some(v) => v,
            None => crate::trust_tasks::build_verifier().await,
        };

        let dedup = self.dedup.unwrap_or_else(|| {
            if self.config.didcomm_config.is_enabled {
                warn!(
                    "Message-id dedup is in-memory: duplicate writes are suppressed while this \
                     process lives, but a restart forgets them and a redelivery could re-apply. \
                     Pass a durable store with `TrustRegistryBuilder::dedup_store`."
                );
            }
            Arc::new(MemoryMessageIdStore::default())
        });

        Ok(TrustRegistry {
            health: Arc::new(RegistryHealth::new(self.config.didcomm_config.is_enabled)),
            config: self.config,
            repository,
            capabilities,
            verifier,
            dedup,
            didcomm_source: self.didcomm_source.unwrap_or_default(),
            shutdown: self.shutdown.unwrap_or_default(),
            service_start_timestamp: Utc::now(),
        })
    }
}

/// The capabilities the standalone service compiles in.
fn default_capabilities(
    repository: Arc<dyn TrustRecordAdminRepository>,
) -> Result<Vec<CapabilityDefinition>, BoxError> {
    Ok(vec![
        crate::capabilities::git_trust::definition(repository).map_err(BoxError::from)?,
    ])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capabilities::MemoryCapabilityStore;
    use crate::storage::adapters::local_storage::LocalStorage;

    async fn registry() -> TrustRegistry {
        let repository: Arc<dyn TrustRecordAdminRepository> = Arc::new(LocalStorage::new());
        TrustRegistry::builder(TrustRegistryConfig::embedded("/tmp/tr-embed-test"))
            .repository(repository)
            .capability_store(Box::new(MemoryCapabilityStore::default()))
            .build()
            .await
            .expect("builds")
    }

    /// A repository is the one thing with no safe default, so the error must
    /// say what to do rather than panic or pick a store.
    #[tokio::test]
    async fn build_without_a_repository_explains_itself() {
        let result = TrustRegistry::builder(TrustRegistryConfig::embedded("/tmp/tr-embed-test"))
            .capability_store(Box::new(MemoryCapabilityStore::default()))
            .build()
            .await;
        let err = match result {
            Ok(_) => panic!("a repository is required"),
            Err(e) => e,
        };
        assert!(
            err.to_string().contains("repository"),
            "unhelpful error: {err}"
        );
    }

    /// An embedded registry must not write capability state into whatever
    /// directory the host happens to run from.
    #[tokio::test]
    async fn capability_store_is_injectable() {
        let _registry = registry().await;
        // The injected memory store was used, so nothing touched the path the
        // config names.
        assert!(!std::path::Path::new("/tmp/tr-embed-test/capabilities.json").exists());
    }

    /// Default must stay `Managed`, or a standalone build would silently stop
    /// opening its own mediator connection.
    #[tokio::test]
    async fn didcomm_source_defaults_to_managed() {
        let registry = registry().await;
        assert!(matches!(
            registry.into_parts().didcomm_source,
            DidCommSource::Managed
        ));
    }

    /// `HostDriven` is the escape hatch for a host that already holds the one
    /// websocket the mediator allows for this DID; it must survive to the
    /// service layer, which is what decides not to start a listener.
    #[tokio::test]
    async fn host_driven_source_reaches_the_service_layer() {
        let repository: Arc<dyn TrustRecordAdminRepository> = Arc::new(LocalStorage::new());
        let registry = TrustRegistry::builder(TrustRegistryConfig::embedded("/tmp/tr-embed-test"))
            .repository(repository)
            .capability_store(Box::new(MemoryCapabilityStore::default()))
            .didcomm_source(DidCommSource::HostDriven)
            .build()
            .await
            .expect("builds");

        assert!(matches!(
            registry.into_parts().didcomm_source,
            DidCommSource::HostDriven
        ));
    }

    /// A host driving its own socket gets the same envelope contract the
    /// DIDComm binding uses — including dropping (not replying to) a body that
    /// is not a Trust Task document at all.
    #[tokio::test]
    async fn route_didcomm_envelope_drops_an_unusable_body() {
        let registry = registry().await;
        let outcome = registry
            .route_didcomm_envelope(
                serde_json::json!({"not": "a trust task"}),
                "did:example:peer",
            )
            .await;
        assert!(
            outcome.is_none(),
            "an undecodable body has no thread or issuer to address an error to"
        );
    }

    #[tokio::test]
    async fn host_supplied_shutdown_token_is_used() {
        let token = CancellationToken::new();
        let repository: Arc<dyn TrustRecordAdminRepository> = Arc::new(LocalStorage::new());
        let registry = TrustRegistry::builder(TrustRegistryConfig::embedded("/tmp/tr-embed-test"))
            .repository(repository)
            .capability_store(Box::new(MemoryCapabilityStore::default()))
            .shutdown(token.clone())
            .build()
            .await
            .expect("builds");

        assert!(!registry.shutdown_token().is_cancelled());
        token.cancel();
        assert!(
            registry.shutdown_token().is_cancelled(),
            "the registry must observe the host's token, not one of its own"
        );
    }

    /// The mountable router must not carry `/health` — the host owns that path,
    /// and silently claiming it would collide with the host's own endpoint.
    #[tokio::test]
    async fn mountable_router_excludes_health() {
        use axum::body::Body;
        use axum::http::{Request, StatusCode};
        use tower::ServiceExt;

        let registry = registry().await;

        let response = registry
            .router()
            .oneshot(
                Request::builder()
                    .uri("/health")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("router responds");
        assert_eq!(response.status(), StatusCode::NOT_FOUND);

        // ...but the dedicated health router does serve it.
        let response = registry
            .health_router()
            .oneshot(
                Request::builder()
                    .uri("/health")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("health router responds");
        assert_eq!(response.status(), StatusCode::OK);
    }

    /// The registry's routes must work under whatever prefix the host picks.
    ///
    /// Asserts a **200**, not merely "not 404": the TRQP recognition handler
    /// answers a missing record with 404 too, so an unmounted route and an
    /// empty store are indistinguishable. Seeding the record the query asks for
    /// is what makes the assertion about routing.
    #[tokio::test]
    async fn router_mounts_under_a_host_prefix() {
        use crate::domain::*;
        use axum::body::Body;
        use axum::http::{Request, StatusCode};
        use tower::ServiceExt;

        let repository: Arc<dyn TrustRecordAdminRepository> = Arc::new(LocalStorage::new());
        repository
            .create(
                TrustRecordBuilder::new()
                    .entity_id(EntityId::new("did:example:entity"))
                    .authority_id(AuthorityId::new("did:example:authority"))
                    .action(Action::new("issue"))
                    .resource(Resource::new("vc"))
                    .recognized(true)
                    .authorized(true)
                    .record_type(RecordType::Recognition)
                    .build()
                    .expect("valid record"),
            )
            .await
            .expect("seeded");

        let registry = TrustRegistry::builder(TrustRegistryConfig::embedded("/tmp/tr-embed-test"))
            .repository(repository)
            .capability_store(Box::new(MemoryCapabilityStore::default()))
            .build()
            .await
            .expect("builds");

        let app = axum::Router::new().nest("/registry", registry.router());

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/registry/recognition")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        serde_json::json!({
                            "entity_id": "did:example:entity",
                            "authority_id": "did:example:authority",
                            "action": "issue",
                            "resource": "vc",
                        })
                        .to_string(),
                    ))
                    .expect("request"),
            )
            .await
            .expect("nested router responds");

        assert_eq!(
            response.status(),
            StatusCode::OK,
            "recognition route should answer at the host's chosen prefix"
        );
    }
}
