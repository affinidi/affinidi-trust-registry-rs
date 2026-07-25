//! Embedding the Trust Registry inside a host axum application.
//!
//! Run with:
//!
//! ```sh
//! cargo run -p trust-registry --example embedded_axum
//! ```
//!
//! Then, from another shell (set `EXAMPLE_ADDR` to move it off the default
//! `127.0.0.1:8231`):
//!
//! ```sh
//! curl 127.0.0.1:8231/                          # the host's own route
//! curl 127.0.0.1:8231/healthz                   # the host's own health, including the registry's
//! curl -X POST 127.0.0.1:8231/registry/recognition \
//!   -H 'content-type: application/json' \
//!   -d '{"entity_id":"did:example:issuer","authority_id":"did:example:authority",
//!        "action":"issue","resource":"vc"}'     # the registry, under the host's prefix
//! ```
//!
//! What this demonstrates, and why each part matters:
//!
//! - The **host** owns the socket, the router, the tracing subscriber and the
//!   shutdown signal. The registry never binds, never installs a subscriber,
//!   never reads the environment and never calls `process::exit`.
//! - The registry's routes mount under a prefix the host picks, alongside the
//!   host's own routes on the same port.
//! - `/healthz` is the *host's* endpoint, with the registry's health folded in
//!   as one component among others — which is why `router()` does not ship a
//!   `/health` of its own.
//! - Storage, capability state and the shutdown token are all supplied by the
//!   host.

use std::sync::Arc;

use axum::{Json, Router, routing::get};
use tokio_util::sync::CancellationToken;
use trust_registry::capabilities::MemoryCapabilityStore;
use trust_registry::configs::{ServerConfig, TrustRegistryConfig};
use trust_registry::domain::*;
use trust_registry::storage::adapters::local_storage::LocalStorage;
use trust_registry::storage::repository::TrustRecordAdminRepository;
use trust_registry::{TrustRegistry, health::RegistryHealth};

type BoxError = Box<dyn std::error::Error + Send + Sync>;

/// Whatever the host application already keeps in its own state.
#[derive(Clone)]
struct HostState {
    name: &'static str,
    /// The registry's health, folded into the host's own health endpoint.
    registry_health: Arc<RegistryHealth>,
}

#[tokio::main]
async fn main() -> Result<(), BoxError> {
    // The HOST installs the tracing subscriber. The registry never does — that
    // is why `server::start()` (which does) is behind the `standalone` feature.
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();

    // The HOST decides where records live. Any `TrustRecordAdminRepository`
    // works; `LocalStorage` is in-memory and dependency-free, so this example
    // needs no backend feature at all.
    let repository: Arc<dyn TrustRecordAdminRepository> = Arc::new(LocalStorage::new());
    seed(&repository).await?;

    // The HOST owns the shutdown signal, so the registry's background work
    // stops when the host does.
    let shutdown = CancellationToken::new();

    let config = TrustRegistryConfig {
        server_config: ServerConfig {
            // Irrelevant here: the host binds the socket, not the registry.
            // Left explicit to make that point.
            ..Default::default()
        },
        ..TrustRegistryConfig::embedded("./.trust-registry-example")
    };

    let registry = TrustRegistry::builder(config)
        .repository(repository)
        // In-memory, so the example leaves nothing behind. A real host would
        // point this at its own durable storage rather than let capability
        // state land in whatever directory it happens to run from.
        .capability_store(Box::new(MemoryCapabilityStore::default()))
        .shutdown(shutdown.clone())
        .build()
        .await?;

    let state = HostState {
        name: "example-host",
        registry_health: registry.health().clone(),
    };

    // The host's own application, with the registry mounted inside it. One
    // router, one port, one process.
    let app = Router::new()
        .route("/", get(|| async { "host application" }))
        .route("/healthz", get(host_health))
        .with_state(state)
        .nest("/registry", registry.router());

    // The host picks the address. `EXAMPLE_ADDR` is read *here*, in the host —
    // the registry itself reads no environment at all.
    let addr = std::env::var("EXAMPLE_ADDR").unwrap_or_else(|_| "127.0.0.1:8231".to_string());
    let listener = tokio::net::TcpListener::bind(&addr).await?;
    tracing::info!("host listening on http://{}", listener.local_addr()?);
    tracing::info!("registry mounted at /registry");

    let graceful = shutdown.clone();
    axum::serve(listener, app)
        .with_graceful_shutdown(async move {
            let _ = tokio::signal::ctrl_c().await;
            // Cancelling the token the registry was built with stops its
            // background work alongside the host's server.
            graceful.cancel();
        })
        .await?;

    Ok(())
}

/// The host's health endpoint, reporting the registry as one component among
/// whatever else the host runs.
async fn host_health(
    axum::extract::State(state): axum::extract::State<HostState>,
) -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "service": state.name,
        "status": "ok",
        "components": {
            "trust_registry": state.registry_health.to_json(),
        },
    }))
}

/// One record, so the example's `curl` returns a recognised answer rather than
/// an empty-store 404.
async fn seed(repository: &Arc<dyn TrustRecordAdminRepository>) -> Result<(), BoxError> {
    repository
        .create(
            TrustRecordBuilder::new()
                .entity_id(EntityId::new("did:example:issuer"))
                .authority_id(AuthorityId::new("did:example:authority"))
                .action(Action::new("issue"))
                .resource(Resource::new("vc"))
                .recognized(true)
                .authorized(true)
                .record_type(RecordType::Recognition)
                .build()
                .map_err(|e| -> BoxError { e.to_string().into() })?,
        )
        .await
        .map_err(|e| -> BoxError { e.to_string().into() })?;
    Ok(())
}
