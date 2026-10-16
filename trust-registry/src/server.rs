use std::net::SocketAddr;
use std::sync::Arc;

use crate::storage::repository::TrustRecordAdminRepository;
use axum::{Json, Router, routing::get};
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
use tower_http::cors::CorsLayer;
use tracing::{debug, error, info, warn};

use crate::{
    configs::{DidcommConfig, TrustRegistryConfig},
    didcomm::listener::start_didcomm_listener,
    health::RegistryHealth,
    http::application_routes,
};

type BoxError = Box<dyn std::error::Error + Send + Sync>;

#[cfg(feature = "standalone")]
fn setup_logging() {
    use tracing_subscriber::EnvFilter;

    let _ = tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env()) // reads RUST_LOG
        .with_target(false)
        .with_level(true)
        .with_thread_ids(true)
        .try_init();
}

/// A running Trust Registry server.
///
/// Returned by [`serve`]. Holds the bound HTTP address, the shutdown token, and
/// the background task handles so a caller (production `main` or an integration
/// test) can learn where the server is listening, wait for it, or stop it
/// cleanly — without the process-global side effects (`dotenv`,
/// `std::process::exit`) that [`start`] performs.
///
/// With `ENABLE_REST=false` no HTTP listener is bound at all (no TRQP routes,
/// no `/health`), so the HTTP fields are `None`.
pub struct ServerHandle {
    http_addr: Option<SocketAddr>,
    shutdown: CancellationToken,
    http_task: Option<JoinHandle<Result<(), BoxError>>>,
    didcomm_task: Option<JoinHandle<Result<(), BoxError>>>,
    health: Arc<RegistryHealth>,
    audit: Arc<crate::audit::bounded::BoundedAuditLogger>,
}

impl ServerHandle {
    /// The address the HTTP server bound to. When the config requested an
    /// ephemeral port (`…:0`), this is the concrete port the OS assigned.
    /// `None` when REST is disabled and nothing was bound.
    pub fn http_addr(&self) -> Option<SocketAddr> {
        self.http_addr
    }

    /// Convenience `http://<addr>` base URL for the REST/TRQP surface.
    /// `None` when REST is disabled.
    pub fn base_url(&self) -> Option<String> {
        self.http_addr.map(|addr| format!("http://{addr}"))
    }

    /// A clone of the shutdown token, so callers can trigger (or observe)
    /// shutdown without consuming the handle.
    pub fn shutdown_token(&self) -> CancellationToken {
        self.shutdown.clone()
    }

    /// Signal shutdown and await the background tasks. The HTTP server stops
    /// via graceful shutdown; the DIDComm/TSP listeners observe the same token.
    pub async fn shutdown(self) {
        self.shutdown.cancel();
        self.join().await;
    }

    /// The shared health state, so callers (and tests) can observe whether the
    /// write path is still up.
    pub fn health(&self) -> &Arc<RegistryHealth> {
        &self.health
    }

    /// Await the background tasks without signalling shutdown.
    ///
    /// With REST enabled, returns when the **HTTP** task ends: a DIDComm
    /// listener failure does not end this, it degrades health and leaves the
    /// read path serving. With REST disabled the DIDComm listener is the whole
    /// service, so this returns when it ends (or, when DIDComm is host-driven
    /// and nothing runs here, when the shutdown token is cancelled).
    pub async fn join(self) {
        let audit = self.audit.clone();
        self.join_tasks().await;
        // Whatever ended the tasks, record the refusals still only counted.
        audit.flush().await;
    }

    async fn join_tasks(self) {
        let Self {
            http_task,
            didcomm_task,
            health,
            shutdown,
            ..
        } = self;

        let (mut http_task, didcomm_task) = match (http_task, didcomm_task) {
            (Some(http_task), Some(didcomm_task)) => (http_task, didcomm_task),
            (Some(http_task), None) => {
                if let Err(e) = http_task.await {
                    error!("http task panicked: {e:?}");
                }
                return;
            }
            // No read path to fall back to: the listener ending is the service
            // ending, so return and let the caller (or supervisor) react.
            (None, Some(didcomm_task)) => {
                let result = didcomm_task.await;
                log_task_exit("didcomm", &result);
                health.mark_writes_unavailable(describe_task_exit(&result));
                return;
            }
            (None, None) => {
                shutdown.cancelled().await;
                return;
            }
        };

        tokio::select! {
            result = didcomm_task => {
                // The DIDComm listener stopping must NOT bring the process
                // down: the read path (REST/TRQP) is independent and still
                // useful. Previously this arm ended `join`, so an unreachable
                // mediator killed the HTTP server too. Degrade, keep serving
                // reads, and let the operator see it on /health.
                log_task_exit("didcomm", &result);
                health.mark_writes_unavailable(describe_task_exit(&result));
                error!(
                    "DIDComm listener stopped; continuing to serve reads. \
                     Record mutations cannot be received until it recovers \
                     (/health reports status=degraded)."
                );
                if let Err(e) = http_task.await {
                    error!("http task panicked: {e:?}");
                }
            }
            result = &mut http_task => log_task_exit("http", &result),
        }
    }
}

/// One-line reason a task ended, for the `/health` `detail` field.
fn describe_task_exit(result: &Result<Result<(), BoxError>, tokio::task::JoinError>) -> String {
    match result {
        Ok(Ok(())) => "didcomm listener exited cleanly".to_string(),
        Ok(Err(e)) => format!("didcomm listener failed: {e}"),
        Err(e) => format!("didcomm listener panicked: {e}"),
    }
}

fn log_task_exit(name: &str, result: &Result<Result<(), BoxError>, tokio::task::JoinError>) {
    match result {
        Ok(Ok(())) => info!("{name} task exited"),
        Ok(Err(e)) => error!("{name} task failed: {e}"),
        Err(e) => error!("{name} task panicked: {e:?}"),
    }
}

fn build_cors_layer(allowed_origins: &[String]) -> CorsLayer {
    if allowed_origins.is_empty() {
        info!("CORS: No allowed origins configured, allowing all origins");
        return CorsLayer::permissive();
    }

    if allowed_origins.len() == 1 && allowed_origins[0] == "*" {
        info!("CORS: Wildcard configured, allowing all origins");
        return CorsLayer::permissive();
    }

    info!("CORS: Configured allowed origins: {:?}", allowed_origins);

    let origins: Vec<_> = allowed_origins
        .iter()
        .filter_map(|origin| origin.parse().ok())
        .collect();

    CorsLayer::new()
        .allow_origin(origins)
        .allow_methods(tower_http::cors::Any)
        .allow_headers(tower_http::cors::Any)
}

/// Build the top-level HTTP router (health check + TRQP application routes + CORS).
///
/// The service form of the router. The application routes themselves are the
/// same ones [`crate::TrustRegistry::router`] hands an embedding host; what the
/// service adds on top is `/health` and the CORS layer, both of which a host
/// owns for itself.
fn build_router(parts: &crate::embed::RegistryParts) -> Router {
    let cors = build_cors_layer(&parts.config.server_config.cors_allowed_origins);

    let health = parts.health.clone();
    let health_route = Router::new().route(
        "/health",
        get(move || {
            let health = health.clone();
            async move { Json(health.to_json()) }
        }),
    );

    health_route
        .merge(application_routes("", parts.shared_data()))
        .layer(cors)
}

async fn start_didcomm_server(
    config: DidcommConfig,
    repository: Arc<dyn TrustRecordAdminRepository>,
    tasks: crate::trust_tasks::TaskHandler,
    source: crate::didcomm::listener::DidCommSource,
    shutdown: CancellationToken,
) -> Result<(), BoxError> {
    // `start_didcomm_listener` returns the listener task's own result nested
    // inside the join result. Both layers are propagated, so `/health` says
    // why the listener stopped instead of reporting a failure as a clean exit.
    start_didcomm_listener(config, repository, tasks, source, shutdown).await??;
    Ok(())
}

/// Start the Trust Registry servers over `repository` and return a
/// [`ServerHandle`] once the HTTP listener (if any) is bound.
///
/// This is the reusable core of [`start`]: it performs **no** process-global
/// setup (no `dotenv`, no logging init, no `std::process::exit`). When REST is
/// enabled (`config.didcomm_config.transport_flags.rest`) it binds whatever
/// `config.server_config.listen_address` requests — including an ephemeral
/// `…:0` port, which the returned handle reports via
/// [`ServerHandle::http_addr`]; when REST is disabled nothing is bound. The HTTP server is wired for graceful shutdown
/// on `shutdown`; the DIDComm listener (and, with the `tsp` feature, the TSP
/// receive loop) is started only when `config.didcomm_config.is_enabled`.
pub async fn serve(
    config: Arc<TrustRegistryConfig>,
    repository: Arc<dyn TrustRecordAdminRepository>,
    shutdown: CancellationToken,
) -> Result<ServerHandle, BoxError> {
    let registry = crate::TrustRegistry::builder(config)
        .repository(repository)
        .shutdown(shutdown)
        .build()
        .await?;
    serve_registry(registry).await
}

/// Run an assembled [`TrustRegistry`](crate::TrustRegistry) as a service.
///
/// The service half of the split: the registry itself binds nothing, and this
/// adds the socket, the CORS layer, `/health` and the DIDComm listener on top.
/// Reached via [`serve`] or [`crate::TrustRegistry::serve`].
pub(crate) async fn serve_registry(
    registry: crate::TrustRegistry,
) -> Result<ServerHandle, BoxError> {
    let parts = registry.into_parts();

    debug!("CONFIGS: {:?}", &parts.config);

    let (http_addr, http_task) = if parts.config.didcomm_config.transport_flags.rest {
        // Bind first so the caller (and the returned handle) learns the
        // concrete address before any request can race against it.
        let listener = tokio::net::TcpListener::bind(&parts.config.server_config.listen_address)
            .await
            .map_err(|e| {
                format!(
                    "failed to bind REST listener on {} (LISTEN_ADDRESS): {e}",
                    parts.config.server_config.listen_address
                )
            })?;
        let http_addr = listener.local_addr()?;

        let router = build_router(&parts);

        info!("HTTP server is starting on {http_addr}...");

        let http_shutdown = parts.shutdown.clone();
        let http_task = tokio::spawn(async move {
            axum::serve(listener, router)
                .with_graceful_shutdown(async move { http_shutdown.cancelled().await })
                .await
                .map_err(BoxError::from)
        });
        (Some(http_addr), Some(http_task))
    } else {
        warn!(
            "REST is disabled (ENABLE_REST=false): no HTTP listener, no TRQP routes, no /health."
        );
        (None, None)
    };

    use crate::didcomm::listener::DidCommSource;

    let didcomm_task = match (
        parts.config.didcomm_config.is_enabled,
        &parts.didcomm_source,
    ) {
        (false, _) => {
            warn!("DIDComm server is disabled.");
            None
        }
        // The host drives the receive loop and calls into the registry itself,
        // so there is no listener to start — but the write path is up, which is
        // why health is not degraded here.
        (true, DidCommSource::HostDriven) => {
            info!(
                "DIDComm is host-driven: the host owns the mediator socket and routes \
                 inbound documents through the registry itself."
            );
            None
        }
        (true, source) => Some(tokio::spawn(start_didcomm_server(
            parts.config.didcomm_config.clone(),
            parts.repository.clone(),
            parts.task_handler(),
            source.clone(),
            parts.shutdown.clone(),
        ))),
    };

    Ok(ServerHandle {
        http_addr,
        shutdown: parts.shutdown,
        http_task,
        didcomm_task,
        audit: parts.audit.clone(),
        health: parts.health,
    })
}

/// Standalone entrypoint: own the process.
///
/// Loads `.env`, installs a global tracing subscriber, reads the whole config
/// from the environment, and exits the process when a server task dies so a
/// supervisor restarts it. Every one of those is a process-global side effect a
/// host must not inherit, which is why this sits behind the `standalone`
/// feature — an embedded registry uses [`serve`] (or the builder) instead.
#[cfg(feature = "standalone")]
pub async fn start() {
    use crate::configs::Configs;
    use crate::storage::factory::TrustStorageRepoFactory;

    // resources section
    dotenvy::dotenv().ok();

    setup_logging();

    let config = match TrustRegistryConfig::load().await {
        Ok(c) => Arc::new(c),
        Err(e) => {
            error!(
                "Failed to load configs. End of work. Original error is: {}",
                e
            );
            panic!("Failed to load configs");
        }
    };

    let repository_factory = TrustStorageRepoFactory::new(Arc::clone(&config));

    let repository = match repository_factory.create().await {
        Ok(r) => r,
        Err(e) => {
            error!("Failed to initialize trust record repository: {e}");
            panic!("Failed to initialize trust record repository: {e}");
        }
    };

    // Shutdown token for graceful termination of background tasks.
    let shutdown = CancellationToken::new();

    let handle = match serve(config, repository, shutdown).await {
        Ok(handle) => handle,
        Err(e) => {
            error!("Failed to start Trust Registry server: {e}");
            panic!("Failed to start Trust Registry server: {e}");
        }
    };

    // Block until a server task exits (which, in production, only happens on
    // failure), then terminate the process so a supervisor restarts us.
    handle.join().await;
    std::process::exit(1);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capabilities::MemoryCapabilityStore;
    use crate::didcomm::listener::DidCommSource;
    use crate::storage::adapters::local_storage::LocalStorage;

    async fn registry(
        listen_address: String,
        rest: bool,
        shutdown: CancellationToken,
    ) -> crate::TrustRegistry {
        let mut config = TrustRegistryConfig::embedded("/tmp/tr-server-test");
        config.server_config.listen_address = listen_address;
        // Host-driven DIDComm keeps the transport set valid with REST off
        // without needing a mediator.
        config.didcomm_config.is_enabled = true;
        config.didcomm_config.transport_flags.didcomm = true;
        config.didcomm_config.transport_flags.rest = rest;
        let repository: Arc<dyn TrustRecordAdminRepository> = Arc::new(LocalStorage::new());
        crate::TrustRegistry::builder(Arc::new(config))
            .repository(repository)
            .capability_store(Box::new(MemoryCapabilityStore::default()))
            .didcomm_source(DidCommSource::HostDriven)
            .shutdown(shutdown)
            .build()
            .await
            .expect("builds")
    }

    /// `ENABLE_REST=false` must not bind `LISTEN_ADDRESS` at all: a port held
    /// by another process is no reason for a DIDComm-only registry to fail.
    #[tokio::test]
    async fn rest_disabled_binds_nothing() {
        let occupied = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = occupied.local_addr().unwrap().to_string();
        let shutdown = CancellationToken::new();

        let handle = serve_registry(registry(addr, false, shutdown.clone()).await)
            .await
            .expect("REST-off registry starts even though LISTEN_ADDRESS is taken");
        assert!(handle.http_addr().is_none());
        assert!(handle.base_url().is_none());

        // Nothing runs locally, so `join` waits for shutdown and then returns.
        shutdown.cancel();
        tokio::time::timeout(std::time::Duration::from_secs(5), handle.join())
            .await
            .expect("join returns once shutdown is signalled");
    }

    /// With REST on, a taken port is still a startup error, and it names the
    /// env var so the operator knows what to change.
    #[tokio::test]
    async fn rest_enabled_bind_failure_names_listen_address() {
        let occupied = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = occupied.local_addr().unwrap().to_string();

        let err = match serve_registry(registry(addr, true, CancellationToken::new()).await).await {
            Ok(_) => panic!("binding an occupied port must fail"),
            Err(e) => e.to_string(),
        };
        assert!(err.contains("LISTEN_ADDRESS"), "{err}");
    }
}
