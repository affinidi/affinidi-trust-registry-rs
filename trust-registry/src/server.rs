use std::net::SocketAddr;
use std::sync::Arc;

use crate::storage::{
    factory::TrustStorageRepoFactory,
    repository::{TrustRecordAdminRepository, TrustRecordRepository},
};
use axum::{Json, Router, routing::get};
use dotenvy::dotenv;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
use tower_http::cors::CorsLayer;
use tracing::{debug, error, info, warn};
use tracing_subscriber::EnvFilter;

use crate::{
    SharedData,
    configs::{Configs, DidcommConfig, TrustRegistryConfig},
    didcomm::listener::start_didcomm_listener,
    health::RegistryHealth,
    http::application_routes,
};

type BoxError = Box<dyn std::error::Error + Send + Sync>;

fn setup_logging() {
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
pub struct ServerHandle {
    http_addr: SocketAddr,
    shutdown: CancellationToken,
    http_task: JoinHandle<Result<(), BoxError>>,
    didcomm_task: Option<JoinHandle<Result<(), BoxError>>>,
    health: Arc<RegistryHealth>,
}

impl ServerHandle {
    /// The address the HTTP server bound to. When the config requested an
    /// ephemeral port (`…:0`), this is the concrete port the OS assigned.
    pub fn http_addr(&self) -> SocketAddr {
        self.http_addr
    }

    /// Convenience `http://<addr>` base URL for the REST/TRQP surface.
    pub fn base_url(&self) -> String {
        format!("http://{}", self.http_addr)
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
    /// Returns when the **HTTP** task ends. A DIDComm listener failure does not
    /// end this: it degrades health and leaves the read path serving.
    pub async fn join(self) {
        let Self {
            mut http_task,
            didcomm_task,
            health,
            ..
        } = self;

        let Some(didcomm_task) = didcomm_task else {
            if let Err(e) = http_task.await {
                error!("http task panicked: {e:?}");
            }
            return;
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
fn build_router(
    config: Arc<TrustRegistryConfig>,
    repository: Arc<dyn TrustRecordRepository>,
    query_dispatcher: crate::capabilities::DispatcherHandle,
    health: Arc<RegistryHealth>,
) -> Router {
    let shared_data = SharedData {
        config: config.clone(),
        service_start_timestamp: chrono::Utc::now(),
        repository,
        query_dispatcher,
    };

    let cors = build_cors_layer(&config.server_config.cors_allowed_origins);

    let health_route = Router::new().route(
        "/health",
        get({
            let health = health.clone();
            move || {
                let health = health.clone();
                async move { Json(health.to_json()) }
            }
        }),
    );

    health_route
        .merge(application_routes("", shared_data))
        .layer(cors)
}

async fn start_didcomm_server(
    config: DidcommConfig,
    repository: Arc<dyn TrustRecordAdminRepository>,
    dispatcher: crate::capabilities::DispatcherHandle,
    shutdown: CancellationToken,
) -> Result<(), BoxError> {
    // `start_didcomm_listener` returns the listener task's own result nested
    // inside the join result; the inner listener outcome is discarded here.
    let _ = start_didcomm_listener(config, repository, dispatcher, shutdown).await?;
    Ok(())
}

/// Start the Trust Registry servers over `repository` and return a
/// [`ServerHandle`] once the HTTP listener is bound.
///
/// This is the reusable core of [`start`]: it performs **no** process-global
/// setup (no `dotenv`, no logging init, no `std::process::exit`) and binds
/// whatever `config.server_config.listen_address` requests — including an
/// ephemeral `…:0` port, which the returned handle reports via
/// [`ServerHandle::http_addr`]. The HTTP server is wired for graceful shutdown
/// on `shutdown`; the DIDComm listener (and, with the `tsp` feature, the TSP
/// receive loop) is started only when `config.didcomm_config.is_enabled`.
pub async fn serve(
    config: Arc<TrustRegistryConfig>,
    repository: Arc<dyn TrustRecordAdminRepository>,
    shutdown: CancellationToken,
) -> Result<ServerHandle, BoxError> {
    // Bind first so the caller (and the returned handle) learns the concrete
    // address before any request can race against it.
    let listener = tokio::net::TcpListener::bind(&config.server_config.listen_address).await?;
    let http_addr = listener.local_addr()?;

    // Capability composition: one set owns the live dispatchers every
    // transport reads through. No capabilities are compiled in yet — the
    // framework ships wired but empty; the first module (git-trust) registers
    // here.
    let capability_state_path = std::env::var("TR_CAPABILITY_STATE")
        .unwrap_or_else(|_| "./.trust-registry/capabilities.json".to_string());
    let base_repository = repository.clone();
    let query_repository = repository.clone();
    let capability_repository = repository.clone();
    let capabilities = crate::capabilities::CapabilitySet::new(
        vec![
            crate::capabilities::git_trust::definition(capability_repository)
                .map_err(BoxError::from)?,
        ],
        Box::new(crate::capabilities::FileCapabilityStore::new(
            capability_state_path,
        )),
        Box::new(move || crate::trust_tasks::build_dispatcher(base_repository.clone())),
        Box::new(move || crate::trust_tasks::build_query_dispatcher(query_repository.clone())),
    )
    .map_err(BoxError::from)?;

    // The read-only HTTP surface upcasts from the admin repository.
    let read_repository: Arc<dyn TrustRecordRepository> = repository.clone();
    let health = Arc::new(RegistryHealth::new(config.didcomm_config.is_enabled));
    let router = build_router(
        config.clone(),
        read_repository,
        capabilities.query_dispatcher(),
        health.clone(),
    );

    info!("HTTP server is starting on {http_addr}...");
    debug!("CONFIGS: {:?}", &config);

    let http_shutdown = shutdown.clone();
    let http_task = tokio::spawn(async move {
        axum::serve(listener, router)
            .with_graceful_shutdown(async move { http_shutdown.cancelled().await })
            .await
            .map_err(BoxError::from)
    });

    let didcomm_task = if config.didcomm_config.is_enabled {
        Some(tokio::spawn(start_didcomm_server(
            config.didcomm_config.clone(),
            repository,
            capabilities.dispatcher(),
            shutdown.clone(),
        )))
    } else {
        warn!("DIDComm server is disabled.");
        None
    };

    Ok(ServerHandle {
        http_addr,
        shutdown,
        http_task,
        didcomm_task,
        health,
    })
}

pub async fn start() {
    // resources section
    dotenv().ok();

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
