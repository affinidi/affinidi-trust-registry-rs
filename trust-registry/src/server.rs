use std::future::Future;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use crate::storage::repository::TrustRecordAdminRepository;
use axum::Router;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
use tower_http::cors::CorsLayer;
use tracing::{debug, error, info, warn};

use crate::{
    BoxError,
    configs::{DidcommConfig, TrustRegistryConfig},
    didcomm::listener::start_didcomm_listener,
    health::RegistryHealth,
    http::limits::{BoundedListener, bound_requests},
};

/// How long [`ServerHandle::join`] waits, once shutdown is under way, for the
/// DIDComm/TSP listener to stop: draining its in-flight handlers (each bounded
/// by its own handler and ack time limits, 40 seconds in all), sending their
/// deletions to the mediator directly (at most 20 seconds), and closing its
/// own mediator connection (at most 10 seconds), with margin. The same bounds
/// hold on the pickup and the TSP delivery-layer receive paths.
pub const LISTENER_SHUTDOWN_GRACE: Duration = Duration::from_secs(80);

/// Margin [`ServerHandle::join`] adds to the HTTP request time limit while
/// waiting for in-flight HTTP requests to drain.
const HTTP_SHUTDOWN_MARGIN: Duration = Duration::from_secs(5);

type TaskResult = Result<Result<(), BoxError>, tokio::task::JoinError>;

/// Diagnostics follow `RUST_LOG`; audit entries have a layer of their own,
/// always on at `INFO`, so lowering the log level never drops them.
#[cfg(feature = "standalone")]
fn setup_logging() {
    use crate::audit::audit_logger::AUDIT_TARGET;
    use tracing_subscriber::{
        EnvFilter, Layer, filter::filter_fn, layer::SubscriberExt, util::SubscriberInitExt,
    };

    let diagnostics = tracing_subscriber::fmt::layer()
        .with_target(false)
        .with_level(true)
        .with_thread_ids(true)
        .with_filter(EnvFilter::from_default_env()) // reads RUST_LOG
        .with_filter(filter_fn(|metadata| metadata.target() != AUDIT_TARGET));
    let audit = tracing_subscriber::fmt::layer()
        .with_target(false)
        .with_level(true)
        .with_thread_ids(true)
        .with_filter(filter_fn(|metadata| {
            metadata.target() == AUDIT_TARGET && *metadata.level() <= tracing::Level::INFO
        }));
    let _ = tracing_subscriber::registry()
        .with(diagnostics)
        .with(audit)
        .try_init();
}

/// A running Trust Registry server.
///
/// Returned by [`serve`]. Holds the bound HTTP address, the shutdown token, and
/// the background task handles so a caller (production `main` or an integration
/// test) can learn where the server is listening, wait for it, or stop it
/// cleanly — without the process-global side effects (`dotenv`, signal
/// handlers) that [`start`] performs.
///
/// With `ENABLE_REST=false` no HTTP listener is bound at all (no TRQP routes,
/// no `/health`), so the HTTP fields are `None`.
pub struct ServerHandle {
    http_addr: Option<SocketAddr>,
    shutdown: CancellationToken,
    http_task: Option<JoinHandle<Result<(), BoxError>>>,
    didcomm_task: Option<JoinHandle<Result<(), BoxError>>>,
    /// How long, once shutdown is under way, the HTTP server may take to
    /// drain its in-flight requests.
    http_grace: Duration,
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

    /// Signal shutdown and wait for every task to stop: the HTTP server drains
    /// its in-flight requests, and the DIDComm/TSP listener stops receiving and
    /// drains its in-flight handlers, each within a bounded time (see
    /// [`join`](Self::join)). A failure is logged; use `shutdown_token` and
    /// [`join`](Self::join) to receive it instead.
    pub async fn shutdown(self) {
        self.shutdown.cancel();
        if let Err(e) = self.join().await {
            error!("the Trust Registry did not stop cleanly: {e}");
        }
    }

    /// The shared health state, so callers (and tests) can observe whether the
    /// write path is still up.
    pub fn health(&self) -> &Arc<RegistryHealth> {
        &self.health
    }

    /// Wait until the service stops, then wait for every task to finish and
    /// flush the audit log.
    ///
    /// The service stops when the shutdown token is cancelled, when the HTTP
    /// server ends, or — with REST disabled — when the DIDComm listener ends.
    /// With REST enabled a DIDComm listener failure does not stop it: health
    /// is degraded and reads keep being served. Once stopping, the shutdown
    /// token is cancelled (if it was not already) and each remaining task is
    /// awaited for a bounded time — the HTTP request time limit plus a margin,
    /// and [`LISTENER_SHUTDOWN_GRACE`] for the listener — then aborted.
    ///
    /// Returns `Ok` when the stop was requested through the shutdown token and
    /// every task stopped cleanly in time; `Err` when a task ended on its own,
    /// failed, panicked, or had to be aborted.
    pub async fn join(self) -> Result<(), BoxError> {
        let audit = self.audit.clone();
        let result = self.join_tasks().await;
        // Whatever ended the tasks, record the refusals still only counted.
        audit.flush().await;
        result
    }

    async fn join_tasks(self) -> Result<(), BoxError> {
        let Self {
            mut http_task,
            mut didcomm_task,
            shutdown,
            http_grace,
            ..
        } = self;

        let rest = http_task.is_some();
        let mut http_result: Option<TaskResult> = None;
        let mut didcomm_result: Option<TaskResult> = None;

        // Run until a stop is requested or the task the service depends on
        // ends by itself.
        loop {
            tokio::select! {
                _ = shutdown.cancelled() => break,
                result = poll_task(&mut http_task), if http_result.is_none() => {
                    log_task_exit("http", &result);
                    http_result = Some(result);
                    break;
                }
                result = poll_task(&mut didcomm_task), if didcomm_result.is_none() => {
                    log_task_exit("didcomm", &result);
                    didcomm_result = Some(result);
                    if http_task.is_none() {
                        // No read path to fall back to: the listener ending is
                        // the service ending.
                        break;
                    }
                    // The DIDComm listener stopping must NOT bring the process
                    // down: the read path (REST/TRQP) is independent and still
                    // useful. Its task has already degraded /health.
                    error!(
                        "DIDComm listener stopped; continuing to serve reads. \
                         Record mutations cannot be received until it recovers \
                         (/health reports status=degraded)."
                    );
                }
            }
        }

        // Read before cancelling below: was the stop asked for, or did a task
        // end by itself?
        let requested = shutdown.is_cancelled();
        let listener_failed_while_serving = task_failed(&didcomm_result);
        let mut failures = Vec::new();
        if !requested {
            failures.push("a server task ended without a shutdown request".to_string());
        }
        // Whatever ended the service, stop what is still running.
        shutdown.cancel();

        // Both drain at once, each within its own bound.
        let http_pending = http_task.take().filter(|_| http_result.is_none());
        let didcomm_pending = didcomm_task.take().filter(|_| didcomm_result.is_none());
        let (http_finished, didcomm_finished) = tokio::join!(
            async {
                match http_pending {
                    Some(task) => Some(finish("http", task, http_grace).await),
                    None => None,
                }
            },
            async {
                match didcomm_pending {
                    Some(task) => Some(finish("didcomm", task, LISTENER_SHUTDOWN_GRACE).await),
                    None => None,
                }
            },
        );
        if let Some(finished) = http_finished {
            if finished.is_none() {
                failures.push(format!(
                    "the HTTP server did not stop within {http_grace:?}"
                ));
            }
            http_result = finished;
        }
        if let Some(finished) = didcomm_finished {
            match &finished {
                None => failures.push(format!(
                    "the DIDComm listener did not stop within {LISTENER_SHUTDOWN_GRACE:?}"
                )),
                Some(result) => log_task_exit("didcomm", result),
            }
            didcomm_result = finished;
        }

        if let Some(Ok(Err(e))) = &http_result {
            failures.push(format!("the HTTP server failed: {e}"));
        }
        if let Some(Err(_)) = &http_result {
            failures.push("the HTTP server panicked".to_string());
        }
        // A listener that failed while reads went on was reported on /health
        // and does not fail the stop; one that was the whole service, or that
        // failed while stopping, does.
        if task_failed(&didcomm_result) && (!rest || !listener_failed_while_serving) {
            failures.push("the DIDComm listener failed".to_string());
        }

        if failures.is_empty() {
            Ok(())
        } else {
            Err(failures.join("; ").into())
        }
    }
}

fn task_failed(result: &Option<TaskResult>) -> bool {
    matches!(result, Some(Ok(Err(_))) | Some(Err(_)))
}

/// Await `task` if there is one; never resolves when there is none.
async fn poll_task(task: &mut Option<JoinHandle<Result<(), BoxError>>>) -> TaskResult {
    match task {
        Some(task) => task.await,
        None => std::future::pending().await,
    }
}

/// Await `task` for at most `grace`, aborting it if it has not finished.
async fn finish(
    name: &str,
    mut task: JoinHandle<Result<(), BoxError>>,
    grace: Duration,
) -> Option<TaskResult> {
    match tokio::time::timeout(grace, &mut task).await {
        Ok(result) => Some(result),
        Err(_) => {
            error!("{name} task did not stop within {grace:?} of shutdown; aborting it");
            task.abort();
            None
        }
    }
}

/// How the listener ended, for the `/health` `detail` field. `/health` is
/// public, so it carries the class of the failure only; the error itself is
/// logged ([`log_task_exit`]).
fn describe_task_exit(result: &Result<(), BoxError>) -> &'static str {
    match result {
        Ok(()) => "didcomm listener exited; see the registry's log",
        Err(_) => "didcomm listener failed; see the registry's log",
    }
}

fn log_task_exit(name: &str, result: &TaskResult) {
    match result {
        Ok(Ok(())) => info!("{name} task exited"),
        Ok(Err(e)) => error!("{name} task failed: {e}"),
        Err(e) => error!("{name} task panicked: {e:?}"),
    }
}

/// The standalone service's CORS layer, from a list already checked by
/// [`crate::configs::server::validate_cors_origins`] (checked again here, since
/// a host may build `ServerConfig` itself):
///
/// - empty: no layer. Browsers then allow same-origin requests only.
/// - `["*"]`: any origin, method and header.
/// - origins: those origins, `GET`/`POST`/`OPTIONS` and the `content-type`
///   header, which is all the registry's routes take.
fn build_cors_layer(allowed_origins: &[String]) -> Result<Option<CorsLayer>, BoxError> {
    crate::configs::server::validate_cors_origins(allowed_origins)
        .map_err(|e| format!("CORS_ALLOWED_ORIGINS: {e}"))?;

    if allowed_origins.is_empty() {
        info!(
            "CORS: no allowed origins configured; cross-origin browser requests are not \
             allowed (set CORS_ALLOWED_ORIGINS, or '*' for any origin)"
        );
        return Ok(None);
    }

    if allowed_origins.len() == 1 && allowed_origins[0] == "*" {
        info!("CORS: wildcard configured, allowing all origins");
        return Ok(Some(CorsLayer::permissive()));
    }

    let origins = allowed_origins
        .iter()
        .map(|origin| origin.parse())
        .collect::<Result<Vec<axum::http::HeaderValue>, _>>()
        .map_err(|e| format!("CORS_ALLOWED_ORIGINS: {e}"))?;
    info!("CORS: allowed origins: {:?}", allowed_origins);

    Ok(Some(
        CorsLayer::new()
            .allow_origin(origins)
            .allow_methods([
                axum::http::Method::GET,
                axum::http::Method::POST,
                axum::http::Method::OPTIONS,
            ])
            .allow_headers([axum::http::header::CONTENT_TYPE]),
    ))
}

/// Build the top-level HTTP router (health check + TRQP application routes +
/// request limits + CORS).
///
/// The service form of the router: the registry's own
/// [`router`](crate::TrustRegistry::router) and
/// [`health_router`](crate::TrustRegistry::health_router), which a host can
/// mount itself, plus the request time and concurrency limits
/// ([`crate::http::limits`]) and the CORS layer, all of which a host owns for
/// itself.
fn build_router(registry: &crate::TrustRegistry) -> Result<Router, BoxError> {
    let cors = build_cors_layer(&registry.config.server_config.cors_allowed_origins)?;
    let routes = registry.health_router().merge(registry.router());
    let router = bound_requests(routes, &registry.config.server_config.http_limits);
    Ok(match cors {
        Some(cors) => router.layer(cors),
        None => router,
    })
}

/// Run the DIDComm listener, reporting on `health` when it stops: a listener
/// that ends while the service is running means writes are unavailable,
/// whether or not anyone is awaiting the [`ServerHandle`].
async fn start_didcomm_server(
    config: DidcommConfig,
    repository: Arc<dyn TrustRecordAdminRepository>,
    tasks: crate::trust_tasks::TaskHandler,
    source: crate::didcomm::listener::DidCommSource,
    health: Arc<RegistryHealth>,
    shutdown: CancellationToken,
) -> Result<(), BoxError> {
    supervise_listener(
        start_didcomm_listener(
            config,
            repository,
            tasks,
            source,
            Some(health.clone()),
            shutdown.clone(),
        ),
        &health,
        &shutdown,
    )
    .await
}

/// Await the listener and, unless it stopped because shutdown was requested,
/// mark writes unavailable. Both the listener's own result and its task's join
/// result are propagated, so `/health` says why it stopped instead of
/// reporting a failure as a clean exit.
async fn supervise_listener<E1, E2>(
    listener: impl Future<Output = Result<Result<(), E1>, E2>>,
    health: &RegistryHealth,
    shutdown: &CancellationToken,
) -> Result<(), BoxError>
where
    E1: Into<BoxError>,
    E2: Into<BoxError>,
{
    let result = match listener.await {
        Ok(Ok(())) => Ok(()),
        Ok(Err(e)) => Err(e.into()),
        Err(e) => Err(e.into()),
    };
    if result.is_err() || !shutdown.is_cancelled() {
        health.mark_writes_unavailable(describe_task_exit(&result));
    }
    result
}

/// Start the Trust Registry servers over `repository` and return a
/// [`ServerHandle`] once the HTTP listener (if any) is bound.
///
/// This is the reusable core of [`start`]: it performs **no** process-global
/// setup (no `dotenv`, no logging init, no signal handlers). When REST is
/// enabled (`config.didcomm_config.transport_flags.rest`) it binds whatever
/// `config.server_config.listen_address` requests — including an ephemeral
/// `…:0` port, which the returned handle reports via
/// [`ServerHandle::http_addr`]; when REST is disabled nothing is bound. The
/// HTTP server is wired for graceful shutdown on `shutdown`; the DIDComm
/// listener (and, with the `tsp` feature, the TSP receive loop) is started
/// only when `config.didcomm_config.is_enabled`.
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
    let config = &registry.config;
    debug!(
        listen_address = %config.server_config.listen_address,
        storage_backend = ?config.storage_config.storage_backend,
        didcomm_enabled = config.didcomm_config.is_enabled,
        transport_flags = ?config.didcomm_config.transport_flags,
        registry_did = %config.didcomm_config.profile_config.did,
        mediator_did = %config.didcomm_config.mediator_did,
        admin_dids = config.didcomm_config.admin_config.admin_dids.len(),
        "configuration loaded"
    );

    let http_grace = config.server_config.http_limits.request_timeout + HTTP_SHUTDOWN_MARGIN;
    let (http_addr, http_task) = if config.didcomm_config.transport_flags.rest {
        // Bind first so the caller (and the returned handle) learns the
        // concrete address before any request can race against it.
        let listener = tokio::net::TcpListener::bind(&config.server_config.listen_address)
            .await
            .map_err(|e| {
                format!(
                    "failed to bind REST listener on {} (LISTEN_ADDRESS): {e}",
                    config.server_config.listen_address
                )
            })?;
        let http_addr = listener.local_addr()?;

        let router = build_router(&registry)?;

        info!("HTTP server is starting on {http_addr}...");

        let http_shutdown = registry.shutdown.clone();
        let limits = config.server_config.http_limits;
        let http_task = tokio::spawn(async move {
            axum::serve(BoundedListener::new(listener, &limits), router)
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

    let didcomm_task = match (config.didcomm_config.is_enabled, &registry.didcomm_source) {
        (false, _) => {
            warn!("DIDComm server is disabled.");
            None
        }
        // The host drives the receive loop and calls into the registry itself,
        // so there is no listener to start. Health reports the write path as
        // `unknown` until the host says otherwise.
        (true, DidCommSource::HostDriven) => {
            info!(
                "DIDComm is host-driven: the host owns the mediator socket and routes \
                 inbound documents through the registry itself."
            );
            None
        }
        (true, source) => Some(tokio::spawn(start_didcomm_server(
            config.didcomm_config.clone(),
            registry.repository.clone(),
            registry.task_handler(),
            source.clone(),
            registry.health.clone(),
            registry.shutdown.clone(),
        ))),
    };

    Ok(ServerHandle {
        http_addr,
        shutdown: registry.shutdown.clone(),
        http_task,
        didcomm_task,
        http_grace,
        audit: registry.audit.clone(),
        health: registry.health.clone(),
    })
}

/// Forward every SIGTERM and Ctrl-C (SIGINT) to a channel, by name.
///
/// The handlers are installed when this is called, not when its task first
/// runs, so a signal that arrives during startup is not missed. As PID 1 in a
/// container the process has no default signal dispositions, so without them
/// SIGTERM would be ignored.
#[cfg(feature = "standalone")]
fn shutdown_signals() -> std::io::Result<tokio::sync::mpsc::Receiver<&'static str>> {
    let (tx, rx) = tokio::sync::mpsc::channel(4);
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};
        let mut terminate = signal(SignalKind::terminate())?;
        let mut interrupt = signal(SignalKind::interrupt())?;
        tokio::spawn(async move {
            loop {
                let name = tokio::select! {
                    Some(()) = terminate.recv() => "SIGTERM",
                    Some(()) = interrupt.recv() => "SIGINT",
                    else => return,
                };
                if tx.send(name).await.is_err() {
                    return;
                }
            }
        });
    }
    #[cfg(not(unix))]
    tokio::spawn(async move {
        while tokio::signal::ctrl_c().await.is_ok() {
            if tx.send("Ctrl-C").await.is_err() {
                return;
            }
        }
    });
    Ok(rx)
}

/// Cancel `shutdown` on the first signal; on a second, call `force` — the
/// operator asked again, so stop waiting for the drain.
#[cfg(feature = "standalone")]
fn cancel_on_signal(
    mut signals: tokio::sync::mpsc::Receiver<&'static str>,
    shutdown: CancellationToken,
    force: impl FnOnce(&'static str) + Send + 'static,
) {
    tokio::spawn(async move {
        tokio::select! {
            Some(name) = signals.recv() => {
                info!("{name} received; shutting down (send it again to stop at once)");
                shutdown.cancel();
            }
            _ = shutdown.cancelled() => {}
        }
        if let Some(name) = signals.recv().await {
            force(name);
        }
    });
}

/// A second signal during shutdown: exit at once. In-flight handlers are cut
/// short, so their messages stay queued at the mediator and are redelivered.
#[cfg(feature = "standalone")]
fn force_exit(name: &'static str) {
    error!("{name} received again; exiting without waiting for the drain to finish");
    std::process::exit(130);
}

/// Standalone entrypoint: own the process.
///
/// Loads `.env`, installs a global tracing subscriber and SIGTERM/Ctrl-C
/// handlers, reads the whole config from the environment, and runs until a
/// signal or a server task ends. Every one of those is a process-global side
/// effect a host must not inherit, which is why this sits behind the
/// `standalone` feature — an embedded registry uses [`serve`] (or the builder)
/// instead.
///
/// Returns success when a signal stopped the registry and every task stopped
/// cleanly, and failure when startup failed or a task ended on its own, so a
/// supervisor can tell a requested stop from a crash. It returns rather than
/// calling `std::process::exit`, so destructors run after the audit log has
/// been flushed.
#[cfg(feature = "standalone")]
pub async fn start() -> std::process::ExitCode {
    use crate::configs::Configs;
    use crate::storage::factory::TrustStorageRepoFactory;
    use std::process::ExitCode;

    // resources section
    dotenvy::dotenv().ok();

    setup_logging();

    // Installed first, so a stop requested during startup is honoured.
    let shutdown = CancellationToken::new();
    match shutdown_signals() {
        Ok(signals) => cancel_on_signal(signals, shutdown.clone(), force_exit),
        Err(e) => {
            error!("could not install the SIGTERM/SIGINT handlers: {e}");
            return ExitCode::FAILURE;
        }
    }

    let config = match TrustRegistryConfig::load().await {
        Ok(c) => Arc::new(c),
        Err(e) => {
            error!("Failed to load configs. End of work. Original error is: {e}");
            return ExitCode::FAILURE;
        }
    };

    let repository = match TrustStorageRepoFactory::new(Arc::clone(&config))
        .create()
        .await
    {
        Ok(r) => r,
        Err(e) => {
            error!("Failed to initialize trust record repository: {e}");
            return ExitCode::FAILURE;
        }
    };

    let handle = match serve(config, repository, shutdown).await {
        Ok(handle) => handle,
        Err(e) => {
            error!("Failed to start Trust Registry server: {e}");
            return ExitCode::FAILURE;
        }
    };

    match handle.join().await {
        Ok(()) => {
            info!("Trust Registry stopped");
            ExitCode::SUCCESS
        }
        Err(e) => {
            error!("Trust Registry stopped: {e}");
            ExitCode::FAILURE
        }
    }
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
            .expect("join returns once shutdown is signalled")
            .expect("a requested stop is clean");
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

    fn origins(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| s.to_string()).collect()
    }

    /// Send a CORS preflight for `POST` from `origin` through `layer` and
    /// return the `Access-Control-Allow-Origin` it answered, if any.
    async fn preflight(layer: Option<CorsLayer>, origin: &str) -> Option<String> {
        use axum::body::Body;
        use axum::http::{Method, Request};
        use tower::ServiceExt;

        let router = Router::new().route("/x", axum::routing::post(|| async { "ok" }));
        let router = match layer {
            Some(layer) => router.layer(layer),
            None => router,
        };
        let response = router
            .oneshot(
                Request::builder()
                    .method(Method::OPTIONS)
                    .uri("/x")
                    .header("origin", origin)
                    .header("access-control-request-method", "POST")
                    .header("access-control-request-headers", "content-type")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        response
            .headers()
            .get("access-control-allow-origin")
            .map(|v| v.to_str().unwrap().to_string())
    }

    /// Unset means no cross-origin access, not every origin.
    #[tokio::test]
    async fn cors_unset_allows_no_cross_origin_requests() {
        let layer = build_cors_layer(&[]).unwrap();
        assert!(layer.is_none());
        assert_eq!(preflight(layer, "https://any.example").await, None);
    }

    #[tokio::test]
    async fn cors_wildcard_allows_any_origin() {
        let layer = build_cors_layer(&origins(&["*"])).unwrap();
        assert_eq!(
            preflight(layer, "https://any.example").await.as_deref(),
            Some("*")
        );
    }

    #[tokio::test]
    async fn cors_list_allows_only_the_listed_origins() {
        let list = origins(&["https://app.example.com", "http://localhost:3000"]);
        assert_eq!(
            preflight(build_cors_layer(&list).unwrap(), "http://localhost:3000")
                .await
                .as_deref(),
            Some("http://localhost:3000")
        );
        assert_eq!(
            preflight(build_cors_layer(&list).unwrap(), "https://other.example").await,
            None
        );
    }

    /// An entry that could never match is refused at startup, not dropped
    /// while the log reports it as configured.
    #[test]
    fn cors_invalid_entry_is_an_error_naming_it() {
        let err = build_cors_layer(&origins(&["https://app.example.com", "app.example.com"]))
            .unwrap_err()
            .to_string();
        assert!(err.contains("CORS_ALLOWED_ORIGINS"), "{err}");
        assert!(err.contains("'app.example.com'"), "{err}");
    }

    // --- lifecycle --------------------------------------------------------

    fn audit() -> Arc<crate::audit::bounded::BoundedAuditLogger> {
        Arc::new(crate::audit::bounded::BoundedAuditLogger::new(Arc::new(
            crate::audit::audit_logger::BaseAuditLogger::new(Default::default()),
        )))
    }

    /// A handle over hand-made tasks, so the supervision logic can be tested
    /// without a mediator.
    fn handle(
        shutdown: &CancellationToken,
        http_task: Option<JoinHandle<Result<(), BoxError>>>,
        didcomm_task: Option<JoinHandle<Result<(), BoxError>>>,
    ) -> ServerHandle {
        ServerHandle {
            http_addr: None,
            shutdown: shutdown.clone(),
            http_task,
            didcomm_task,
            http_grace: Duration::from_secs(5),
            health: Arc::new(RegistryHealth::new(true)),
            audit: audit(),
        }
    }

    /// Stops when shutdown is signalled, as axum's graceful shutdown does.
    fn http_like(shutdown: &CancellationToken) -> JoinHandle<Result<(), BoxError>> {
        let shutdown = shutdown.clone();
        tokio::spawn(async move {
            shutdown.cancelled().await;
            Ok(())
        })
    }

    /// Stops a while after shutdown is signalled, as the listener does while
    /// draining its handlers, and records that it finished.
    fn listener_like(
        shutdown: &CancellationToken,
        finished: Arc<std::sync::atomic::AtomicBool>,
    ) -> JoinHandle<Result<(), BoxError>> {
        let shutdown = shutdown.clone();
        tokio::spawn(async move {
            shutdown.cancelled().await;
            tokio::time::sleep(Duration::from_millis(200)).await;
            finished.store(true, std::sync::atomic::Ordering::SeqCst);
            Ok(())
        })
    }

    /// `shutdown()` returns only once the listener has finished, with REST on
    /// — where the HTTP task used to end the wait and the listener's handle
    /// was dropped — and with REST off.
    #[tokio::test]
    async fn shutdown_awaits_the_listener() {
        for rest in [true, false] {
            let shutdown = CancellationToken::new();
            let finished = Arc::new(std::sync::atomic::AtomicBool::new(false));
            let handle = handle(
                &shutdown,
                rest.then(|| http_like(&shutdown)),
                Some(listener_like(&shutdown, finished.clone())),
            );
            tokio::time::timeout(Duration::from_secs(5), handle.shutdown())
                .await
                .expect("shutdown returns");
            assert!(
                finished.load(std::sync::atomic::Ordering::SeqCst),
                "rest={rest}: shutdown returned before the listener finished"
            );
        }
    }

    /// A requested stop with every task stopping cleanly is a success, so the
    /// standalone binary exits 0.
    #[tokio::test]
    async fn a_requested_stop_joins_ok() {
        let shutdown = CancellationToken::new();
        let finished = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let handle = handle(
            &shutdown,
            Some(http_like(&shutdown)),
            Some(listener_like(&shutdown, finished)),
        );
        shutdown.cancel();
        handle.join().await.expect("a requested stop is clean");
    }

    /// The HTTP server ending by itself is a failure, and it stops the
    /// listener rather than leaving it running.
    #[tokio::test]
    async fn the_http_server_ending_by_itself_fails_and_stops_the_rest() {
        let shutdown = CancellationToken::new();
        let finished = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let http = tokio::spawn(async { Err::<(), BoxError>("accept failed".into()) });
        let handle = handle(
            &shutdown,
            Some(http),
            Some(listener_like(&shutdown, finished.clone())),
        );
        let err = handle.join().await.expect_err("an unrequested stop fails");
        assert!(err.to_string().contains("accept failed"), "{err}");
        assert!(shutdown.is_cancelled());
        assert!(finished.load(std::sync::atomic::Ordering::SeqCst));
    }

    /// With REST on, a listener failure degrades health but the service goes
    /// on, and a later requested stop is still clean.
    #[tokio::test]
    async fn a_listener_failure_with_rest_on_does_not_fail_the_stop() {
        let shutdown = CancellationToken::new();
        let listener = tokio::spawn(async { Err::<(), BoxError>("mediator gone".into()) });
        let handle = handle(&shutdown, Some(http_like(&shutdown)), Some(listener));
        let stopper = shutdown.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(100)).await;
            stopper.cancel();
        });
        handle
            .join()
            .await
            .expect("reads kept going; the stop was asked for");
    }

    /// With REST off, the listener is the service: its failure is the
    /// service's failure.
    #[tokio::test]
    async fn a_listener_failure_with_rest_off_fails() {
        let shutdown = CancellationToken::new();
        let listener = tokio::spawn(async { Err::<(), BoxError>("mediator gone".into()) });
        let handle = handle(&shutdown, None, Some(listener));
        handle.join().await.expect_err("the only task failed");
    }

    /// The wait is bounded: a listener that ignores shutdown is aborted after
    /// the grace period, and the stop is reported as unclean.
    #[tokio::test(start_paused = true)]
    async fn a_listener_that_will_not_stop_is_aborted() {
        let shutdown = CancellationToken::new();
        let stuck = tokio::spawn(std::future::pending::<Result<(), BoxError>>());
        let handle = handle(&shutdown, Some(http_like(&shutdown)), Some(stuck));
        shutdown.cancel();
        let err = handle
            .join()
            .await
            .expect_err("an aborted task is not clean");
        assert!(err.to_string().contains("did not stop"), "{err}");
    }

    /// The listener's own task reports to health when it stops, so health
    /// degrades even when nobody awaits the `ServerHandle`.
    #[tokio::test]
    async fn a_stopped_listener_degrades_health_without_join() {
        let health = RegistryHealth::new(true);
        let shutdown = CancellationToken::new();

        let result = supervise_listener(
            async { Ok::<Result<(), BoxError>, BoxError>(Err("auth failed".into())) },
            &health,
            &shutdown,
        )
        .await;
        assert!(result.is_err());
        assert_eq!(health.to_json()["writes"], "unavailable");
        assert!(
            !health.to_json()["detail"]
                .as_str()
                .unwrap_or_default()
                .contains("auth failed"),
            "the error is logged, not published"
        );

        // Stopping because shutdown was asked for is not a fault.
        let health = RegistryHealth::new(true);
        shutdown.cancel();
        supervise_listener(
            async { Ok::<Result<(), BoxError>, BoxError>(Ok(())) },
            &health,
            &shutdown,
        )
        .await
        .expect("clean");
        assert_eq!(health.to_json()["writes"], "starting");
    }

    /// The service's `/health` is the registry's own health router, reporting
    /// the record store and, for a host-driven registry, `writes: unknown`.
    #[tokio::test]
    async fn service_health_route_reports_storage_and_write_path() {
        use axum::body::Body;
        use axum::http::Request;
        use tower::ServiceExt;

        let registry = registry("127.0.0.1:0".to_string(), true, CancellationToken::new()).await;
        let response = build_router(&registry)
            .expect("router")
            .oneshot(
                Request::builder()
                    .uri("/health")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(body["status"], "OK");
        assert_eq!(body["writes"], "unknown");
        assert_eq!(body["storage"], "ok");
    }

    #[cfg(feature = "standalone")]
    #[tokio::test]
    async fn a_signal_cancels_the_shutdown_token() {
        let shutdown = CancellationToken::new();
        let (tx, rx) = tokio::sync::mpsc::channel(4);
        let (forced_tx, forced_rx) = tokio::sync::oneshot::channel();
        cancel_on_signal(rx, shutdown.clone(), move |name| {
            let _ = forced_tx.send(name);
        });
        assert!(!shutdown.is_cancelled());
        tx.send("SIGTERM").await.unwrap();
        tokio::time::timeout(Duration::from_secs(5), shutdown.cancelled())
            .await
            .expect("the signal cancels the token");

        // A second signal forces the exit rather than waiting for the drain.
        tx.send("SIGINT").await.unwrap();
        let forced = tokio::time::timeout(Duration::from_secs(5), forced_rx)
            .await
            .expect("a second signal forces")
            .unwrap();
        assert_eq!(forced, "SIGINT");
    }
}
