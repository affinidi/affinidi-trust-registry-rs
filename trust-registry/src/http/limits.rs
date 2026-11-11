//! Resource limits for the HTTP surface.
//!
//! Every route the registry serves over HTTP is unauthenticated, so each
//! request, and each connection, is bounded:
//!
//! - **body size** ([`HttpLimits::max_body_bytes`]): applied by
//!   [`application_routes`](crate::http::application_routes) itself, so a host
//!   mounting [`TrustRegistry::router`](crate::TrustRegistry::router) gets it
//!   too. A larger body is answered `413`;
//! - **request time** ([`HttpLimits::request_timeout`]): a request whose
//!   answer is not ready in time, for example behind a stalled storage backend,
//!   is answered `503` and its work dropped;
//! - **requests in flight** ([`HttpLimits::max_concurrent_requests`]): a
//!   request beyond the limit is answered `503` with `Retry-After` at once
//!   rather than queued;
//! - **open connections** ([`HttpLimits::max_connections`]): beyond the limit
//!   the listener stops accepting until one closes;
//! - **idle connections** ([`HttpLimits::idle_timeout`]): a connection that
//!   neither sends nor accepts a byte for this long is closed, so a client
//!   that opens connections and goes quiet, or reads its answer too slowly to
//!   make progress, cannot hold them.
//!
//! The last four are applied by the standalone service ([`crate::server`]);
//! a host serving the router itself owns its server and applies its own.
//! Neither bounds a client that keeps a connection busy by trickling bytes
//! just inside the idle timeout; a deployment exposed to untrusted networks
//! should also sit behind a reverse proxy that enforces a header read deadline.

use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use axum::Router;
use axum::extract::Request;
use axum::http::{HeaderValue, StatusCode, header};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tokio::time::{Instant, Sleep};

/// Default for [`HttpLimits::request_timeout`].
pub const DEFAULT_REQUEST_TIMEOUT: Duration = Duration::from_secs(10);
/// Default for [`HttpLimits::idle_timeout`].
pub const DEFAULT_IDLE_TIMEOUT: Duration = Duration::from_secs(30);
/// Default for [`HttpLimits::max_body_bytes`]: room for a signed Trust Task
/// or a TRQP query with its context, well short of axum's 2 MB.
pub const DEFAULT_MAX_BODY_BYTES: usize = 64 * 1024;
/// Default for [`HttpLimits::max_concurrent_requests`].
pub const DEFAULT_MAX_CONCURRENT_REQUESTS: usize = 256;
/// Default for [`HttpLimits::max_connections`].
pub const DEFAULT_MAX_CONNECTIONS: usize = 1024;

/// How long a client told the service is busy should wait, in seconds.
const RETRY_AFTER_SECS: &str = "1";

/// Bounds on what one HTTP client can make the registry hold.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HttpLimits {
    /// The longest a request may take to be answered.
    pub request_timeout: Duration,
    /// The longest a connection may make no progress before it is closed.
    /// Longer than `request_timeout`, so a request being answered is never
    /// cut off as idle.
    pub idle_timeout: Duration,
    /// The largest request body accepted.
    pub max_body_bytes: usize,
    /// The most requests answered at once.
    pub max_concurrent_requests: usize,
    /// The most connections held open at once.
    pub max_connections: usize,
}

impl Default for HttpLimits {
    fn default() -> Self {
        Self {
            request_timeout: DEFAULT_REQUEST_TIMEOUT,
            idle_timeout: DEFAULT_IDLE_TIMEOUT,
            max_body_bytes: DEFAULT_MAX_BODY_BYTES,
            max_concurrent_requests: DEFAULT_MAX_CONCURRENT_REQUESTS,
            max_connections: DEFAULT_MAX_CONNECTIONS,
        }
    }
}

impl HttpLimits {
    /// Read `TR_HTTP_REQUEST_TIMEOUT_SECS`, `TR_HTTP_IDLE_TIMEOUT_SECS`,
    /// `TR_HTTP_MAX_BODY_BYTES`, `TR_HTTP_MAX_CONCURRENT_REQUESTS` and
    /// `TR_HTTP_MAX_CONNECTIONS`, each defaulting when unset.
    ///
    /// A value that is not a positive whole number, or an idle timeout not
    /// longer than the request timeout, is an error rather than a silent
    /// default, so a typo cannot lift a limit.
    pub fn from_env() -> Result<Self, String> {
        Self::parse(|name| std::env::var(name).ok())
    }

    fn parse(read: impl Fn(&str) -> Option<String>) -> Result<Self, String> {
        let positive = |name: &str| -> Result<Option<u64>, String> {
            read(name)
                .map(|raw| {
                    raw.trim()
                        .parse::<u64>()
                        .ok()
                        .filter(|value| *value > 0)
                        .ok_or_else(|| {
                            format!("{name} must be a positive whole number, not {raw:?}")
                        })
                })
                .transpose()
        };
        let count = |name: &str| -> Result<Option<usize>, String> {
            positive(name)?
                .map(|value| {
                    usize::try_from(value).map_err(|_| format!("{name} is out of range: {value}"))
                })
                .transpose()
        };
        let defaults = Self::default();
        let limits = Self {
            request_timeout: positive("TR_HTTP_REQUEST_TIMEOUT_SECS")?
                .map_or(defaults.request_timeout, Duration::from_secs),
            idle_timeout: positive("TR_HTTP_IDLE_TIMEOUT_SECS")?
                .map_or(defaults.idle_timeout, Duration::from_secs),
            max_body_bytes: count("TR_HTTP_MAX_BODY_BYTES")?.unwrap_or(defaults.max_body_bytes),
            max_concurrent_requests: count("TR_HTTP_MAX_CONCURRENT_REQUESTS")?
                .unwrap_or(defaults.max_concurrent_requests),
            max_connections: count("TR_HTTP_MAX_CONNECTIONS")?.unwrap_or(defaults.max_connections),
        };
        if limits.idle_timeout <= limits.request_timeout {
            return Err(format!(
                "TR_HTTP_IDLE_TIMEOUT_SECS ({}) must be longer than TR_HTTP_REQUEST_TIMEOUT_SECS ({})",
                limits.idle_timeout.as_secs(),
                limits.request_timeout.as_secs()
            ));
        }
        Ok(limits)
    }
}

/// Bound the requests `router` answers: at most
/// [`max_concurrent_requests`](HttpLimits::max_concurrent_requests) at once,
/// each within [`request_timeout`](HttpLimits::request_timeout), and mark every
/// answer as neither to be sniffed nor stored.
pub fn bound_requests(router: Router, limits: &HttpLimits) -> Router {
    let permits = Arc::new(Semaphore::new(limits.max_concurrent_requests));
    let timeout = limits.request_timeout;
    router.layer(middleware::from_fn(move |request: Request, next: Next| {
        let permits = permits.clone();
        async move { answer_bounded(request, next, permits, timeout).await }
    }))
}

async fn answer_bounded(
    request: Request,
    next: Next,
    permits: Arc<Semaphore>,
    timeout: Duration,
) -> Response {
    let mut response = match permits.try_acquire_owned() {
        Err(_) => unavailable("the registry is answering too many requests; retry shortly"),
        Ok(_permit) => match tokio::time::timeout(timeout, next.run(request)).await {
            Ok(response) => response,
            Err(_) => {
                tracing::warn!(
                    timeout_secs = timeout.as_secs(),
                    "an HTTP request was not answered in time"
                );
                unavailable("the request was not answered in time; retry shortly")
            }
        },
    };
    let headers = response.headers_mut();
    headers.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}

/// A `503` problem document asking the client to retry.
fn unavailable(detail: &str) -> Response {
    let body = serde_json::json!({
        "type": "about:blank",
        "title": "service_unavailable",
        "status": StatusCode::SERVICE_UNAVAILABLE.as_u16(),
        "detail": detail,
        "code": StatusCode::SERVICE_UNAVAILABLE.as_u16(),
    });
    (
        StatusCode::SERVICE_UNAVAILABLE,
        [
            (
                header::CONTENT_TYPE,
                HeaderValue::from_static("application/problem+json"),
            ),
            (
                header::RETRY_AFTER,
                HeaderValue::from_static(RETRY_AFTER_SECS),
            ),
        ],
        body.to_string(),
    )
        .into_response()
}

/// A TCP listener that holds at most
/// [`max_connections`](HttpLimits::max_connections) connections and closes one
/// idle for [`idle_timeout`](HttpLimits::idle_timeout).
pub struct BoundedListener {
    inner: TcpListener,
    connections: Arc<Semaphore>,
    idle_timeout: Duration,
}

impl BoundedListener {
    pub fn new(inner: TcpListener, limits: &HttpLimits) -> Self {
        Self {
            inner,
            connections: Arc::new(Semaphore::new(limits.max_connections)),
            idle_timeout: limits.idle_timeout,
        }
    }
}

impl axum::serve::Listener for BoundedListener {
    type Io = IdleTimeoutIo<TcpStream>;
    type Addr = SocketAddr;

    async fn accept(&mut self) -> (Self::Io, Self::Addr) {
        // The semaphore is never closed, so this waits for a free slot.
        let permit = self.connections.clone().acquire_owned().await.ok();
        let (stream, addr) = axum::serve::Listener::accept(&mut self.inner).await;
        (IdleTimeoutIo::new(stream, permit, self.idle_timeout), addr)
    }

    fn local_addr(&self) -> io::Result<Self::Addr> {
        self.inner.local_addr()
    }
}

/// A connection that fails with [`io::ErrorKind::TimedOut`] once it has made
/// no progress, reading or writing, for its idle timeout, and that holds its
/// listener's connection slot until dropped.
pub struct IdleTimeoutIo<S> {
    io: S,
    idle_timeout: Duration,
    deadline: Pin<Box<Sleep>>,
    _slot: Option<OwnedSemaphorePermit>,
}

impl<S> IdleTimeoutIo<S> {
    fn new(io: S, slot: Option<OwnedSemaphorePermit>, idle_timeout: Duration) -> Self {
        Self {
            io,
            idle_timeout,
            deadline: Box::pin(tokio::time::sleep(idle_timeout)),
            _slot: slot,
        }
    }

    fn progressed(&mut self) {
        let next = Instant::now() + self.idle_timeout;
        self.deadline.as_mut().reset(next);
    }

    /// `Pending`, unless the connection has been idle too long.
    fn pending_or_expired<T>(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<T>> {
        match self.deadline.as_mut().poll(cx) {
            Poll::Ready(()) => Poll::Ready(Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "the HTTP connection was idle for too long",
            ))),
            Poll::Pending => Poll::Pending,
        }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for IdleTimeoutIo<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let before = buf.filled().len();
        match Pin::new(&mut this.io).poll_read(cx, buf) {
            Poll::Ready(Ok(())) => {
                if buf.filled().len() > before {
                    this.progressed();
                }
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Pending => this.pending_or_expired(cx),
        }
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for IdleTimeoutIo<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        match Pin::new(&mut this.io).poll_write(cx, buf) {
            Poll::Ready(Ok(written)) => {
                if written > 0 {
                    this.progressed();
                }
                Poll::Ready(Ok(written))
            }
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Pending => this.pending_or_expired(cx),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        match Pin::new(&mut this.io).poll_flush(cx) {
            Poll::Pending => this.pending_or_expired(cx),
            ready => ready,
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().io).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;
    use axum::body::Body;
    use axum::routing::get;
    use std::collections::HashMap;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tower::ServiceExt;

    fn limits_from(vars: &[(&str, &str)]) -> Result<HttpLimits, String> {
        let vars: HashMap<String, String> = vars
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        HttpLimits::parse(|name| vars.get(name).cloned())
    }

    #[test]
    fn limits_default_when_unset() {
        assert_eq!(limits_from(&[]).unwrap(), HttpLimits::default());
    }

    #[test]
    fn limits_are_read_from_their_settings() {
        let limits = limits_from(&[
            ("TR_HTTP_REQUEST_TIMEOUT_SECS", "5"),
            ("TR_HTTP_IDLE_TIMEOUT_SECS", "20"),
            ("TR_HTTP_MAX_BODY_BYTES", "1024"),
            ("TR_HTTP_MAX_CONCURRENT_REQUESTS", "8"),
            ("TR_HTTP_MAX_CONNECTIONS", "16"),
        ])
        .unwrap();
        assert_eq!(
            limits,
            HttpLimits {
                request_timeout: Duration::from_secs(5),
                idle_timeout: Duration::from_secs(20),
                max_body_bytes: 1024,
                max_concurrent_requests: 8,
                max_connections: 16,
            }
        );
    }

    #[test]
    fn malformed_limits_are_an_error() {
        for (name, value) in [
            ("TR_HTTP_REQUEST_TIMEOUT_SECS", "0"),
            ("TR_HTTP_REQUEST_TIMEOUT_SECS", "ten"),
            ("TR_HTTP_MAX_BODY_BYTES", "-1"),
            ("TR_HTTP_MAX_CONCURRENT_REQUESTS", "0"),
            ("TR_HTTP_MAX_CONNECTIONS", "1k"),
        ] {
            assert!(
                limits_from(&[(name, value)]).is_err(),
                "{name}={value} should be refused"
            );
        }
    }

    #[test]
    fn an_idle_timeout_not_longer_than_the_request_timeout_is_an_error() {
        assert!(
            limits_from(&[
                ("TR_HTTP_REQUEST_TIMEOUT_SECS", "30"),
                ("TR_HTTP_IDLE_TIMEOUT_SECS", "30"),
            ])
            .is_err()
        );
    }

    fn limits(request_timeout_ms: u64, max_concurrent_requests: usize) -> HttpLimits {
        HttpLimits {
            request_timeout: Duration::from_millis(request_timeout_ms),
            max_concurrent_requests,
            ..HttpLimits::default()
        }
    }

    #[tokio::test]
    async fn an_answer_is_marked_neither_sniffed_nor_stored() {
        let router = bound_requests(
            Router::new().route("/", get(|| async { "ok" })),
            &HttpLimits::default(),
        );
        let response = router
            .oneshot(Request::get("/").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.headers()[header::X_CONTENT_TYPE_OPTIONS],
            "nosniff"
        );
        assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
    }

    #[tokio::test]
    async fn a_request_not_answered_in_time_is_refused() {
        let router = bound_requests(
            Router::new().route(
                "/",
                get(|| async {
                    tokio::time::sleep(Duration::from_secs(60)).await;
                    "late"
                }),
            ),
            &limits(50, 8),
        );
        let response = router
            .oneshot(Request::get("/").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(response.headers()[header::RETRY_AFTER], "1");
    }

    #[tokio::test]
    async fn requests_beyond_the_limit_are_refused_at_once() {
        let release = Arc::new(tokio::sync::Notify::new());
        let held = release.clone();
        let router = bound_requests(
            Router::new().route(
                "/",
                get(move || {
                    let held = held.clone();
                    async move {
                        held.notified().await;
                        "ok"
                    }
                }),
            ),
            &limits(10_000, 1),
        );
        let first = tokio::spawn(
            router
                .clone()
                .oneshot(Request::get("/").body(Body::empty()).unwrap()),
        );
        tokio::task::yield_now().await;
        tokio::time::sleep(Duration::from_millis(50)).await;

        let second = router
            .clone()
            .oneshot(Request::get("/").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(second.status(), StatusCode::SERVICE_UNAVAILABLE);

        release.notify_one();
        assert_eq!(first.await.unwrap().unwrap().status(), StatusCode::OK);
    }

    async fn serve_bounded(limits: HttpLimits) -> SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let listener = BoundedListener::new(listener, &limits);
        let addr = axum::serve::Listener::local_addr(&listener).unwrap();
        let router = Router::new().route("/", get(|| async { "ok" }));
        tokio::spawn(async move { axum::serve(listener, router).await });
        addr
    }

    /// A connection that sends nothing is closed after the idle timeout.
    #[tokio::test]
    async fn an_idle_connection_is_closed() {
        let addr = serve_bounded(HttpLimits {
            request_timeout: Duration::from_millis(50),
            idle_timeout: Duration::from_millis(200),
            ..HttpLimits::default()
        })
        .await;
        let mut stream = TcpStream::connect(addr).await.unwrap();
        stream
            .write_all(b"GET / HTTP/1.1\r\nHost: x")
            .await
            .unwrap();

        let mut buf = Vec::new();
        let closed = tokio::time::timeout(Duration::from_secs(5), stream.read_to_end(&mut buf))
            .await
            .expect("closed well before the test gives up");
        assert!(closed.is_err() || buf.is_empty() || buf.starts_with(b"HTTP/1.1 4"));
    }

    /// With every connection slot taken, a new connection is not served until
    /// one is released.
    #[tokio::test]
    async fn connections_beyond_the_limit_wait_for_a_slot() {
        let addr = serve_bounded(HttpLimits {
            max_connections: 1,
            request_timeout: Duration::from_millis(100),
            idle_timeout: Duration::from_millis(500),
            ..HttpLimits::default()
        })
        .await;
        let holder = TcpStream::connect(addr).await.unwrap();

        let mut waiting = TcpStream::connect(addr).await.unwrap();
        waiting
            .write_all(b"GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
            .await
            .unwrap();
        let mut buf = [0u8; 16];
        assert!(
            tokio::time::timeout(Duration::from_millis(150), waiting.read(&mut buf))
                .await
                .is_err(),
            "the second connection is not served while the first holds the slot"
        );

        drop(holder);
        let mut answer = Vec::new();
        tokio::time::timeout(Duration::from_secs(5), waiting.read_to_end(&mut answer))
            .await
            .expect("served once the slot is free")
            .unwrap();
        assert!(answer.starts_with(b"HTTP/1.1 200"));
    }
}
