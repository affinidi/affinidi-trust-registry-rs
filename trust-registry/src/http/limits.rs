//! Resource limits for the HTTP surface.
//!
//! Every route the registry serves over HTTP is unauthenticated, so each
//! request, and each connection, is bounded:
//!
//! - **body size** ([`HttpLimits::max_body_bytes`]): applied by
//!   [`application_routes`](crate::http::application_routes) itself, so a host
//!   mounting [`TrustRegistry::router`](crate::TrustRegistry::router) gets it
//!   too. A larger body is answered `413`, in the shape of the route's other
//!   errors;
//! - **body time** and **request time** ([`HttpLimits::request_timeout`]): the
//!   body must arrive within it (else `408`), and is read *before* the request
//!   takes one of the in-flight slots, so a slow sender holds only its own
//!   connection; the answer must then be ready within it too (else `503`, the
//!   work dropped), for example behind a stalled storage backend;
//! - **requests in flight** ([`HttpLimits::max_concurrent_requests`]): a
//!   request beyond the limit is answered `503` with `Retry-After` at once
//!   rather than queued. `/health` is exempt, so a busy registry can still be
//!   probed;
//! - **open connections** ([`HttpLimits::max_connections`]): beyond the limit
//!   the listener stops accepting until one closes;
//! - **request headers** ([`HttpLimits::header_timeout`]): a request's headers
//!   must be complete within this long of the connection opening, or of the
//!   first byte of the next request on a kept-alive connection. The deadline
//!   does not move as bytes arrive, so a client cannot hold a connection by
//!   trickling them;
//! - **idle connections** ([`HttpLimits::idle_timeout`]): a connection that
//!   neither sends nor accepts a byte for this long is closed, which also
//!   covers a client that reads its answer too slowly to make progress;
//! - **connection age** ([`HttpLimits::max_connection_age`]): once past it, a
//!   connection is closed while it waits for a request's headers; a request
//!   already being answered is let finish, up to twice the request timeout
//!   beyond the age.
//!
//! All but the body limit are applied by the standalone service
//! ([`crate::server`]); a host serving the router itself owns its server and
//! applies its own. The header deadline reads HTTP/1.1 framing (the server
//! speaks nothing else). Enabling axum's `http2` feature would need it
//! revisited: the HTTP/2 connection preface (`PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n`)
//! contains a blank line, which would read as the end of a request's headers.

use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use axum::Json;
use axum::Router;
use axum::body::{Body, Bytes};
use axum::extract::Request;
use axum::http::{HeaderValue, StatusCode, header};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tokio::time::{Instant, Sleep};

use crate::http::error::AppError;

/// Default for [`HttpLimits::request_timeout`].
pub const DEFAULT_REQUEST_TIMEOUT: Duration = Duration::from_secs(10);
/// Default for [`HttpLimits::header_timeout`].
pub const DEFAULT_HEADER_TIMEOUT: Duration = Duration::from_secs(15);
/// Default for [`HttpLimits::idle_timeout`].
pub const DEFAULT_IDLE_TIMEOUT: Duration = Duration::from_secs(30);
/// Default for [`HttpLimits::max_connection_age`].
pub const DEFAULT_MAX_CONNECTION_AGE: Duration = Duration::from_secs(300);
/// Default for [`HttpLimits::max_body_bytes`]: room for a signed Trust Task
/// or a TRQP query with its context, well short of axum's 2 MB.
pub const DEFAULT_MAX_BODY_BYTES: usize = 64 * 1024;
/// Default for [`HttpLimits::max_concurrent_requests`].
pub const DEFAULT_MAX_CONCURRENT_REQUESTS: usize = 256;
/// Default for [`HttpLimits::max_connections`].
pub const DEFAULT_MAX_CONNECTIONS: usize = 1024;

/// How long a client told the service is busy should wait, in seconds.
const RETRY_AFTER_SECS: &str = "1";

/// The path exempt from the request limits.
const HEALTH_PATH: &str = "/health";

/// Bounds on what one HTTP client can make the registry hold.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HttpLimits {
    /// The longest a request body may take to arrive, and then the longest
    /// its answer may take.
    pub request_timeout: Duration,
    /// The longest a request's headers may take to arrive.
    pub header_timeout: Duration,
    /// The longest a connection may make no progress before it is closed.
    /// Longer than `request_timeout`, so a request being answered is never
    /// cut off as idle.
    pub idle_timeout: Duration,
    /// The longest a connection is kept open. Longer than `request_timeout`.
    pub max_connection_age: Duration,
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
            header_timeout: DEFAULT_HEADER_TIMEOUT,
            idle_timeout: DEFAULT_IDLE_TIMEOUT,
            max_connection_age: DEFAULT_MAX_CONNECTION_AGE,
            max_body_bytes: DEFAULT_MAX_BODY_BYTES,
            max_concurrent_requests: DEFAULT_MAX_CONCURRENT_REQUESTS,
            max_connections: DEFAULT_MAX_CONNECTIONS,
        }
    }
}

impl HttpLimits {
    /// Read `TR_HTTP_REQUEST_TIMEOUT_SECS`, `TR_HTTP_HEADER_TIMEOUT_SECS`,
    /// `TR_HTTP_IDLE_TIMEOUT_SECS`, `TR_HTTP_MAX_CONNECTION_AGE_SECS`,
    /// `TR_HTTP_MAX_BODY_BYTES`, `TR_HTTP_MAX_CONCURRENT_REQUESTS` and
    /// `TR_HTTP_MAX_CONNECTIONS`, each defaulting when unset.
    ///
    /// A value that is not a positive whole number, or an idle timeout or
    /// connection age not longer than the request timeout, is an error rather
    /// than a silent default, so a typo cannot lift a limit.
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
        let secs = |name: &str, default: Duration| -> Result<Duration, String> {
            Ok(positive(name)?.map_or(default, Duration::from_secs))
        };
        let defaults = Self::default();
        let limits = Self {
            request_timeout: secs("TR_HTTP_REQUEST_TIMEOUT_SECS", defaults.request_timeout)?,
            header_timeout: secs("TR_HTTP_HEADER_TIMEOUT_SECS", defaults.header_timeout)?,
            idle_timeout: secs("TR_HTTP_IDLE_TIMEOUT_SECS", defaults.idle_timeout)?,
            max_connection_age: secs(
                "TR_HTTP_MAX_CONNECTION_AGE_SECS",
                defaults.max_connection_age,
            )?,
            max_body_bytes: count("TR_HTTP_MAX_BODY_BYTES")?.unwrap_or(defaults.max_body_bytes),
            max_concurrent_requests: count("TR_HTTP_MAX_CONCURRENT_REQUESTS")?
                .unwrap_or(defaults.max_concurrent_requests),
            max_connections: count("TR_HTTP_MAX_CONNECTIONS")?.unwrap_or(defaults.max_connections),
        };
        for (name, value) in [
            ("TR_HTTP_IDLE_TIMEOUT_SECS", limits.idle_timeout),
            ("TR_HTTP_MAX_CONNECTION_AGE_SECS", limits.max_connection_age),
        ] {
            if value <= limits.request_timeout {
                return Err(format!(
                    "{name} ({}) must be longer than TR_HTTP_REQUEST_TIMEOUT_SECS ({})",
                    value.as_secs(),
                    limits.request_timeout.as_secs()
                ));
            }
        }
        Ok(limits)
    }
}

/// Bound the requests `router` answers: each body read within
/// [`request_timeout`](HttpLimits::request_timeout) and
/// [`max_body_bytes`](HttpLimits::max_body_bytes) before the request takes a
/// slot, then at most
/// [`max_concurrent_requests`](HttpLimits::max_concurrent_requests) answered at
/// once, each within `request_timeout`. `/health` is exempt. Every answer is
/// marked as neither to be sniffed nor stored.
pub fn bound_requests(router: Router, limits: &HttpLimits) -> Router {
    let permits = Arc::new(Semaphore::new(limits.max_concurrent_requests));
    let limits = *limits;
    router.layer(middleware::from_fn(move |request: Request, next: Next| {
        let permits = permits.clone();
        async move {
            let mut response = if request.uri().path() == HEALTH_PATH {
                next.run(request).await
            } else {
                answer_bounded(request, next, permits, limits).await
            };
            let headers = response.headers_mut();
            headers.insert(
                header::X_CONTENT_TYPE_OPTIONS,
                HeaderValue::from_static("nosniff"),
            );
            headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
            response
        }
    }))
}

async fn answer_bounded(
    request: Request,
    next: Next,
    permits: Arc<Semaphore>,
    limits: HttpLimits,
) -> Response {
    let (parts, body) = request.into_parts();
    let path = parts.uri.path().to_string();
    let declared_too_large = parts
        .headers
        .get(header::CONTENT_LENGTH)
        .and_then(|length| length.to_str().ok())
        .and_then(|length| length.parse::<u64>().ok())
        .is_some_and(|length| length > limits.max_body_bytes as u64);
    if declared_too_large {
        return too_large(&path, limits.max_body_bytes);
    }
    let bytes = match tokio::time::timeout(
        limits.request_timeout,
        read_capped(body, limits.max_body_bytes),
    )
    .await
    {
        Ok(Ok(Some(bytes))) => bytes,
        Ok(Ok(None)) => return too_large(&path, limits.max_body_bytes),
        Ok(Err(_)) => {
            return problem(
                StatusCode::BAD_REQUEST,
                "bad_request",
                "the request body could not be read",
            );
        }
        Err(_) => {
            return problem(
                StatusCode::REQUEST_TIMEOUT,
                "request_timeout",
                "the request body did not arrive in time",
            );
        }
    };
    let request = Request::from_parts(parts, Body::from(bytes));

    let Ok(_permit) = permits.try_acquire_owned() else {
        return unavailable("the registry is answering too many requests; retry shortly");
    };
    match tokio::time::timeout(limits.request_timeout, next.run(request)).await {
        Ok(response) => response,
        Err(_) => {
            tracing::warn!(
                timeout_secs = limits.request_timeout.as_secs(),
                "an HTTP request was not answered in time"
            );
            unavailable("the request was not answered in time; retry shortly")
        }
    }
}

/// Read `body` whole, or `None` once it exceeds `max_bytes`.
async fn read_capped(body: Body, max_bytes: usize) -> Result<Option<Bytes>, axum::Error> {
    use futures::StreamExt;
    let mut stream = body.into_data_stream();
    let mut collected = Vec::new();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk?;
        if collected.len() + chunk.len() > max_bytes {
            return Ok(None);
        }
        collected.extend_from_slice(&chunk);
    }
    Ok(Some(Bytes::from(collected)))
}

/// A body over the limit, answered in the shape of the route's other errors:
/// the Trust Task binding's `{code, message}`, or a TRQP problem document.
fn too_large(path: &str, max_bytes: usize) -> Response {
    if path.ends_with("/trust-tasks") {
        trust_task_too_large(max_bytes)
    } else {
        AppError::PayloadTooLarge { max_bytes }.into_response()
    }
}

/// `413` for `POST /trust-tasks`, in the shape that route gives every document
/// it cannot read: `{"code": "malformedRequest", "message": …}`.
pub(crate) fn trust_task_too_large(max_bytes: usize) -> Response {
    (
        StatusCode::PAYLOAD_TOO_LARGE,
        Json(serde_json::json!({
            "code": "malformedRequest",
            "message": format!("the Trust Task document is larger than {max_bytes} bytes"),
        })),
    )
        .into_response()
}

/// A problem document with `status`.
fn problem(status: StatusCode, title: &str, detail: &str) -> Response {
    let body = serde_json::json!({
        "type": "about:blank",
        "title": title,
        "status": status.as_u16(),
        "detail": detail,
        "code": status.as_u16(),
    });
    (
        status,
        [(
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/problem+json"),
        )],
        body.to_string(),
    )
        .into_response()
}

/// A `503` problem document asking the client to retry.
fn unavailable(detail: &str) -> Response {
    let mut response = problem(
        StatusCode::SERVICE_UNAVAILABLE,
        "service_unavailable",
        detail,
    );
    response.headers_mut().insert(
        header::RETRY_AFTER,
        HeaderValue::from_static(RETRY_AFTER_SECS),
    );
    response
}

/// A TCP listener that holds at most
/// [`max_connections`](HttpLimits::max_connections) connections, each under the
/// deadlines of [`ConnectionLimitsIo`].
pub struct BoundedListener {
    inner: TcpListener,
    connections: Arc<Semaphore>,
    limits: HttpLimits,
}

impl BoundedListener {
    pub fn new(inner: TcpListener, limits: &HttpLimits) -> Self {
        Self {
            inner,
            connections: Arc::new(Semaphore::new(limits.max_connections)),
            limits: *limits,
        }
    }
}

impl axum::serve::Listener for BoundedListener {
    type Io = ConnectionLimitsIo<TcpStream>;
    type Addr = SocketAddr;

    async fn accept(&mut self) -> (Self::Io, Self::Addr) {
        // The semaphore is never closed, so this waits for a free slot.
        let permit = self.connections.clone().acquire_owned().await.ok();
        let (stream, addr) = axum::serve::Listener::accept(&mut self.inner).await;
        (ConnectionLimitsIo::new(stream, permit, &self.limits), addr)
    }

    fn local_addr(&self) -> io::Result<Self::Addr> {
        self.inner.local_addr()
    }
}

/// A connection that fails with [`io::ErrorKind::TimedOut`] once
///
/// - a request's headers have not completed within the header timeout of the
///   connection opening, or of the first byte read after the previous answer
///   (the deadline does not move as bytes arrive),
/// - it has made no progress, reading or writing, for the idle timeout,
/// - it is past the maximum connection age while awaiting a request's
///   headers, or
/// - it is past the age by twice the request timeout, whatever it is doing,
///
/// and that holds its listener's connection slot until dropped.
pub struct ConnectionLimitsIo<S> {
    io: S,
    header_timeout: Duration,
    idle_timeout: Duration,
    idle_at: Instant,
    phase: Phase,
    /// Past this, the connection closes while awaiting headers.
    close_at: Instant,
    /// Past this, the connection closes whatever it is doing.
    hard_close_at: Instant,
    timer: Pin<Box<Sleep>>,
    _slot: Option<OwnedSemaphorePermit>,
}

/// Where a connection is in its request/answer cycle, as far as its bytes
/// show.
enum Phase {
    /// Reading a request's headers, which must be complete by `due`.
    /// `started` once a byte other than the CR/LF a parser skips before the
    /// request line has arrived; `tail` keeps the last bytes, to find the
    /// blank line that ends the headers across reads.
    AwaitingHead {
        due: Instant,
        started: bool,
        tail: Vec<u8>,
    },
    /// The headers are complete; the body and the answer are under way.
    InRequest,
    /// An answer has been written; the next byte read starts a request.
    Answered,
}

/// The blank line that ends a request's headers, in the forms an HTTP/1.1
/// parser accepts (`\r\n\r\n`, and bare-LF `\n\n` or `\r\n\n`).
fn ends_headers(bytes: &[u8]) -> bool {
    bytes.windows(2).any(|w| w == b"\n\n") || bytes.windows(3).any(|w| w == b"\n\r\n")
}

impl<S> ConnectionLimitsIo<S> {
    fn new(io: S, slot: Option<OwnedSemaphorePermit>, limits: &HttpLimits) -> Self {
        let now = Instant::now();
        let close_at = now + limits.max_connection_age;
        let mut this = Self {
            io,
            header_timeout: limits.header_timeout,
            idle_timeout: limits.idle_timeout,
            idle_at: now + limits.idle_timeout,
            phase: Phase::AwaitingHead {
                due: now + limits.header_timeout,
                started: false,
                tail: Vec::new(),
            },
            close_at,
            hard_close_at: close_at + limits.request_timeout * 2,
            timer: Box::pin(tokio::time::sleep_until(now)),
            _slot: slot,
        };
        this.rearm();
        this
    }

    fn next_deadline(&self) -> Instant {
        let next = self.idle_at.min(self.hard_close_at);
        match &self.phase {
            Phase::AwaitingHead { due, .. } => next.min(*due).min(self.close_at),
            Phase::InRequest | Phase::Answered => next,
        }
    }

    fn rearm(&mut self) {
        let next = self.next_deadline();
        if self.timer.deadline() != next {
            self.timer.as_mut().reset(next);
        }
    }

    /// The deadline that has passed, if any.
    fn expired(&self) -> Option<io::Error> {
        let now = Instant::now();
        let awaiting_due = match &self.phase {
            Phase::AwaitingHead { due, .. } => Some(*due),
            Phase::InRequest | Phase::Answered => None,
        };
        let reason = if awaiting_due.is_some_and(|due| now >= due) {
            "the request headers did not arrive in time"
        } else if awaiting_due.is_some() && now >= self.close_at {
            "the HTTP connection reached its maximum age"
        } else if now >= self.idle_at {
            "the HTTP connection was idle for too long"
        } else if now >= self.hard_close_at {
            "the HTTP connection outlived its maximum age"
        } else {
            return None;
        };
        Some(io::Error::new(io::ErrorKind::TimedOut, reason))
    }

    fn read_progress(&mut self, bytes: &[u8]) {
        let now = Instant::now();
        self.idle_at = now + self.idle_timeout;
        if matches!(self.phase, Phase::Answered) {
            self.phase = Phase::AwaitingHead {
                due: now + self.header_timeout,
                started: false,
                tail: Vec::new(),
            };
        }
        if let Phase::AwaitingHead { started, tail, .. } = &mut self.phase {
            let mut bytes = bytes;
            if !*started {
                bytes = match bytes.iter().position(|b| *b != b'\r' && *b != b'\n') {
                    Some(first) => {
                        *started = true;
                        &bytes[first..]
                    }
                    None => &[],
                };
            }
            tail.extend_from_slice(bytes);
            if ends_headers(tail) {
                self.phase = Phase::InRequest;
            } else {
                let keep = tail.len().saturating_sub(2);
                tail.drain(..keep);
            }
        }
        self.rearm();
    }

    fn write_progress(&mut self, written: &[u8]) {
        self.idle_at = Instant::now() + self.idle_timeout;
        // An answer (not an interim `1xx`) ends the request; the wait for the
        // next one's headers starts when its first byte is read, so a slow
        // reader of a long answer is not cut off.
        if matches!(self.phase, Phase::InRequest) && !written.starts_with(b"HTTP/1.1 1") {
            self.phase = Phase::Answered;
        }
        self.rearm();
    }

    /// `Pending`, unless a deadline has passed.
    fn pending_or_expired<T>(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<T>> {
        loop {
            if let Some(e) = self.expired() {
                return Poll::Ready(Err(e));
            }
            match self.timer.as_mut().poll(cx) {
                Poll::Pending => return Poll::Pending,
                // The deadline it slept to may since have moved: re-check.
                Poll::Ready(()) => {
                    let next = self.next_deadline();
                    self.timer.as_mut().reset(next);
                }
            }
        }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for ConnectionLimitsIo<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if let Some(e) = this.expired() {
            return Poll::Ready(Err(e));
        }
        let before = buf.filled().len();
        match Pin::new(&mut this.io).poll_read(cx, buf) {
            Poll::Ready(Ok(())) => {
                if buf.filled().len() > before {
                    let read = buf.filled()[before..].to_vec();
                    this.read_progress(&read);
                }
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Pending => this.pending_or_expired(cx),
        }
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for ConnectionLimitsIo<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        match Pin::new(&mut this.io).poll_write(cx, buf) {
            Poll::Ready(Ok(written)) => {
                if written > 0 {
                    this.write_progress(&buf[..written]);
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
            ("TR_HTTP_HEADER_TIMEOUT_SECS", "3"),
            ("TR_HTTP_IDLE_TIMEOUT_SECS", "20"),
            ("TR_HTTP_MAX_CONNECTION_AGE_SECS", "60"),
            ("TR_HTTP_MAX_BODY_BYTES", "1024"),
            ("TR_HTTP_MAX_CONCURRENT_REQUESTS", "8"),
            ("TR_HTTP_MAX_CONNECTIONS", "16"),
        ])
        .unwrap();
        assert_eq!(
            limits,
            HttpLimits {
                request_timeout: Duration::from_secs(5),
                header_timeout: Duration::from_secs(3),
                idle_timeout: Duration::from_secs(20),
                max_connection_age: Duration::from_secs(60),
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
    fn a_timeout_not_longer_than_the_request_timeout_is_an_error() {
        for name in [
            "TR_HTTP_IDLE_TIMEOUT_SECS",
            "TR_HTTP_MAX_CONNECTION_AGE_SECS",
        ] {
            assert!(
                limits_from(&[("TR_HTTP_REQUEST_TIMEOUT_SECS", "30"), (name, "30")]).is_err(),
                "{name}"
            );
        }
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
        serve_bounded_with(limits, Router::new().route("/", get(|| async { "ok" }))).await
    }

    async fn serve_bounded_with(limits: HttpLimits, router: Router) -> SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let listener = BoundedListener::new(listener, &limits);
        let addr = axum::serve::Listener::local_addr(&listener).unwrap();
        tokio::spawn(async move { axum::serve(listener, router).await });
        addr
    }

    fn awaiting_head(io: &ConnectionLimitsIo<()>) -> bool {
        matches!(io.phase, Phase::AwaitingHead { .. })
    }

    /// Blank lines before the request line, which a parser skips, do not
    /// count as the end of the headers; the headers' own blank line does, in
    /// every form a parser accepts.
    #[tokio::test]
    async fn the_end_of_headers_is_found_only_after_the_request_line() {
        let limits = HttpLimits::default();
        let mut io = ConnectionLimitsIo::new((), None, &limits);
        io.read_progress(b"\r\n\r\n\n\n");
        assert!(awaiting_head(&io), "leading blank lines end nothing");
        io.read_progress(b"GET / HTTP/1.1\r\nHost: x\r");
        assert!(awaiting_head(&io));
        io.read_progress(b"\n\r\n");
        assert!(!awaiting_head(&io), "split across reads");

        for request in [
            &b"GET / HTTP/1.1\nHost: x\n\n"[..],
            &b"GET / HTTP/1.1\r\nHost: x\r\n\n"[..],
            &b"\r\nGET / HTTP/1.1\r\nHost: x\r\n\r\n"[..],
        ] {
            let mut io = ConnectionLimitsIo::new((), None, &limits);
            io.read_progress(request);
            assert!(
                !awaiting_head(&io),
                "{:?}",
                String::from_utf8_lossy(request)
            );
        }
    }

    /// The next request's header deadline starts at its first byte, not at
    /// the answer, so a slow reader of an answer is not cut off; an interim
    /// `1xx` does not end the request.
    #[tokio::test]
    async fn the_next_header_deadline_starts_at_the_next_request() {
        let mut io = ConnectionLimitsIo::new((), None, &HttpLimits::default());
        io.read_progress(b"POST / HTTP/1.1\r\nExpect: 100-continue\r\n\r\n");
        io.write_progress(b"HTTP/1.1 100 Continue\r\n\r\n");
        assert!(matches!(io.phase, Phase::InRequest));
        io.read_progress(b"{\"body\":1}");
        assert!(
            matches!(io.phase, Phase::InRequest),
            "body bytes are not a head"
        );
        io.write_progress(b"HTTP/1.1 200 OK\r\n");
        assert!(matches!(io.phase, Phase::Answered));
        io.write_progress(b"more of a long answer");
        assert!(
            matches!(io.phase, Phase::Answered),
            "no deadline while answering"
        );
        io.read_progress(b"G");
        assert!(awaiting_head(&io));
    }

    /// Blank lines sent ahead of trickled headers do not stop the header
    /// deadline.
    #[tokio::test]
    async fn leading_blank_lines_do_not_lift_the_header_deadline() {
        let addr = serve_bounded(HttpLimits {
            request_timeout: Duration::from_millis(100),
            header_timeout: Duration::from_millis(400),
            idle_timeout: Duration::from_secs(5),
            ..HttpLimits::default()
        })
        .await;
        let mut stream = TcpStream::connect(addr).await.unwrap();
        stream.write_all(b"\r\n\r\n").await.unwrap();
        let started = Instant::now();
        let mut closed = false;
        for byte in b"GET / HTTP/1.1\r\nHost: x\r\nX-Slow: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" {
            if stream.write_all(&[*byte]).await.is_err() {
                closed = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
            let mut probe = [0u8; 1];
            if let Ok(Ok(0) | Err(_)) =
                tokio::time::timeout(Duration::from_millis(1), stream.read(&mut probe)).await
            {
                closed = true;
                break;
            }
        }
        assert!(closed, "the connection was closed");
        assert!(started.elapsed() < Duration::from_secs(2));
    }

    /// A request accepted just before the connection's maximum age is
    /// answered in full; the age closes the connection only between
    /// requests.
    #[tokio::test]
    async fn a_request_accepted_near_the_maximum_age_is_answered() {
        let addr = serve_bounded_with(
            HttpLimits {
                request_timeout: Duration::from_millis(200),
                header_timeout: Duration::from_secs(5),
                idle_timeout: Duration::from_secs(5),
                max_connection_age: Duration::from_millis(300),
                ..HttpLimits::default()
            },
            Router::new().route(
                "/",
                get(|| async {
                    tokio::time::sleep(Duration::from_millis(150)).await;
                    "ok"
                }),
            ),
        )
        .await;
        let mut stream = TcpStream::connect(addr).await.unwrap();
        tokio::time::sleep(Duration::from_millis(250)).await;
        stream
            .write_all(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n")
            .await
            .unwrap();
        let mut answer = Vec::new();
        while !answer.ends_with(b"\r\n\r\nok") {
            let mut buf = [0u8; 256];
            let read = tokio::time::timeout(Duration::from_secs(2), stream.read(&mut buf))
                .await
                .unwrap()
                .unwrap();
            assert!(read > 0, "the answer was cut off");
            answer.extend_from_slice(&buf[..read]);
        }
        assert!(answer.starts_with(b"HTTP/1.1 200"));
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

    fn post(path: &str, body: Vec<u8>) -> Request {
        Request::post(path).body(Body::from(body)).unwrap()
    }

    fn echo_routes() -> Router {
        Router::new()
            .route("/trust-tasks", axum::routing::post(|| async { "ok" }))
            .route("/recognition", axum::routing::post(|| async { "ok" }))
    }

    async fn json_of(response: Response) -> serde_json::Value {
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        serde_json::from_slice(&bytes).unwrap()
    }

    /// A body over the limit is answered `413` in the route's own error shape,
    /// whether or not it declares its length.
    #[tokio::test]
    async fn an_oversized_body_is_answered_in_the_routes_shape() {
        let limits = HttpLimits {
            max_body_bytes: 1024,
            ..HttpLimits::default()
        };
        let router = bound_requests(echo_routes(), &limits);
        for declared in [true, false] {
            let make = |path: &str| {
                let body = vec![b'x'; 2048];
                if declared {
                    post(path, body)
                } else {
                    let stream = futures::stream::iter(vec![Ok::<_, std::io::Error>(
                        axum::body::Bytes::from(body),
                    )]);
                    Request::post(path).body(Body::from_stream(stream)).unwrap()
                }
            };
            let response = router.clone().oneshot(make("/trust-tasks")).await.unwrap();
            assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
            assert_eq!(json_of(response).await["code"], "malformedRequest");

            let response = router.clone().oneshot(make("/recognition")).await.unwrap();
            assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
            assert_eq!(
                response.headers()[header::CONTENT_TYPE],
                "application/problem+json"
            );
            assert_eq!(json_of(response).await["status"], 413);
        }

        let response = router
            .clone()
            .oneshot(post("/recognition", vec![b'x'; 512]))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    /// A body that does not arrive in time is answered `408`, and while it is
    /// awaited it holds none of the in-flight slots.
    #[tokio::test]
    async fn a_slow_body_holds_no_request_slot() {
        let router = bound_requests(echo_routes(), &limits(200, 1));
        let (_sender, body) =
            tokio::sync::mpsc::channel::<Result<axum::body::Bytes, std::io::Error>>(1);
        let slow = tokio::spawn(
            router.clone().oneshot(
                Request::post("/recognition")
                    .body(Body::from_stream(tokio_stream_of(body)))
                    .unwrap(),
            ),
        );
        tokio::time::sleep(Duration::from_millis(50)).await;

        let quick = router
            .clone()
            .oneshot(post("/recognition", b"{}".to_vec()))
            .await
            .unwrap();
        assert_eq!(
            quick.status(),
            StatusCode::OK,
            "the slow body holds no slot"
        );
        assert_eq!(
            slow.await.unwrap().unwrap().status(),
            StatusCode::REQUEST_TIMEOUT
        );
    }

    fn tokio_stream_of(
        mut receiver: tokio::sync::mpsc::Receiver<Result<axum::body::Bytes, std::io::Error>>,
    ) -> impl futures::Stream<Item = Result<axum::body::Bytes, std::io::Error>> {
        futures::stream::poll_fn(move |cx| receiver.poll_recv(cx))
    }

    /// `/health` answers even when every request slot is taken.
    #[tokio::test]
    async fn health_is_exempt_from_the_request_limit() {
        let release = Arc::new(tokio::sync::Notify::new());
        let held = release.clone();
        let router = bound_requests(
            Router::new()
                .route(
                    "/slow",
                    get(move || {
                        let held = held.clone();
                        async move {
                            held.notified().await;
                            "ok"
                        }
                    }),
                )
                .route("/health", get(|| async { "up" })),
            &limits(10_000, 1),
        );
        let first = tokio::spawn(
            router
                .clone()
                .oneshot(Request::get("/slow").body(Body::empty()).unwrap()),
        );
        tokio::time::sleep(Duration::from_millis(50)).await;

        let health = router
            .clone()
            .oneshot(Request::get("/health").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(health.status(), StatusCode::OK);
        assert_eq!(health.headers()[header::CACHE_CONTROL], "no-store");

        release.notify_one();
        first.await.unwrap().unwrap();
    }

    /// A client that keeps sending header bytes, each well inside the idle
    /// timeout, is still cut off at the header deadline.
    #[tokio::test]
    async fn trickled_headers_are_cut_off_at_the_header_deadline() {
        let addr = serve_bounded(HttpLimits {
            request_timeout: Duration::from_millis(100),
            header_timeout: Duration::from_millis(400),
            idle_timeout: Duration::from_secs(5),
            ..HttpLimits::default()
        })
        .await;
        let mut stream = TcpStream::connect(addr).await.unwrap();
        let started = Instant::now();
        let mut closed = false;
        for byte in b"GET / HTTP/1.1\r\nHost: x\r\nX-Slow: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" {
            if stream.write_all(&[*byte]).await.is_err() {
                closed = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
            let mut probe = [0u8; 1];
            if let Ok(Ok(0) | Err(_)) =
                tokio::time::timeout(Duration::from_millis(1), stream.read(&mut probe)).await
            {
                closed = true;
                break;
            }
        }
        assert!(closed, "the connection was closed");
        assert!(
            started.elapsed() < Duration::from_secs(2),
            "closed near the header deadline, not after the trickle"
        );
    }

    /// Headers that complete in time are answered, and on a kept-alive
    /// connection the next request gets its own header deadline.
    #[tokio::test]
    async fn requests_on_a_kept_alive_connection_are_served() {
        let addr = serve_bounded(HttpLimits {
            request_timeout: Duration::from_millis(100),
            header_timeout: Duration::from_millis(300),
            idle_timeout: Duration::from_secs(5),
            ..HttpLimits::default()
        })
        .await;
        let mut stream = TcpStream::connect(addr).await.unwrap();
        for _ in 0..2 {
            stream
                .write_all(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n")
                .await
                .unwrap();
            // Read the whole answer: its head, then the `ok` body.
            let mut answer = Vec::new();
            while !answer.ends_with(b"\r\n\r\nok") {
                let mut buf = [0u8; 256];
                let read = tokio::time::timeout(Duration::from_secs(2), stream.read(&mut buf))
                    .await
                    .unwrap()
                    .unwrap();
                assert!(read > 0, "the connection stayed open");
                answer.extend_from_slice(&buf[..read]);
            }
            assert!(answer.starts_with(b"HTTP/1.1 200"));
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
    }

    /// No connection outlives the maximum age, however active.
    #[tokio::test]
    async fn a_connection_is_closed_at_its_maximum_age() {
        let addr = serve_bounded(HttpLimits {
            request_timeout: Duration::from_millis(50),
            header_timeout: Duration::from_secs(5),
            idle_timeout: Duration::from_secs(5),
            max_connection_age: Duration::from_millis(300),
            ..HttpLimits::default()
        })
        .await;
        let mut stream = TcpStream::connect(addr).await.unwrap();
        stream
            .write_all(b"GET / HTTP/1.1\r\nHost: x")
            .await
            .unwrap();
        let mut buf = Vec::new();
        tokio::time::timeout(Duration::from_secs(2), stream.read_to_end(&mut buf))
            .await
            .expect("closed at the maximum age")
            .ok();
    }
}
