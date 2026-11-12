//! HTTPS binding: `POST <registry>/trust-tasks` per the `trust-tasks-https`
//! wire contract (JSON body = the request document; a 2xx body is the reply
//! document, a non-2xx body is a `trust-task-error` document).
//!
//! Implemented directly on `reqwest` rather than `trust_tasks_https::HttpsClient`:
//! that client's typed `send` bounds (`Payload` on both sides) don't admit the
//! untyped `TrustTask<Value>` seam this crate routes every binding through.
//! (Its historical lack of timeouts was fixed upstream in trust-tasks-https
//! 0.2.1.) The wire contract is identical and is pinned by the round-trip
//! test against an in-process server.
//!
//! The registry URL often comes from a DID document (see
//! [`crate::ServiceCapabilities`]), so the transport treats it as externally
//! supplied: it requires `https` (plain `http` only to a loopback host unless
//! [`HttpsTransportConfig::allow_insecure_http`] is set), never follows a
//! redirect, reads at most [`HttpsTransportConfig::max_response_bytes`] of a
//! reply, and copies at most [`MAX_ERROR_DETAIL_CHARS`] characters of an
//! unparseable error body into the returned error. It also refuses to
//! connect to loopback, private, link-local and other non-public addresses
//! unless [`HttpsTransportConfig::allow_non_public_addresses`] is set, which
//! is how to reach a registry on a private network.
//!
//! The address check covers every connection: an IP literal in the base URL
//! is checked when the transport is built (the endpoint is fixed for the
//! transport's life and redirects are not followed, and the connector never
//! passes a literal to the resolver), and a host name is resolved by
//! the transport's own resolver for each new connection, which refuses the name
//! if any address it resolves to is not public and hands the connector only
//! the addresses it checked, so the connection is made to one of those.

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use serde_json::Value;
use trust_tasks_rs::TrustTask;

use crate::error::TrqlError;
use crate::transport::{TransportKind, TrqlTransport};

/// Default cap on a reply body: 64 KiB. A registry reply is a small JSON
/// document.
pub const DEFAULT_MAX_RESPONSE_BYTES: usize = 64 * 1024;

/// How many characters of a non-Trust-Task error body are copied into
/// [`TrqlError::Transport`]'s `detail`.
pub const MAX_ERROR_DETAIL_CHARS: usize = 256;

/// Configuration for [`HttpsTransport`].
///
/// Build it with [`HttpsTransportConfig::new`] and adjust the fields.
#[derive(Clone)]
#[non_exhaustive]
pub struct HttpsTransportConfig {
    /// Base URL of the registry, e.g. `https://registry.example.com` — the
    /// transport POSTs to `<base>/trust-tasks`.
    pub base_url: String,
    /// End-to-end request timeout.
    pub timeout: Duration,
    /// Connection-establishment timeout.
    pub connect_timeout: Duration,
    /// Optional bearer token (`Authorization: Bearer <token>`). Redacted in
    /// the `Debug` output.
    pub bearer_token: Option<String>,
    /// Allow a plain `http://` base URL to any host. Off by default: `http`
    /// is then accepted only for `localhost` and loopback addresses.
    pub allow_insecure_http: bool,
    /// Largest reply body read, in bytes; a larger reply is refused.
    /// Default [`DEFAULT_MAX_RESPONSE_BYTES`].
    pub max_response_bytes: usize,
    /// Allow connecting to loopback, private, link-local, shared, multicast
    /// and other non-public addresses. Off by default: the transport then
    /// refuses an IP literal in the URL that is not public, and a host name
    /// any of whose addresses is not public, and it connects directly,
    /// ignoring proxy settings from the environment (a proxy would connect
    /// on its behalf). Set it to reach a registry on a private network or on
    /// this machine, or to go through a proxy, and only for a base URL you
    /// trust, not one taken from a DID document you do not control.
    pub allow_non_public_addresses: bool,
}

impl HttpsTransportConfig {
    /// Defaults: 30s request timeout, 10s connect timeout, no bearer token,
    /// `https` required (except to loopback), 64 KiB reply cap, non-public
    /// addresses refused.
    pub fn new(base_url: impl Into<String>) -> Self {
        Self {
            base_url: base_url.into(),
            timeout: Duration::from_secs(30),
            connect_timeout: Duration::from_secs(10),
            bearer_token: None,
            allow_insecure_http: false,
            max_response_bytes: DEFAULT_MAX_RESPONSE_BYTES,
            allow_non_public_addresses: false,
        }
    }
}

impl fmt::Debug for HttpsTransportConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HttpsTransportConfig")
            .field("base_url", &self.base_url)
            .field("timeout", &self.timeout)
            .field("connect_timeout", &self.connect_timeout)
            .field("bearer_token", &self.bearer_token.as_ref().map(|_| "***"))
            .field("allow_insecure_http", &self.allow_insecure_http)
            .field("max_response_bytes", &self.max_response_bytes)
            .field(
                "allow_non_public_addresses",
                &self.allow_non_public_addresses,
            )
            .finish()
    }
}

/// [`TrqlTransport`] over the `trust-tasks-https` binding.
///
/// The inner `reqwest::Client` is built once with finite timeouts and no
/// redirect following, and reused for every exchange.
pub struct HttpsTransport {
    http: reqwest::Client,
    endpoint: reqwest::Url,
    bearer_token: Option<String>,
    timeout: Duration,
    max_response_bytes: usize,
}

impl fmt::Debug for HttpsTransport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HttpsTransport")
            .field("endpoint", &self.endpoint.as_str())
            .field("bearer_token", &self.bearer_token.as_ref().map(|_| "***"))
            .field("timeout", &self.timeout)
            .field("max_response_bytes", &self.max_response_bytes)
            .finish_non_exhaustive()
    }
}

impl HttpsTransport {
    /// Build the transport, validating the URL and constructing the shared
    /// HTTP client.
    ///
    /// Refused with [`TrqlError::Config`]: a URL that does not parse, a
    /// scheme other than `https` or `http`, `http` to a host that is not
    /// loopback (unless [`HttpsTransportConfig::allow_insecure_http`]), a URL
    /// carrying a username or password, and, unless
    /// [`HttpsTransportConfig::allow_non_public_addresses`], an IP literal
    /// that is not a public address.
    pub fn new(config: HttpsTransportConfig) -> Result<Self, TrqlError> {
        let endpoint: reqwest::Url =
            format!("{}/trust-tasks", config.base_url.trim_end_matches('/'))
                .parse()
                .map_err(|e| TrqlError::Config(format!("invalid registry base URL: {e}")))?;
        let host = endpoint
            .host_str()
            .ok_or_else(|| TrqlError::Config("registry base URL has no host".into()))?;
        let host_ip = host
            .trim_start_matches('[')
            .trim_end_matches(']')
            .parse::<IpAddr>()
            .ok();
        match endpoint.scheme() {
            "https" => {}
            "http" => {
                let loopback = host.eq_ignore_ascii_case("localhost")
                    || host_ip.is_some_and(|ip| ip.is_loopback());
                if !loopback && !config.allow_insecure_http {
                    return Err(TrqlError::Config(format!(
                        "registry base URL must use https (http is accepted only for a \
                         loopback host unless allow_insecure_http is set): {host}"
                    )));
                }
            }
            other => {
                return Err(TrqlError::Config(format!(
                    "registry base URL scheme must be https, not {other}"
                )));
            }
        }
        if !endpoint.username().is_empty() || endpoint.password().is_some() {
            return Err(TrqlError::Config(
                "registry base URL must not carry a username or password".into(),
            ));
        }
        if config.max_response_bytes == 0 {
            return Err(TrqlError::Config(
                "max_response_bytes must be greater than 0".into(),
            ));
        }

        let mut builder = reqwest::Client::builder()
            .timeout(config.timeout)
            .connect_timeout(config.connect_timeout)
            .redirect(reqwest::redirect::Policy::none());
        if !config.allow_non_public_addresses {
            // Checked once: the endpoint never changes and no redirect is
            // followed, and the connector connects to a literal without
            // calling the resolver.
            if let Some(ip) = host_ip
                && !is_public_address(ip)
            {
                return Err(TrqlError::Config(format!(
                    "registry base URL names a non-public address: {ip}"
                )));
            }
            builder = builder
                .no_proxy()
                .dns_resolver(Arc::new(PublicAddressResolver));
        }
        let http = builder
            .build()
            .map_err(|e| TrqlError::Config(format!("could not build HTTP client: {e}")))?;
        Ok(Self {
            http,
            endpoint,
            bearer_token: config.bearer_token,
            timeout: config.timeout,
            max_response_bytes: config.max_response_bytes,
        })
    }

    fn transport_error(detail: String) -> TrqlError {
        TrqlError::Transport {
            kind: TransportKind::Https,
            detail,
        }
    }

    /// Read the body chunk by chunk, refusing it once it passes the cap.
    async fn read_capped(&self, mut response: reqwest::Response) -> Result<Vec<u8>, TrqlError> {
        let cap = self.max_response_bytes;
        if let Some(len) = response.content_length()
            && len > cap as u64
        {
            return Err(Self::transport_error(format!(
                "response body of {len} bytes exceeds the {cap}-byte limit"
            )));
        }
        let mut body = Vec::new();
        while let Some(chunk) = response.chunk().await.map_err(|e| {
            if e.is_timeout() {
                TrqlError::Timeout {
                    kind: TransportKind::Https,
                    waited_secs: self.timeout.as_secs(),
                }
            } else {
                Self::transport_error(format!("failed reading response body: {e}"))
            }
        })? {
            if body.len() + chunk.len() > cap {
                return Err(Self::transport_error(format!(
                    "response body exceeds the {cap}-byte limit"
                )));
            }
            body.extend_from_slice(&chunk);
        }
        Ok(body)
    }
}

#[async_trait::async_trait]
impl TrqlTransport for HttpsTransport {
    fn kind(&self) -> TransportKind {
        TransportKind::Https
    }

    async fn exchange(&self, request: TrustTask<Value>) -> Result<TrustTask<Value>, TrqlError> {
        let mut http_request = self.http.post(self.endpoint.clone()).json(&request);
        if let Some(token) = &self.bearer_token {
            http_request = http_request.bearer_auth(token);
        }

        let response = http_request.send().await.map_err(|e| {
            if e.is_timeout() {
                TrqlError::Timeout {
                    kind: TransportKind::Https,
                    waited_secs: self.timeout.as_secs(),
                }
            } else if e.is_connect() {
                Self::transport_error(format!("could not connect to {}: {e}", self.endpoint))
            } else {
                Self::transport_error(e.to_string())
            }
        })?;

        let status = response.status();
        if status.is_redirection() {
            return Err(Self::transport_error(format!(
                "HTTP {status}: redirects are not followed"
            )));
        }
        let body = self.read_capped(response).await?;

        // Success and error statuses both carry a Trust Task document (the
        // error status carries `trust-task-error`); the client layer maps it.
        match serde_json::from_slice::<TrustTask<Value>>(&body) {
            Ok(document) => Ok(document),
            Err(e) if status.is_success() => Err(TrqlError::Contract(format!(
                "HTTP {status} body is not a Trust Task document: {e}"
            ))),
            Err(_) => Err(Self::transport_error(format!(
                "HTTP {status} with non-Trust-Task body: {}",
                truncate_detail(&String::from_utf8_lossy(&body))
            ))),
        }
    }
}

/// At most [`MAX_ERROR_DETAIL_CHARS`] characters of `text`, marked when cut.
fn truncate_detail(text: &str) -> String {
    match text.char_indices().nth(MAX_ERROR_DETAIL_CHARS) {
        Some((end, _)) => format!("{}… (truncated)", &text[..end]),
        None => text.to_string(),
    }
}

/// Resolver used unless [`HttpsTransportConfig::allow_non_public_addresses`]:
/// resolves with the system resolver and refuses the name if any address it
/// resolves to is not public. The connector connects only to the addresses
/// returned here (it does not resolve again), so what is checked is what is
/// connected to.
struct PublicAddressResolver;

impl reqwest::dns::Resolve for PublicAddressResolver {
    fn resolve(&self, name: reqwest::dns::Name) -> reqwest::dns::Resolving {
        let host = name.as_str().to_string();
        Box::pin(async move {
            let addrs: Vec<SocketAddr> =
                tokio::net::lookup_host((host.as_str(), 0)).await?.collect();
            if let Some(addr) = addrs.iter().find(|a| !is_public_address(a.ip())) {
                return Err(
                    format!("{host} resolves to a non-public address: {}", addr.ip()).into(),
                );
            }
            if addrs.is_empty() {
                return Err(format!("{host} resolved to no addresses").into());
            }
            Ok(Box::new(addrs.into_iter()) as reqwest::dns::Addrs)
        })
    }
}

/// Whether `ip` is a globally routable unicast address.
fn is_public_address(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => is_public_v4(v4),
        IpAddr::V6(v6) => {
            if let Some(v4) = v6.to_ipv4_mapped() {
                return is_public_v4(v4);
            }
            is_public_v6(v6)
        }
    }
}

fn is_public_v4(ip: Ipv4Addr) -> bool {
    let [a, b, ..] = ip.octets();
    !(ip.is_unspecified()
        || ip.is_loopback()
        || ip.is_private()
        || ip.is_link_local()
        || ip.is_multicast()
        || ip.is_broadcast()
        || ip.is_documentation()
        || a == 0 // "this network"
        || (a == 100 && (64..128).contains(&b)) // shared address space (RFC 6598)
        || (a == 192 && b == 0 && ip.octets()[2] == 0) // IETF protocol assignments
        || (a == 198 && (b == 18 || b == 19)) // benchmarking (RFC 2544)
        || a >= 240) // reserved
}

fn is_public_v6(ip: Ipv6Addr) -> bool {
    let first = ip.segments()[0];
    !(ip.is_unspecified()
        || ip.is_loopback()
        || ip.is_multicast()
        || (first & 0xfe00) == 0xfc00 // unique local (fc00::/7)
        || (first & 0xffc0) == 0xfe80 // link-local (fe80::/10)
        || (first & 0xffc0) == 0xfec0 // site-local (fec0::/10, deprecated)
        || first == 0x2001 && ip.segments()[1] == 0x0db8 // documentation
        || first == 0x0064 && ip.segments()[1] == 0xff9b // NAT64 (64:ff9b::/96)
        || ip.segments()[..6] == [0, 0, 0, 0, 0, 0]) // IPv4-compatible (deprecated)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn non_public_addresses_are_recognised() {
        for ip in [
            "127.0.0.1",
            "10.1.2.3",
            "172.16.0.1",
            "192.168.1.1",
            "169.254.169.254",
            "100.64.0.1",
            "0.0.0.0",
            "224.0.0.1",
            "255.255.255.255",
            "::1",
            "::",
            "fd00::1",
            "fe80::1",
            "::ffff:127.0.0.1",
            "::ffff:169.254.169.254",
            "64:ff9b::a9fe:a9fe",
        ] {
            assert!(!is_public_address(ip.parse().unwrap()), "{ip}");
        }
        for ip in ["93.184.216.34", "1.1.1.1", "2606:4700::1111"] {
            assert!(is_public_address(ip.parse().unwrap()), "{ip}");
        }
    }

    #[test]
    fn error_detail_is_truncated() {
        let long = "x".repeat(10_000);
        let cut = truncate_detail(&long);
        assert!(cut.len() < 300, "{}", cut.len());
        assert!(cut.ends_with("(truncated)"));
        assert_eq!(truncate_detail("short"), "short");
    }
}
