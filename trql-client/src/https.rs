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

use std::time::Duration;

use serde_json::Value;
use trust_tasks_rs::TrustTask;

use crate::error::TrqlError;
use crate::transport::{TransportKind, TrqlTransport};

/// Configuration for [`HttpsTransport`].
#[derive(Debug, Clone)]
pub struct HttpsTransportConfig {
    /// Base URL of the registry, e.g. `https://registry.example.com` — the
    /// transport POSTs to `<base>/trust-tasks`.
    pub base_url: String,
    /// End-to-end request timeout.
    pub timeout: Duration,
    /// Connection-establishment timeout.
    pub connect_timeout: Duration,
    /// Optional bearer token (`Authorization: Bearer <token>`).
    pub bearer_token: Option<String>,
}

impl HttpsTransportConfig {
    /// Defaults: 30s request timeout, 10s connect timeout, no bearer token.
    pub fn new(base_url: impl Into<String>) -> Self {
        Self {
            base_url: base_url.into(),
            timeout: Duration::from_secs(30),
            connect_timeout: Duration::from_secs(10),
            bearer_token: None,
        }
    }
}

/// [`TrqlTransport`] over the `trust-tasks-https` binding.
///
/// The inner `reqwest::Client` is built once with finite timeouts and reused
/// for every exchange.
pub struct HttpsTransport {
    http: reqwest::Client,
    endpoint: reqwest::Url,
    bearer_token: Option<String>,
    timeout: Duration,
}

impl HttpsTransport {
    /// Build the transport, validating the URL and constructing the shared
    /// HTTP client.
    pub fn new(config: HttpsTransportConfig) -> Result<Self, TrqlError> {
        let endpoint: reqwest::Url =
            format!("{}/trust-tasks", config.base_url.trim_end_matches('/'))
                .parse()
                .map_err(|e| TrqlError::Config(format!("invalid registry base URL: {e}")))?;
        let http = reqwest::Client::builder()
            .timeout(config.timeout)
            .connect_timeout(config.connect_timeout)
            .build()
            .map_err(|e| TrqlError::Config(format!("could not build HTTP client: {e}")))?;
        Ok(Self {
            http,
            endpoint,
            bearer_token: config.bearer_token,
            timeout: config.timeout,
        })
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
                TrqlError::Transport {
                    kind: TransportKind::Https,
                    detail: format!("could not connect to {}: {e}", self.endpoint),
                }
            } else {
                TrqlError::Transport {
                    kind: TransportKind::Https,
                    detail: e.to_string(),
                }
            }
        })?;

        let status = response.status();
        let body = response.bytes().await.map_err(|e| TrqlError::Transport {
            kind: TransportKind::Https,
            detail: format!("failed reading response body: {e}"),
        })?;

        // Success and error statuses both carry a Trust Task document (the
        // error status carries `trust-task-error`); the client layer maps it.
        match serde_json::from_slice::<TrustTask<Value>>(&body) {
            Ok(document) => Ok(document),
            Err(e) if status.is_success() => Err(TrqlError::Contract(format!(
                "HTTP {status} body is not a Trust Task document: {e}"
            ))),
            Err(_) => Err(TrqlError::Transport {
                kind: TransportKind::Https,
                detail: format!(
                    "HTTP {status} with non-Trust-Task body: {}",
                    String::from_utf8_lossy(&body)
                ),
            }),
        }
    }
}
