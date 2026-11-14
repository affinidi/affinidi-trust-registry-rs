//! Round-trip tests for the HTTPS binding against an in-process server that
//! speaks the `POST /trust-tasks` wire contract (the same one the
//! trust-registry serves): 2xx carries the `#response` document, non-2xx
//! carries a `trust-task-error` document, correlation via `threadId`.

#![allow(clippy::unwrap_used, clippy::expect_used)]
#![cfg(feature = "https")]

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use axum::{
    Json, Router,
    http::{StatusCode, header},
    routing::post,
};
use serde_json::Value;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use trql_client::{
    DEFAULT_MAX_RESPONSE_BYTES, HttpsTransport, HttpsTransportConfig, MAX_ERROR_DETAIL_CHARS,
    TrqlClient, TrqlError, TrqpQuery,
};
use trust_tasks_rs::{RejectReason, TrustTask};

/// Serve `router` on an ephemeral port and return its base URL.
async fn serve(router: Router) -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, router).await.unwrap();
    });
    format!("http://{addr}")
}

/// A config for a test server on this machine: loopback is not a public
/// address, so these tests opt out of the address filter.
fn local_config(base_url: impl Into<String>) -> HttpsTransportConfig {
    HttpsTransportConfig::new(base_url).with_allow_non_public_addresses(true)
}

fn client_for(base_url: &str) -> TrqlClient {
    let transport = HttpsTransport::new(local_config(base_url)).unwrap();
    TrqlClient::new(Arc::new(transport), "did:example:registry")
}

#[tokio::test]
async fn authorization_round_trip_over_http() {
    let router = Router::new().route(
        "/trust-tasks",
        post(|Json(doc): Json<TrustTask<Value>>| async move {
            assert_eq!(doc.recipient.as_deref(), Some("did:example:registry"));
            assert_eq!(doc.type_uri.slug(), "registry/authorization");
            let payload = serde_json::json!({
                "entityId": doc.payload["entityId"],
                "authorityId": doc.payload["authorityId"],
                "action": doc.payload["action"],
                "resource": doc.payload["resource"],
                "authorized": true,
                "evaluatedAt": "2026-07-16T00:00:00Z",
            });
            Json(doc.respond_with("urn:uuid:reply".to_string(), payload))
        }),
    );
    let base = serve(router).await;

    let response = client_for(&base)
        .authorization(TrqpQuery::new(
            "did:example:signer",
            "did:example:authority",
            "git.commit.sign",
            "openvtc",
        ))
        .await
        .unwrap();

    assert!(response.authorized);
    assert_eq!(response.entity_id, "did:example:signer");
}

#[tokio::test]
async fn error_status_with_error_document_maps_to_rejected() {
    let router = Router::new().route(
        "/trust-tasks",
        post(|Json(doc): Json<TrustTask<Value>>| async move {
            let error = doc.reject_with(
                "urn:uuid:err".to_string(),
                RejectReason::PermissionDenied {
                    reason: "nope".to_string(),
                },
            );
            (StatusCode::FORBIDDEN, Json(error))
        }),
    );
    let base = serve(router).await;

    let err = client_for(&base)
        .authorization(TrqpQuery::new("e", "a", "act", "res"))
        .await
        .unwrap_err();

    match err {
        TrqlError::Rejected { retryable, .. } => assert!(!retryable),
        other => panic!("expected Rejected, got {other}"),
    }
}

#[tokio::test]
async fn non_trust_task_error_body_is_a_transport_error() {
    let router = Router::new().route(
        "/trust-tasks",
        post(|| async { (StatusCode::BAD_GATEWAY, "upstream exploded") }),
    );
    let base = serve(router).await;

    let err = client_for(&base)
        .authorization(TrqpQuery::new("e", "a", "act", "res"))
        .await
        .unwrap_err();

    assert!(matches!(err, TrqlError::Transport { .. }), "got: {err}");
    assert!(err.is_retryable());
}

#[tokio::test]
async fn hung_server_times_out_instead_of_hanging() {
    let router = Router::new().route(
        "/trust-tasks",
        post(|| async {
            tokio::time::sleep(Duration::from_secs(60)).await;
            "never sent"
        }),
    );
    let base = serve(router).await;

    let mut config = local_config(&base);
    config.timeout = Duration::from_millis(300);
    let transport = HttpsTransport::new(config).unwrap();
    let client = TrqlClient::new(Arc::new(transport), "did:example:registry");

    let err = client
        .authorization(TrqpQuery::new("e", "a", "act", "res"))
        .await
        .unwrap_err();

    assert!(matches!(err, TrqlError::Timeout { .. }), "got: {err}");
}

#[tokio::test]
async fn success_status_with_garbage_body_is_a_contract_error() {
    let router = Router::new().route("/trust-tasks", post(|| async { "not a document" }));
    let base = serve(router).await;

    let err = client_for(&base)
        .authorization(TrqpQuery::new("e", "a", "act", "res"))
        .await
        .unwrap_err();

    assert!(matches!(err, TrqlError::Contract(_)), "got: {err}");
    assert!(!err.is_retryable());
}

/// A 2xx carrying a properly correlated `#response` that grants authorization
/// for a *different* authority than the one queried. Everything the binding
/// checked before this — status, document shape, `threadId`, response type —
/// passes; only the tuple echo catches it.
#[tokio::test]
async fn correlated_answer_for_another_authority_is_rejected_over_the_wire() {
    let router = Router::new().route(
        "/trust-tasks",
        post(|Json(doc): Json<TrustTask<Value>>| async move {
            let payload = serde_json::json!({
                "entityId": doc.payload["entityId"],
                "authorityId": "did:example:not-who-we-asked-about",
                "action": doc.payload["action"],
                "resource": doc.payload["resource"],
                "authorized": true,
                "evaluatedAt": "2026-07-16T00:00:00Z",
            });
            Json(doc.respond_with("urn:uuid:reply".to_string(), payload))
        }),
    );
    let base = serve(router).await;

    let err = client_for(&base)
        .authorization(TrqpQuery::new(
            "did:example:signer",
            "did:example:authority",
            "git.commit.sign",
            "openvtc",
        ))
        .await
        .unwrap_err();

    assert!(
        matches!(
            err,
            TrqlError::AnswerMismatch {
                field: "authorityId",
                ..
            }
        ),
        "got: {err}"
    );
    assert!(!err.is_retryable());
}

/// The full referral shape over the wire: we followed a referral from a VTC,
/// the registry answers faithfully for the authority we named, but that
/// authority is not the one that referred us — so the referral stays
/// unconfirmed and the answer is refused.
#[tokio::test]
async fn unconfirmed_referral_is_rejected_over_the_wire() {
    let router = Router::new().route(
        "/trust-tasks",
        post(|Json(doc): Json<TrustTask<Value>>| async move {
            let payload = serde_json::json!({
                "entityId": doc.payload["entityId"],
                "authorityId": doc.payload["authorityId"],
                "action": doc.payload["action"],
                "resource": doc.payload["resource"],
                "authorized": true,
                "evaluatedAt": "2026-07-16T00:00:00Z",
            });
            Json(doc.respond_with("urn:uuid:reply".to_string(), payload))
        }),
    );
    let base = serve(router).await;
    let transport = HttpsTransport::new(local_config(&base)).unwrap();
    let client = TrqlClient::new(Arc::new(transport), "did:example:registry")
        .referred_by("did:example:referring-vtc");

    let err = client
        .authorization(TrqpQuery::new(
            "did:example:signer",
            "did:example:authority",
            "git.commit.sign",
            "openvtc",
        ))
        .await
        .unwrap_err();

    assert!(
        matches!(err, TrqlError::ReferralNotClosed { .. }),
        "got: {err}"
    );

    // ...and the same registry, asked about the authority that referred us,
    // closes the loop.
    let transport = HttpsTransport::new(local_config(&base)).unwrap();
    let response = TrqlClient::new(Arc::new(transport), "did:example:registry")
        .referred_by("did:example:referring-vtc")
        .authorization(TrqpQuery::new(
            "did:example:signer",
            "did:example:referring-vtc",
            "git.commit.sign",
            "openvtc",
        ))
        .await
        .unwrap();
    assert!(response.authorized);
}

fn authorized_reply(doc: TrustTask<Value>) -> TrustTask<Value> {
    let payload = serde_json::json!({
        "entityId": doc.payload["entityId"],
        "authorityId": doc.payload["authorityId"],
        "action": doc.payload["action"],
        "resource": doc.payload["resource"],
        "authorized": true,
        "evaluatedAt": "2026-07-16T00:00:00Z",
    });
    doc.respond_with("urn:uuid:reply".to_string(), payload)
}

fn query() -> TrqpQuery {
    TrqpQuery::new("e", "a", "act", "res")
}

/// An error status whose body is a well-formed success document granting
/// the query is a broken exchange, not an answer: whichever of the two
/// disagreeing signals is more permissive must not win.
#[tokio::test]
async fn error_status_with_a_success_document_is_not_an_answer() {
    for status in [
        StatusCode::FORBIDDEN,
        StatusCode::INTERNAL_SERVER_ERROR,
        StatusCode::BAD_GATEWAY,
    ] {
        let router = Router::new().route(
            "/trust-tasks",
            post(move |Json(doc): Json<TrustTask<Value>>| async move {
                (status, Json(authorized_reply(doc)))
            }),
        );
        let base = serve(router).await;
        let err = client_for(&base)
            .authorization(query())
            .await
            .expect_err("an error status must never yield an answer");
        assert!(matches!(err, TrqlError::Contract(_)), "{status}: {err}");
        assert!(err.to_string().contains("non-error"), "{err}");
    }
}

/// A success status carrying a `trust-task-error` document is still a
/// refusal: the query fails, with the registry's code.
#[tokio::test]
async fn success_status_with_an_error_document_is_not_an_answer() {
    let router = Router::new().route(
        "/trust-tasks",
        post(|Json(doc): Json<TrustTask<Value>>| async move {
            let error = doc.reject_with(
                "urn:uuid:err".to_string(),
                RejectReason::PermissionDenied {
                    reason: "nope".to_string(),
                },
            );
            (StatusCode::OK, Json(error))
        }),
    );
    let base = serve(router).await;
    let err = client_for(&base)
        .authorization(query())
        .await
        .expect_err("an error document must never yield an answer");
    assert!(matches!(err, TrqlError::Rejected { .. }), "{err}");
}

/// A redirect is answered as a transport error; the target is never asked.
#[tokio::test]
async fn redirect_is_not_followed() {
    let reached = Arc::new(AtomicBool::new(false));
    let reached_in_handler = reached.clone();
    let router = Router::new()
        .route(
            "/trust-tasks",
            post(|| async {
                (
                    StatusCode::TEMPORARY_REDIRECT,
                    [(header::LOCATION, "/elsewhere")],
                )
            }),
        )
        .route(
            "/elsewhere",
            post(move |Json(doc): Json<TrustTask<Value>>| {
                let reached = reached_in_handler.clone();
                async move {
                    reached.store(true, Ordering::SeqCst);
                    Json(authorized_reply(doc))
                }
            }),
        );
    let base = serve(router).await;

    let err = client_for(&base).authorization(query()).await.unwrap_err();

    assert!(matches!(err, TrqlError::Transport { .. }), "got: {err}");
    assert!(err.to_string().contains("redirect"), "got: {err}");
    assert!(!reached.load(Ordering::SeqCst));
}

/// A reply larger than the cap is refused, with a declared length.
#[tokio::test]
async fn oversized_reply_with_content_length_is_refused() {
    let router = Router::new().route(
        "/trust-tasks",
        post(|| async { "x".repeat(DEFAULT_MAX_RESPONSE_BYTES + 1) }),
    );
    let base = serve(router).await;

    let err = client_for(&base).authorization(query()).await.unwrap_err();

    assert!(matches!(err, TrqlError::Transport { .. }), "got: {err}");
    assert!(err.to_string().contains("limit"), "got: {err}");
}

/// A chunked reply with no declared length is refused once it passes the cap,
/// without reading the rest.
#[tokio::test]
async fn oversized_chunked_reply_is_refused() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        // Read the request head and body (small); exact framing is not needed.
        let mut buf = vec![0u8; 16 * 1024];
        let _ = socket.read(&mut buf).await;
        let head = "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\n\
                    transfer-encoding: chunked\r\n\r\n";
        if socket.write_all(head.as_bytes()).await.is_err() {
            return;
        }
        // Up to 64 MiB in 16 KiB chunks; the client must stop well before.
        let chunk = vec![b' '; 16 * 1024];
        for _ in 0..4096 {
            let frame = format!("{:x}\r\n", chunk.len());
            if socket.write_all(frame.as_bytes()).await.is_err()
                || socket.write_all(&chunk).await.is_err()
                || socket.write_all(b"\r\n").await.is_err()
            {
                return;
            }
        }
        let _ = socket.write_all(b"0\r\n\r\n").await;
    });

    let mut config = local_config(format!("http://{addr}"));
    config.max_response_bytes = 32 * 1024;
    let transport = HttpsTransport::new(config).unwrap();
    let err = TrqlClient::new(Arc::new(transport), "did:example:registry")
        .authorization(query())
        .await
        .unwrap_err();

    assert!(matches!(err, TrqlError::Transport { .. }), "got: {err}");
    assert!(err.to_string().contains("32768-byte limit"), "got: {err}");
}

/// The body of a non-2xx answer that is not a Trust Task document is copied
/// into the error only up to a bound.
#[tokio::test]
async fn error_body_is_truncated_in_the_error() {
    let router = Router::new().route(
        "/trust-tasks",
        post(|| async { (StatusCode::BAD_GATEWAY, "y".repeat(10_000)) }),
    );
    let base = serve(router).await;

    let err = client_for(&base).authorization(query()).await.unwrap_err();

    let TrqlError::Transport { detail, .. } = &err else {
        panic!("expected Transport, got {err}");
    };
    assert!(
        detail.len() < MAX_ERROR_DETAIL_CHARS + 100,
        "{}",
        detail.len()
    );
    assert!(detail.ends_with("(truncated)"), "{detail}");
}

#[test]
fn plain_http_is_refused_for_a_non_loopback_host() {
    for url in [
        "http://registry.example.com",
        "http://10.0.0.5:3232",
        "http://169.254.169.254",
        "ftp://registry.example.com",
        "file:///etc/passwd",
    ] {
        let err = HttpsTransport::new(HttpsTransportConfig::new(url)).unwrap_err();
        assert!(matches!(err, TrqlError::Config(_)), "{url}: {err}");
    }
    for url in [
        "https://registry.example.com",
        "http://localhost:3232",
        "http://127.0.0.1:3232",
        "http://[::1]:3232",
    ] {
        HttpsTransport::new(local_config(url)).unwrap_or_else(|e| panic!("{url}: {e}"));
    }
    let mut config = HttpsTransportConfig::new("http://registry.example.com");
    config.allow_insecure_http = true;
    HttpsTransport::new(config).unwrap();
}

#[test]
fn credentials_in_the_url_are_refused() {
    let err = HttpsTransport::new(HttpsTransportConfig::new(
        "https://u:p@registry.example.com",
    ))
    .unwrap_err();
    assert!(matches!(err, TrqlError::Config(_)), "got: {err}");
}

#[test]
fn debug_output_redacts_the_bearer_token() {
    let mut config = HttpsTransportConfig::new("https://registry.example.com");
    config.bearer_token = Some("s3cr3t-token-value".to_string());
    let shown = format!("{config:?}");
    assert!(!shown.contains("s3cr3t-token-value"), "{shown}");
    assert!(shown.contains("***"), "{shown}");

    let transport = HttpsTransport::new(config).unwrap();
    let shown = format!("{transport:?}");
    assert!(!shown.contains("s3cr3t-token-value"), "{shown}");
}

/// The address filter is on unless the config opts out.
#[test]
fn address_filter_is_on_by_default() {
    assert!(!HttpsTransportConfig::new("https://registry.example.com").allow_non_public_addresses);
}

/// By default an IP literal that is not public is refused when the
/// transport is built (a literal is never passed to the resolver, and the
/// endpoint is fixed for the transport's life with redirects off, so this
/// one check covers every request); opting out accepts it.
#[test]
fn address_filter_refuses_a_non_public_ip_literal() {
    for url in [
        "https://127.0.0.1",
        "http://127.0.0.1:3232",
        "https://10.1.2.3",
        "https://169.254.169.254",
        "https://100.64.0.1",
        "https://[::1]",
        "https://[fe80::1]",
        "https://[fd00::1]",
        "https://[::ffff:169.254.169.254]",
    ] {
        let err = HttpsTransport::new(HttpsTransportConfig::new(url)).unwrap_err();
        assert!(matches!(err, TrqlError::Config(_)), "{url}: {err}");
        HttpsTransport::new(local_config(url)).unwrap_or_else(|e| panic!("{url}: {e}"));
    }
}

/// By default a host name that resolves to a loopback address is refused at
/// connect time, and the server is never reached.
#[tokio::test]
async fn address_filter_refuses_a_name_resolving_to_loopback() {
    let reached = Arc::new(AtomicBool::new(false));
    let reached_in_handler = reached.clone();
    let router = Router::new().route(
        "/trust-tasks",
        post(move |Json(doc): Json<TrustTask<Value>>| {
            let reached = reached_in_handler.clone();
            async move {
                reached.store(true, Ordering::SeqCst);
                Json(authorized_reply(doc))
            }
        }),
    );
    let base = serve(router).await;
    let port = base.rsplit(':').next().unwrap();

    let transport = HttpsTransport::new(HttpsTransportConfig::new(format!(
        "http://localhost:{port}"
    )))
    .unwrap();
    let err = TrqlClient::new(Arc::new(transport), "did:example:registry")
        .authorization(query())
        .await
        .unwrap_err();

    assert!(matches!(err, TrqlError::Transport { .. }), "got: {err}");
    assert!(!reached.load(Ordering::SeqCst));
}
