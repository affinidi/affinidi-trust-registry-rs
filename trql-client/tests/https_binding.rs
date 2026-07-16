//! Round-trip tests for the HTTPS binding against an in-process server that
//! speaks the `POST /trust-tasks` wire contract (the same one the
//! trust-registry serves): 2xx carries the `#response` document, non-2xx
//! carries a `trust-task-error` document, correlation via `threadId`.

#![allow(clippy::unwrap_used, clippy::expect_used)]
#![cfg(feature = "https")]

use std::sync::Arc;
use std::time::Duration;

use axum::{Json, Router, http::StatusCode, routing::post};
use serde_json::Value;
use trql_client::{HttpsTransport, HttpsTransportConfig, TrqlClient, TrqlError, TrqpQuery};
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

fn client_for(base_url: &str) -> TrqlClient {
    let transport = HttpsTransport::new(HttpsTransportConfig::new(base_url)).unwrap();
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
                "entity_id": doc.payload["entity_id"],
                "authority_id": doc.payload["authority_id"],
                "action": doc.payload["action"],
                "resource": doc.payload["resource"],
                "authorized": true,
                "time_evaluated": "2026-07-16T00:00:00Z",
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

    let mut config = HttpsTransportConfig::new(&base);
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
