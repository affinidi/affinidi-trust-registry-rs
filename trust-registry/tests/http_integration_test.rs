use serde_json::{Value, json};
use std::env;
use trust_registry::trust_tasks::type_uris;
use trust_tasks_rs::TrustTask;

async fn setup_test_environment() -> String {
    dotenvy::from_filename(".env.test").ok();
    let address = env::var("LISTEN_ADDRESS")
        .map(|address| format!("http://{}", address))
        .unwrap_or("http://0.0.0.0:3232".to_string());
    let test_data = "entity_id,authority_id,action,resource,recognized,authorized,context
did:example:entity1,did:example:authority1,action1,resource1,true,true,eyJ0ZXN0IjogImNvbnRleHQifQ==
did:example:entity2,did:example:authority2,action2,resource2,false,true,eyJ0ZXN0IjogImNvbnRleHQifQ==
did:example:entity3,did:example:authority3,action3,resource3,true,false,eyJ0ZXN0IjogImNvbnRleHQifQ==";
    let temp_file = std::env::temp_dir().join("integration_test_data.csv");
    tokio::fs::write(&temp_file, test_data).await.unwrap();
    if env::var("TR_STORAGE_BACKEND").unwrap_or("csv".to_owned()) == "csv" {
        unsafe {
            env::set_var("FILE_STORAGE_PATH", temp_file.to_str().unwrap());
        }
    }

    address
}

async fn get_test_server_url() -> String {
    setup_test_environment().await
}

#[tokio::test]
async fn test_health_endpoint() {
    let server_url = get_test_server_url().await;
    let client = reqwest::Client::new();

    let response = client
        .get(format!("{}/health", server_url))
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), 200);

    // Asserted field-by-field rather than as a whole body: `/health` now also
    // reports write-path state, and an exact-equality assertion would break on
    // every additive field.
    let json: Value = response.json().await.unwrap();
    assert_eq!(json["status"], "OK");
    // This server runs with DIDComm configured, so writes are either up or
    // reported unavailable — never absent.
    assert!(
        json.get("writes").is_some(),
        "health must report write-path state, got {json}"
    );
}

/// A `registry/*` query Trust Task for `POST /trust-tasks`. Anonymous: no
/// issuer, no recipient, no proof, which is all a query needs.
fn query_task(type_uri: &str, entity_id: &str) -> Value {
    let doc = TrustTask::new(
        format!("urn:uuid:{}", uuid::Uuid::new_v4()),
        type_uri.parse().expect("valid type uri"),
        json!({
            "entity_id": entity_id,
            "authority_id": "did:example:authority1",
            "action": "action1",
            "resource": "resource1"
        }),
    );
    serde_json::to_value(doc).unwrap()
}

async fn post_task(server_url: &str, body: &Value) -> reqwest::Response {
    reqwest::Client::new()
        .post(format!("{}/trust-tasks", server_url))
        .json(body)
        .send()
        .await
        .unwrap()
}

#[tokio::test]
async fn test_registry_recognition_over_https() {
    let server_url = get_test_server_url().await;

    let response = post_task(
        &server_url,
        &query_task(type_uris::RECOGNITION, "did:example:entity1"),
    )
    .await;
    assert_eq!(response.status(), 200);

    let reply: TrustTask<Value> = response.json().await.unwrap();
    assert!(reply.type_uri.is_response(), "not a response: {reply:?}");
    assert_eq!(reply.type_uri.slug(), "registry/recognition");
    assert_eq!(reply.payload["entity_id"], "did:example:entity1");
    assert_eq!(reply.payload["recognized"], json!(true));
    assert!(reply.payload.get("authorized").is_none());
    assert!(
        reply.payload["message"]
            .as_str()
            .unwrap()
            .contains("recognized by")
    );
}

#[tokio::test]
async fn test_registry_authorization_over_https() {
    let server_url = get_test_server_url().await;

    let response = post_task(
        &server_url,
        &query_task(type_uris::AUTHORIZATION, "did:example:entity1"),
    )
    .await;
    assert_eq!(response.status(), 200);

    let reply: TrustTask<Value> = response.json().await.unwrap();
    assert!(reply.type_uri.is_response(), "not a response: {reply:?}");
    assert_eq!(reply.type_uri.slug(), "registry/authorization");
    assert_eq!(reply.payload["authorized"], json!(true));
    assert!(reply.payload.get("recognized").is_none());
    assert!(
        reply.payload["message"]
            .as_str()
            .unwrap()
            .contains("authorized to")
    );
}

/// Absence is a denial, not an error: an unknown tuple answers `false`.
#[tokio::test]
async fn test_registry_recognition_over_https_unknown_record_is_not_recognized() {
    let server_url = get_test_server_url().await;

    let response = post_task(
        &server_url,
        &query_task(type_uris::RECOGNITION, "did:example:nonexistent"),
    )
    .await;
    assert_eq!(response.status(), 200);
    let reply: TrustTask<Value> = response.json().await.unwrap();
    assert_eq!(reply.payload["recognized"], json!(false));
}

#[tokio::test]
async fn test_registry_authorization_over_https_unknown_record_is_not_authorized() {
    let server_url = get_test_server_url().await;

    let response = post_task(
        &server_url,
        &query_task(type_uris::AUTHORIZATION, "did:example:nonexistent"),
    )
    .await;
    assert_eq!(response.status(), 200);
    let reply: TrustTask<Value> = response.json().await.unwrap();
    assert_eq!(reply.payload["authorized"], json!(false));
}

#[tokio::test]
async fn test_trust_tasks_malformed_body_is_bad_request() {
    let server_url = get_test_server_url().await;

    let response = reqwest::Client::new()
        .post(format!("{}/trust-tasks", server_url))
        .header("content-type", "application/json")
        .body("{ invalid json")
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), 400);
}

/// The raw TRQP REST routes are gone; Trust Tasks are the only query surface.
#[tokio::test]
async fn test_legacy_trqp_rest_routes_are_not_served() {
    let server_url = get_test_server_url().await;
    let client = reqwest::Client::new();

    for path in ["recognition", "authorization"] {
        let response = client
            .post(format!("{}/{path}", server_url))
            .json(&json!({
                "entity_id": "did:example:entity1",
                "authority_id": "did:example:authority1",
                "action": "action1",
                "resource": "resource1"
            }))
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), 404, "/{path} is still served");
    }
}

#[tokio::test]
async fn test_cors_headers_present() {
    let server_url = get_test_server_url().await;
    let client = reqwest::Client::new();

    let response = client
        .request(reqwest::Method::OPTIONS, format!("{}/health", server_url))
        .header("Origin", "http://localhost:3000")
        .header("Access-Control-Request-Method", "GET")
        .send()
        .await
        .unwrap();

    let headers = response.headers();
    assert!(headers.contains_key("access-control-allow-origin"));
}

#[tokio::test]
async fn test_method_not_allowed() {
    let server_url = get_test_server_url().await;
    let client = reqwest::Client::new();

    let response = client
        .get(format!("{}/trust-tasks", server_url))
        .send()
        .await
        .expect("Failed to send method not allowed request");

    assert_eq!(response.status(), 405);
}

#[tokio::test]
async fn test_invalid_endpoint() {
    let server_url = get_test_server_url().await;
    let client = reqwest::Client::new();

    let response = client
        .get(format!("{}/nonexistent", server_url))
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), 404);
}

#[tokio::test]
async fn test_wellknown_did_endpoint_returns_valid_json() {
    let server_url = get_test_server_url().await;
    let client = reqwest::Client::new();

    let response = client
        .get(format!("{}/.well-known/did.json", server_url))
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), 200);

    let doc: Value = response.json().await.unwrap();

    assert!(
        doc.get("id").is_some(),
        "DID document should have an 'id' field"
    );
    assert!(
        doc["@context"].is_array(),
        "DID document should have '@context' as array"
    );
    assert!(
        doc["verificationMethod"].is_array(),
        "DID document should have 'verificationMethod' array"
    );
    assert!(
        doc["authentication"].is_array(),
        "DID document should have 'authentication' array"
    );
    assert!(
        doc["assertionMethod"].is_array(),
        "DID document should have 'assertionMethod' array"
    );
    assert!(
        doc["keyAgreement"].is_array(),
        "DID document should have 'keyAgreement' array"
    );
    assert!(
        doc["service"].is_array(),
        "DID document should have 'service' array"
    );
}

#[tokio::test]
async fn test_wellknown_did_document_no_private_keys() {
    let server_url = get_test_server_url().await;
    let client = reqwest::Client::new();

    let response = client
        .get(format!("{}/.well-known/did.json", server_url))
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), 200);

    let doc: Value = response.json().await.unwrap();

    // Check all verification methods don't contain private keys
    if let Some(methods) = doc["verificationMethod"].as_array() {
        for method in methods {
            if let Some(jwk) = method.get("publicKeyJwk") {
                assert!(
                    jwk.get("d").is_none(),
                    "Private key 'd' field should not be present in public JWK"
                );
            }
        }
    }
}

#[tokio::test]
async fn test_wellknown_did_document_structure() {
    let server_url = get_test_server_url().await;
    let client = reqwest::Client::new();

    let response = client
        .get(format!("{}/.well-known/did.json", server_url))
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), 200);

    let doc: Value = response.json().await.unwrap();

    // Verify DIDComm service is present
    if let Some(services) = doc["service"].as_array() {
        let didcomm_service = services.iter().find(|s| s["type"] == "DIDCommMessaging");
        assert!(
            didcomm_service.is_some(),
            "DID document should have a DIDComm service"
        );

        if let Some(service) = didcomm_service {
            assert!(service.get("id").is_some(), "Service should have an id");
            assert_eq!(service["type"], "DIDCommMessaging");
            assert!(
                service["serviceEndpoint"].get("uri").is_some(),
                "Service endpoint should have a uri"
            );
            assert!(
                service["serviceEndpoint"]["accept"].is_array(),
                "Service endpoint should have accept array"
            );
        }
    }

    // Verify verification methods have correct structure
    if let Some(methods) = doc["verificationMethod"].as_array() {
        for method in methods {
            assert!(
                method.get("id").is_some(),
                "Verification method should have an id"
            );
            assert!(
                method.get("type").is_some(),
                "Verification method should have a type"
            );
            assert!(
                method.get("controller").is_some(),
                "Verification method should have a controller"
            );
            assert!(
                method.get("publicKeyJwk").is_some(),
                "Verification method should have publicKeyJwk"
            );

            // Verify publicKeyJwk structure
            let jwk = &method["publicKeyJwk"];
            assert!(jwk.get("kty").is_some(), "JWK should have kty field");
            assert!(jwk.get("crv").is_some(), "JWK should have crv field");
            assert!(jwk.get("x").is_some(), "JWK should have x coordinate");
        }
    }
}
