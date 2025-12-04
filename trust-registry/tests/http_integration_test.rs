use serde_json::{Value, json};
use std::env;

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
        .get(&format!("{}/health", server_url))
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), 200);

    let json: Value = response.json().await.unwrap();
    assert_eq!(json, json!({"status": "OK"}));
}

#[tokio::test]
async fn test_recognition_endpoint_success() {
    let server_url = get_test_server_url().await;
    let client = reqwest::Client::new();

    let request_body = json!({
        "entity_id": "did:example:entity1",
        "authority_id": "did:example:authority1",
        "action": "action1",
        "resource": "resource1"
    });

    let response = client
        .post(&format!("{}/recognition", server_url))
        .header("content-type", "application/json")
        .json(&request_body)
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), 200);

    let json: Value = response.json().await.unwrap();

    assert!(json.get("entity_id").is_some());
    assert!(json.get("authority_id").is_some());
    assert!(json.get("action").is_some());
    assert!(json.get("resource").is_some());
    assert!(json.get("time_requested").is_some());
    assert!(json.get("time_evaluated").is_some());
    assert!(json.get("message").is_some());

    assert_eq!(json.get("authorized"), None);

    let message = json["message"].as_str().unwrap();
    assert!(message.contains("recognized by"));
}

#[tokio::test]
async fn test_authorization_endpoint_success() {
    let server_url = get_test_server_url().await;
    let client = reqwest::Client::new();

    let request_body = json!({
        "entity_id": "did:example:entity1",
        "authority_id": "did:example:authority1",
        "action": "action1",
        "resource": "resource1"
    });

    let response = client
        .post(&format!("{}/authorization", server_url))
        .header("content-type", "application/json")
        .json(&request_body)
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), 200);

    let json: Value = response.json().await.unwrap();

    assert!(json.get("entity_id").is_some());
    assert!(json.get("authority_id").is_some());
    assert!(json.get("action").is_some());
    assert!(json.get("resource").is_some());
    assert!(json.get("time_requested").is_some());
    assert!(json.get("time_evaluated").is_some());
    assert!(json.get("message").is_some());

    assert_eq!(json.get("recognized"), None);

    let message = json["message"].as_str().unwrap();
    assert!(message.contains("authorized to"));
    assert!(message.contains("+"));
}

#[tokio::test]
async fn test_authorization_endpoint_not_found() {
    let server_url = get_test_server_url().await;
    let client = reqwest::Client::new();

    let request_body = json!({
        "entity_id": "did:example:nonexistent",
        "authority_id": "did:example:authority1",
        "action": "action1",
        "resource": "resource1"
    });

    let response = client
        .post(&format!("{}/authorization", server_url))
        .header("content-type", "application/json")
        .json(&request_body)
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), 404);

    let json: Value = response.json().await.unwrap();

    assert_eq!(json["title"], "not_found");
    assert_eq!(json["type"], "about:blank");
    assert_eq!(json["code"], 404);
}

#[tokio::test]
async fn test_recognition_endpoint_not_found() {
    let server_url = get_test_server_url().await;
    let client = reqwest::Client::new();

    let request_body = json!({
        "entity_id": "did:example:nonexistent",
        "authority_id": "did:example:authority1",
        "action": "action1",
        "resource": "resource1"
    });

    let response = client
        .post(&format!("{}/recognition", server_url))
        .header("content-type", "application/json")
        .json(&request_body)
        .send()
        .await
        .expect("Failed to send recognition not found request");

    assert_eq!(response.status(), 404);

    let json: Value = response.json().await.unwrap();

    assert_eq!(json["title"], "not_found");
    assert_eq!(json["type"], "about:blank");
    assert_eq!(json["code"], 404);
}

#[tokio::test]
async fn test_authorization_endpoint_bad_request() {
    let server_url = get_test_server_url().await;
    let client = reqwest::Client::new();

    let request_body = json!({
        "entity_id": "did:example:entity1",
        "authority_id": "did:example:authority1"
    });

    let response = client
        .post(&format!("{}/authorization", server_url))
        .header("content-type", "application/json")
        .json(&request_body)
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), 400);

    let json: Value = response.json().await.unwrap();

    assert_eq!(json["title"], "bad_request");
    assert_eq!(json["type"], "about:blank");
    assert_eq!(json["code"], 400);
}

#[tokio::test]
async fn test_recognition_endpoint_bad_request() {
    let server_url = get_test_server_url().await;
    let client = reqwest::Client::new();

    let invalid_json = "{ invalid json";

    let response = client
        .post(&format!("{}/recognition", server_url))
        .header("content-type", "application/json")
        .body(invalid_json)
        .send()
        .await
        .expect("Failed to send recognition bad request");

    assert_eq!(response.status(), 400);

    let json: Value = response.json().await.unwrap();

    assert_eq!(json["title"], "bad_request");
    assert_eq!(json["type"], "about:blank");
    assert_eq!(json["code"], 400);
}

#[tokio::test]
async fn test_context_merging_authorization() {
    let server_url = get_test_server_url().await;
    let client = reqwest::Client::new();

    let request_body = json!({
        "entity_id": "did:example:entity1",
        "authority_id": "did:example:authority1",
        "action": "action1",
        "resource": "resource1",
        "context": {
            "additional": "info",
            "test": "overridden"
        }
    });

    let response = client
        .post(&format!("{}/authorization", server_url))
        .header("content-type", "application/json")
        .json(&request_body)
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), 200);

    let json: Value = response.json().await.unwrap();

    let context = &json["context"];
    assert_eq!(context["additional"], "info");
    assert_eq!(context["test"], "overridden");
}

#[tokio::test]
async fn test_context_merging_recognition() {
    let server_url = get_test_server_url().await;
    let client = reqwest::Client::new();

    let request_body = json!({
        "entity_id": "did:example:entity1",
        "authority_id": "did:example:authority1",
        "action": "action1",
        "resource": "resource1",
        "context": {
            "recognition_context": "specific_info"
        }
    });

    let response = client
        .post(&format!("{}/recognition", server_url))
        .header("content-type", "application/json")
        .json(&request_body)
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), 200);

    let json: Value = response.json().await.unwrap();

    let context = &json["context"];
    assert_eq!(context["recognition_context"], "specific_info");
}

#[tokio::test]
async fn test_cors_headers_present() {
    let server_url = get_test_server_url().await;
    let client = reqwest::Client::new();

    let response = client
        .request(reqwest::Method::OPTIONS, &format!("{}/health", server_url))
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
        .get(&format!("{}/authorization", server_url))
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
        .get(&format!("{}/nonexistent", server_url))
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
        .get(&format!("{}/.well-known/did.json", server_url))
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), 200);

    let doc: Value = response.json().await.unwrap();

    assert!(doc.get("id").is_some(), "DID document should have an 'id' field");
    assert!(doc["@context"].is_array(), "DID document should have '@context' as array");
    assert!(doc["verificationMethod"].is_array(), "DID document should have 'verificationMethod' array");
    assert!(doc["authentication"].is_array(), "DID document should have 'authentication' array");
    assert!(doc["assertionMethod"].is_array(), "DID document should have 'assertionMethod' array");
    assert!(doc["keyAgreement"].is_array(), "DID document should have 'keyAgreement' array");
    assert!(doc["service"].is_array(), "DID document should have 'service' array");
}

#[tokio::test]
async fn test_wellknown_did_document_no_private_keys() {
    let server_url = get_test_server_url().await;
    let client = reqwest::Client::new();

    let response = client
        .get(&format!("{}/.well-known/did.json", server_url))
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
        .get(&format!("{}/.well-known/did.json", server_url))
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), 200);

    let doc: Value = response.json().await.unwrap();

    // Verify DIDComm service is present
    if let Some(services) = doc["service"].as_array() {
        let didcomm_service = services.iter().find(|s| s["type"] == "DIDCommMessaging");
        assert!(didcomm_service.is_some(), "DID document should have a DIDComm service");

        if let Some(service) = didcomm_service {
            assert!(service.get("id").is_some(), "Service should have an id");
            assert_eq!(service["type"], "DIDCommMessaging");
            assert!(service["serviceEndpoint"].get("uri").is_some(), "Service endpoint should have a uri");
            assert!(service["serviceEndpoint"]["accept"].is_array(), "Service endpoint should have accept array");
        }
    }

    // Verify verification methods have correct structure
    if let Some(methods) = doc["verificationMethod"].as_array() {
        for method in methods {
            assert!(method.get("id").is_some(), "Verification method should have an id");
            assert!(method.get("type").is_some(), "Verification method should have a type");
            assert!(method.get("controller").is_some(), "Verification method should have a controller");
            assert!(method.get("publicKeyJwk").is_some(), "Verification method should have publicKeyJwk");

            // Verify publicKeyJwk structure
            let jwk = &method["publicKeyJwk"];
            assert!(jwk.get("kty").is_some(), "JWK should have kty field");
            assert!(jwk.get("crv").is_some(), "JWK should have crv field");
            assert!(jwk.get("x").is_some(), "JWK should have x coordinate");
        }
    }
}
