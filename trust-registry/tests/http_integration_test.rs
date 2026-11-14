// `std::env::set_var` is unsafe since edition 2024.
#![allow(unsafe_code)]
// Test code: a panic on an unexpected `Err`/`None` is the failure report.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use serde_json::{Value, json};
use std::env;

/// The address of the registry under test. These tests talk to a server
/// started separately (CI starts it on `sample-data/data.csv`), so its data
/// is whatever that server was started with; nothing set here can change it.
async fn setup_test_environment() -> String {
    dotenvy::from_filename(".env.test").ok();
    env::var("LISTEN_ADDRESS")
        .map(|address| format!("http://{}", address))
        .unwrap_or("http://0.0.0.0:3232".to_string())
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
        .post(format!("{}/recognition", server_url))
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
        .post(format!("{}/authorization", server_url))
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
        .post(format!("{}/authorization", server_url))
        .header("content-type", "application/json")
        .json(&request_body)
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), 404);

    assert_eq!(
        response.headers()["content-type"],
        "application/problem+json",
        "TRQP errors are RFC 9457 Problem Details"
    );
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
        .post(format!("{}/recognition", server_url))
        .header("content-type", "application/json")
        .json(&request_body)
        .send()
        .await
        .expect("Failed to send recognition not found request");

    assert_eq!(response.status(), 404);

    assert_eq!(
        response.headers()["content-type"],
        "application/problem+json",
        "TRQP errors are RFC 9457 Problem Details"
    );
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
        .post(format!("{}/authorization", server_url))
        .header("content-type", "application/json")
        .json(&request_body)
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), 400);

    assert_eq!(
        response.headers()["content-type"],
        "application/problem+json",
        "TRQP errors are RFC 9457 Problem Details"
    );
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
        .post(format!("{}/recognition", server_url))
        .header("content-type", "application/json")
        .body(invalid_json)
        .send()
        .await
        .expect("Failed to send recognition bad request");

    assert_eq!(response.status(), 400);

    assert_eq!(
        response.headers()["content-type"],
        "application/problem+json",
        "TRQP errors are RFC 9457 Problem Details"
    );
    let json: Value = response.json().await.unwrap();

    assert_eq!(json["title"], "bad_request");
    assert_eq!(json["type"], "about:blank");
    assert_eq!(json["code"], 400);
}

#[tokio::test]
async fn test_request_context_is_not_merged_authorization() {
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
        .post(format!("{}/authorization", server_url))
        .header("content-type", "application/json")
        .json(&request_body)
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), 200);

    let json: Value = response.json().await.unwrap();

    // The answer carries the record's stored context as stored; the request's
    // context is neither merged in nor allowed to override it.
    let context = &json["context"];
    assert!(context.get("additional").is_none(), "{context}");
    assert_ne!(context["test"], "overridden", "{context}");
}

#[tokio::test]
async fn test_request_context_is_not_merged_recognition() {
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
        .post(format!("{}/recognition", server_url))
        .header("content-type", "application/json")
        .json(&request_body)
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), 200);

    let json: Value = response.json().await.unwrap();

    let context = &json["context"];
    assert!(context.get("recognition_context").is_none(), "{context}");
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
        .get(format!("{}/authorization", server_url))
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

/// Every object member named `name` anywhere in `value`, by JSON path.
fn find_members(value: &Value, name: &str, path: &str, out: &mut Vec<String>) {
    match value {
        Value::Object(map) => {
            for (key, child) in map {
                let child_path = format!("{path}.{key}");
                if key == name {
                    out.push(child_path.clone());
                }
                find_members(child, name, &child_path, out);
            }
        }
        Value::Array(items) => {
            for (i, child) in items.iter().enumerate() {
                find_members(child, name, &format!("{path}[{i}]"), out);
            }
        }
        _ => {}
    }
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

    // No private key material in any form, anywhere in the document.
    for name in ["privateKeyJwk", "privateKeyMultibase", "d"] {
        let mut found = Vec::new();
        find_members(&doc, name, "$", &mut found);
        assert!(
            found.is_empty(),
            "the served DID document carries private key material at {found:?}"
        );
    }
}

/// The secrets the running registry was configured with, when `.env.test`
/// holds the profile inline (as the CI pipeline's does).
fn configured_secrets() -> Option<Vec<Value>> {
    let raw = env::var("PROFILE_CONFIG").ok()?;
    let raw = raw.trim().trim_matches('\'');
    let profile: Value = serde_json::from_str(raw).ok()?;
    profile["secrets"].as_array().cloned()
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

    // Every verification method is a Multikey with a public multibase key.
    let methods = doc["verificationMethod"]
        .as_array()
        .expect("verificationMethod array");
    assert!(!methods.is_empty(), "the document publishes no key");
    for method in methods {
        assert!(method["id"].is_string(), "verification method id: {method}");
        assert_eq!(method["type"], "Multikey", "{method}");
        assert!(method["controller"].is_string(), "{method}");
        assert!(
            method["publicKeyMultibase"]
                .as_str()
                .is_some_and(|k| k.starts_with('z')),
            "publicKeyMultibase must be a base58btc multikey: {method}"
        );
        assert!(method.get("publicKeyJwk").is_none(), "{method}");
    }
    let method_ids: Vec<&str> = methods.iter().filter_map(|m| m["id"].as_str()).collect();

    // The ids are the configured secrets' own ids, not positional ones.
    if let Some(secrets) = configured_secrets() {
        let secret_ids: Vec<&str> = secrets.iter().filter_map(|s| s["id"].as_str()).collect();
        assert_eq!(
            method_ids, secret_ids,
            "verification methods must carry the profile's secret ids"
        );
    }

    // X25519 keys (multicodec 0xec, `z6LS…`) only under keyAgreement; every
    // relationship references a published method.
    let refs = |rel: &str| -> Vec<String> {
        doc[rel]
            .as_array()
            .map(|a| {
                a.iter()
                    .filter_map(|v| v.as_str().map(str::to_string))
                    .collect()
            })
            .unwrap_or_default()
    };
    let is_x25519 = |id: &str| {
        methods.iter().any(|m| {
            m["id"] == id
                && m["publicKeyMultibase"]
                    .as_str()
                    .is_some_and(|k| k.starts_with("z6LS"))
        })
    };
    for rel in ["authentication", "assertionMethod"] {
        for id in refs(rel) {
            assert!(
                method_ids.contains(&id.as_str()),
                "{rel} names unknown {id}"
            );
            assert!(!is_x25519(&id), "an X25519 key is listed under {rel}: {id}");
        }
    }
    let key_agreement = refs("keyAgreement");
    assert!(!key_agreement.is_empty(), "keyAgreement is empty");
    for id in &key_agreement {
        assert!(
            method_ids.contains(&id.as_str()),
            "keyAgreement names unknown {id}"
        );
    }
    for method in methods {
        let id = method["id"].as_str().unwrap_or_default();
        if is_x25519(id) {
            assert!(
                key_agreement.iter().any(|k| k == id),
                "X25519 key {id} must be under keyAgreement"
            );
        }
    }
}
