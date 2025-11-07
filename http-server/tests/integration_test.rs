use once_cell::sync::Lazy;
use serde_json::{Value, json};
use std::{env, time::Duration};
use tokio::sync::{Mutex, MutexGuard};
use tokio::task::JoinHandle;

static SERVER_HANDLE: Lazy<Mutex<Option<tokio::task::JoinHandle<()>>>> =
    Lazy::new(|| Mutex::new(None));
static SERVER_URL: &str = "http://127.0.0.1:3233";

async fn setup_test_environment() {
    let port = 3233;

    unsafe {
        env::set_var("LISTEN_ADDRESS", &format!("127.0.0.1:{}", port));
        env::set_var("CORS_ALLOWED_ORIGINS", "http://localhost:3000");
    }

    let test_data = "entity_id,authority_id,assertion_id,recognized,assertion_verified,context
did:example:entity1,did:example:authority1,assertion1,true,true,eyJ0ZXN0IjogImNvbnRleHQifQ==
did:example:entity2,did:example:authority2,assertion2,false,true,eyJ0ZXN0IjogImNvbnRleHQifQ==
did:example:entity3,did:example:authority3,assertion3,true,false,eyJ0ZXN0IjogImNvbnRleHQifQ==";

    let temp_file = std::env::temp_dir().join("integration_test_data.csv");
    tokio::fs::write(&temp_file, test_data).await.unwrap();

    unsafe {
        env::set_var("FILE_STORAGE_PATH", temp_file.to_str().unwrap());
    }
}

async fn is_server_alive() -> bool {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()
        .unwrap();

    matches!(
        client.get(&format!("{}/health", SERVER_URL)).send().await,
        Ok(response) if response.status() == 200
    )
}

async fn start_server(handle_guard: MutexGuard<'_, Option<JoinHandle<()>>>) {
    setup_test_environment().await;

    drop(handle_guard);
    let handle = tokio::spawn(async move {
        http_server::server::start().await;
    });

    *SERVER_HANDLE.lock().await = Some(handle);

    // Wait for server to be ready
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .unwrap();

    for attempt in 0..30 {
        match client.get(&format!("{}/health", SERVER_URL)).send().await {
            Ok(response) if response.status() == 200 => {
                println!("Test server ready on attempt {}", attempt + 1);
                return;
            }
            _ => {
                tokio::time::sleep(Duration::from_millis(200)).await;
            }
        }
    }

    panic!("Failed to start test server after 30 attempts");
}

async fn get_test_server_url() -> String {
    let mut handle_guard = SERVER_HANDLE.lock().await;

    // Check if server handle exists and is still running
    let needs_restart = match &*handle_guard {
        None => true,
        Some(handle) => handle.is_finished(),
    };

    drop(handle_guard);

    if needs_restart || !is_server_alive().await {
        println!("Server is dead or not running, restarting...");

        // Kill old handle if it exists
        let mut handle_guard = SERVER_HANDLE.lock().await;
        if let Some(handle) = handle_guard.take() {
            handle.abort();
        }

        start_server(handle_guard).await;
    }

    SERVER_URL.to_string()
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
        "assertion_id": "assertion1"
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

    // Check that the response contains expected fields
    assert!(json.get("entity_id").is_some());
    assert!(json.get("authority_id").is_some());
    assert!(json.get("assertion_id").is_some());
    assert!(json.get("time_requested").is_some());
    assert!(json.get("time_evaluated").is_some());
    assert!(json.get("message").is_some());

    // Check that assertion_verified is None (removed for recognition)
    assert_eq!(json.get("assertion_verified"), None);

    // Check message format
    let message = json["message"].as_str().unwrap();
    assert!(message.contains("recognized to"));
}

#[tokio::test]
async fn test_authorization_endpoint_success() {
    let server_url = get_test_server_url().await;
    let client = reqwest::Client::new();

    let request_body = json!({
        "entity_id": "did:example:entity1",
        "authority_id": "did:example:authority1",
        "assertion_id": "assertion1"
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

    // Check that the response contains expected fields
    assert!(json.get("entity_id").is_some());
    assert!(json.get("authority_id").is_some());
    assert!(json.get("assertion_id").is_some());
    assert!(json.get("time_requested").is_some());
    assert!(json.get("time_evaluated").is_some());
    assert!(json.get("message").is_some());

    // Check that recognized is None (removed for authorization)
    assert_eq!(json.get("recognized"), None);

    // Check message format
    let message = json["message"].as_str().unwrap();
    assert!(message.contains("authorized to"));
}

#[tokio::test]
async fn test_authorization_endpoint_not_found() {
    let server_url = get_test_server_url().await;
    let client = reqwest::Client::new();

    let request_body = json!({
        "entity_id": "did:example:nonexistent",
        "authority_id": "did:example:authority1",
        "assertion_id": "assertion1"
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
        "assertion_id": "assertion1"
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

    // Missing required fields
    let request_body = json!({
        "entity_id": "did:example:entity1",
        "authority_id": "did:example:authority1"
        // Missing assertion_id
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

    // Invalid JSON
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
        "assertion_id": "assertion1",
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
    assert_eq!(context["test"], "overridden"); // Should be overridden by request context
}

#[tokio::test]
async fn test_context_merging_recognition() {
    let server_url = get_test_server_url().await;
    let client = reqwest::Client::new();

    let request_body = json!({
        "entity_id": "did:example:entity1",
        "authority_id": "did:example:authority1",
        "assertion_id": "assertion1",
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
    assert_eq!(context["test"], "context"); // Original context should be preserved
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

    // Check that CORS headers are present
    let headers = response.headers();
    assert!(headers.contains_key("access-control-allow-origin"));
}

#[tokio::test]
async fn test_method_not_allowed() {
    let server_url = get_test_server_url().await;
    let client = reqwest::Client::new();

    let response = client
        .get(&format!("{}/authorization", server_url)) // Should only accept POST
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
async fn test_authorization_with_empty_context() {
    let server_url = get_test_server_url().await;
    let client = reqwest::Client::new();

    let request_body = json!({
        "entity_id": "did:example:entity1",
        "authority_id": "did:example:authority1",
        "assertion_id": "assertion1",
        "context": {}
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

    // Should still contain original context
    let context = &json["context"];
    assert_eq!(context["test"], "context");
}

#[tokio::test]
async fn test_authorization_without_context() {
    let server_url = get_test_server_url().await;
    let client = reqwest::Client::new();

    let request_body = json!({
        "entity_id": "did:example:entity1",
        "authority_id": "did:example:authority1",
        "assertion_id": "assertion1"
        // No context field
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

    // Should contain original context from stored record
    let context = &json["context"];
    assert_eq!(context["test"], "context");
}
