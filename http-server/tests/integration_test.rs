use dotenvy::dotenv;
use serde_json::{Value, json};
use serial_test::serial;
use std::{env, time::Duration};

async fn setup_test_environment() -> String {
    dotenv().ok();
    let port = 3233;

    let test_data = "entity_id,authority_id,assertion_id,recognized,assertion_verified,context
did:example:entity1,did:example:authority1,assertion1,true,true,eyJ0ZXN0IjogImNvbnRleHQifQ==
did:example:entity2,did:example:authority2,assertion2,false,true,eyJ0ZXN0IjogImNvbnRleHQifQ==
did:example:entity3,did:example:authority3,assertion3,true,false,eyJ0ZXN0IjogImNvbnRleHQifQ==";
    let temp_file = std::env::temp_dir().join("integration_test_data.csv");
    tokio::fs::write(&temp_file, test_data).await.unwrap();
    if env::var("TR_STORAGE_BACKEND").unwrap_or("csv".to_owned()) == "csv" {
        unsafe {
            env::set_var("FILE_STORAGE_PATH", temp_file.to_str().unwrap());
        }
    }

    // Start the server in a background task
    tokio::spawn(async move {
        http_server::server::start().await;
    });
    // Give the server time to start
    tokio::time::sleep(tokio::time::Duration::from_millis(1000)).await;
    let base_url = format!("http://127.0.0.1:{}", port);

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .unwrap();

    // Try to connect to health endpoint to ensure server is ready
    for attempt in 0..30 {
        match client.get(&format!("{}/health", base_url)).send().await {
            Ok(response) if response.status() == 200 => {
                println!("Test server ready on attempt {}", attempt + 1);
                return base_url;
            }
            Ok(_) => {
                println!(
                    "Server responded but not with 200 status, attempt {}",
                    attempt + 1
                );
            }
            Err(e) => {
                println!("Connection failed on attempt {}: {}", attempt + 1, e);
            }
        }
        tokio::time::sleep(tokio::time::Duration::from_millis(200)).await;
    }
    panic!("Failed to start test server after 30 attempts");
}
async fn get_test_server_url() -> String {
    setup_test_environment().await
}

#[tokio::test]
#[serial]
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
#[serial]
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
#[serial]
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
#[serial]
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
#[serial]
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
#[serial]
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
#[serial]
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
#[serial]
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
#[serial]
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
}

#[tokio::test]
#[serial]
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
#[serial]
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
#[serial]
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
