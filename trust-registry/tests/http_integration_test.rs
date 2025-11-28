use serde_json::{Value, json};
use std::env;

async fn setup_test_environment() -> String {
    dotenvy::from_filename(".env.test").ok();
    let address = env::var("LISTEN_ADDRESS").unwrap_or("http://127.0.0.1:3233".to_string());
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
