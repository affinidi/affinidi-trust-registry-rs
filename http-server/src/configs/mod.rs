use app::configs::{Configs, TrustStorageBackend, did_document_loader::DidDocumentLoader};
use async_trait::async_trait;
use serde_json::Value;
use std::env;

const DEFAULT_LISTEN_ADDRESS: &str = "0.0.0.0:3232";

#[derive(Debug, Clone)]
pub struct HttpServerConfigs {
    pub(crate) listen_address: String,
    pub(crate) storage_backend: TrustStorageBackend,
    pub(crate) cors_allowed_origins: Vec<String>,
    pub(crate) did_web_document: Option<Value>,
}

#[async_trait]
impl Configs for HttpServerConfigs {
    async fn load() -> Result<Self, Box<dyn std::error::Error>> {
        let backend = env::var("TR_STORAGE_BACKEND")
            .unwrap_or_else(|_| "csv".into())
            .to_lowercase();

        let storage_backend = match backend.as_str() {
            "csv" => TrustStorageBackend::Csv,
            "ddb" | "dynamodb" => TrustStorageBackend::DynamoDb,
            other => return Err(format!("Unsupported TR_STORAGE_BACKEND={other}").into()),
        };

        let listen_address =
            env::var("LISTEN_ADDRESS").unwrap_or(DEFAULT_LISTEN_ADDRESS.to_string());

        let cors_allowed_origins = env::var("CORS_ALLOWED_ORIGINS")
            .unwrap_or_else(|_| String::new())
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();

        let mut did_web_document = None;
        if let Some(path) = env::var("DID_WEB_DOCUMENT_PATH").ok() {
            let loader = DidDocumentLoader::new(&path)
                .map_err(|e| format!("Failed to parse DID_WEB_DOCUMENT_PATH: {}", e))?;
            let document = loader.load().await
                .map_err(|e| format!("Failed to load DID document: {}", e))?;
            let json_document: Value = serde_json::from_str(&document)
                .map_err(|e| format!("Failed to parse DID document: {}", e))?;
            did_web_document = Some(json_document);
        }

        Ok(HttpServerConfigs {
            listen_address,
            storage_backend,
            cors_allowed_origins,
            did_web_document,
        })
    }
}
