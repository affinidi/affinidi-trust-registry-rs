use app::configs::Configs;
use std::env;

const DEFAULT_LISTEN_ADDRESS: &str = "0.0.0.0:3232";
const DEFAULT_TRUST_REGISTRY_FILE_PATH: &str = "trust_records.csv";
const DEFAULT_TRUST_REGISTRY_UPDATE_INTERVAL_SEC: u64 = 60;
const DEFAULT_REGION: &str = "ap-southeast-1";

// TODO: move to app to share with didcomm-server
#[derive(Debug, Clone)]
pub enum TrustStorageBackend {
    Csv,
    DynamoDb,
}

#[derive(Debug, Clone)]
pub struct FileStorageConfig {
    pub path: String,
    pub update_interval_sec: u64,
}

#[derive(Debug, Clone)]
pub struct DynamoDbStorageConfig {
    pub table_name: String,
    pub region: Option<String>,
    pub profile: Option<String>,
    pub endpoint_url: Option<String>,
}

#[derive(Debug, Clone)]
pub struct HttpServerConfigs {
    pub(crate) listen_address: String,
    pub(crate) storage_backend: TrustStorageBackend,
    pub(crate) file_storage: Option<FileStorageConfig>,
    pub(crate) dynamodb_storage: Option<DynamoDbStorageConfig>,
}

impl Configs for HttpServerConfigs {
    fn load() -> Result<Self, Box<dyn std::error::Error>> {
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

        let file_storage = Some(FileStorageConfig {
            path: env::var("FILE_STORAGE_PATH")
                .unwrap_or_else(|_| DEFAULT_TRUST_REGISTRY_FILE_PATH.to_string()),
            update_interval_sec: env::var("FILE_STORAGE_UPDATE_INTERVAL_SEC")
                .unwrap_or_else(|_| DEFAULT_TRUST_REGISTRY_UPDATE_INTERVAL_SEC.to_string())
                .parse::<u64>()?,
        });

        let dynamodb_storage =
            env::var("DDB_TABLE_NAME")
                .ok()
                .map(|table_name| DynamoDbStorageConfig {
                    table_name,
                    region: Some(
                        env::var("AWS_REGION").unwrap_or_else(|_| DEFAULT_REGION.to_string()),
                    ),
                    profile: env::var("AWS_PROFILE").ok(),
                    endpoint_url: env::var("AWS_ENDPOINT")
                        .or_else(|_| env::var("DYNAMODB_ENDPOINT"))
                        .ok(),
                });

        if matches!(storage_backend, TrustStorageBackend::DynamoDb) && dynamodb_storage.is_none() {
            return Err("DDB_TABLE_NAME must be set when TR_STORAGE_BACKEND=dynamodb".into());
        }

        Ok(HttpServerConfigs {
            listen_address,
            storage_backend,
            file_storage,
            dynamodb_storage,
        })
    }
}
