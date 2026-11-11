use super::{Configs, loaders::environment::*};

const DEFAULT_TRUST_REGISTRY_FILE_PATH: &str = "trust_records.csv";
const DEFAULT_TRUST_REGISTRY_UPDATE_INTERVAL_SEC: u64 = 60;
const DEFAULT_REGION: &str = "ap-southeast-1";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum TrustStorageBackend {
    /// CSV file storage — the default, matching `load_storage_backend`'s fallback.
    #[default]
    Csv,
    DynamoDb,
    Redis,
    /// Embedded fjall LSM store (compiled with `--features storage-fjall`).
    Fjall,
}

const DEFAULT_FJALL_PATH: &str = "./trust_records.fjall";

#[derive(Debug, Clone, Default)]
pub struct FileStorageConfig {
    pub is_enabled: bool,
    pub path: String,
    pub update_interval_sec: u64,
}

#[derive(Clone, Default)]
pub struct DynamoDbStorageConfig {
    pub is_enabled: bool,
    pub table_name: String,
    pub region: Option<String>,
    pub profile: Option<String>,
    pub endpoint_url: Option<String>,
}

impl std::fmt::Debug for DynamoDbStorageConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DynamoDbStorageConfig")
            .field("is_enabled", &self.is_enabled)
            .field("table_name", &self.table_name)
            .field("region", &self.region)
            .field("profile", &self.profile)
            .field(
                "endpoint_url",
                &self.endpoint_url.as_deref().map(redact_url_credentials),
            )
            .finish()
    }
}

/// The Redis connection settings.
///
/// `redis_url` may carry a username and password (`redis://user:pass@host`).
/// `Debug` prints it through [`redact_url_credentials`], so dumping the config
/// never writes them out.
#[derive(Clone, Default)]
pub struct RedisStorageConfig {
    pub is_enabled: bool,
    pub redis_url: String,
}

impl std::fmt::Debug for RedisStorageConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RedisStorageConfig")
            .field("is_enabled", &self.is_enabled)
            .field("redis_url", &redact_url_credentials(&self.redis_url))
            .finish()
    }
}

const REDACTED: &str = "***";

/// Query parameters that carry a credential in a connection URL (the Redis
/// client reads `user` and `pass` from the query of a `redis+unix://` URL).
const CREDENTIAL_QUERY_PARAMS: &[&str] = &["user", "username", "pass", "password"];

/// A connection URL fit for logs: the username, password and any credential
/// query parameter are replaced by `***`; scheme, host, port, path and the
/// remaining query are kept.
///
/// A value that does not parse as a URL is replaced as a whole, since there is
/// no telling which part of it is the secret.
pub fn redact_url_credentials(raw: &str) -> String {
    if raw.is_empty() {
        return String::new();
    }
    let Ok(mut url) = url::Url::parse(raw) else {
        return "<unparseable URL>".to_string();
    };
    if !url.username().is_empty() && url.set_username(REDACTED).is_err() {
        return "<unparseable URL>".to_string();
    }
    if url.password().is_some() && url.set_password(Some(REDACTED)).is_err() {
        return "<unparseable URL>".to_string();
    }
    if url.query().is_some() {
        let pairs: Vec<(String, String)> = url
            .query_pairs()
            .map(|(name, value)| {
                let value = if CREDENTIAL_QUERY_PARAMS
                    .iter()
                    .any(|param| name.eq_ignore_ascii_case(param))
                {
                    REDACTED.to_string()
                } else {
                    value.into_owned()
                };
                (name.into_owned(), value)
            })
            .collect();
        url.query_pairs_mut().clear().extend_pairs(pairs);
    }
    url.to_string()
}

#[derive(Debug, Clone, Default)]
pub struct FjallStorageConfig {
    pub is_enabled: bool,
    pub path: String,
}

#[derive(Debug, Clone, Default)]
pub struct StorageConfig {
    pub ddb_storage_config: DynamoDbStorageConfig,
    pub file_storage_config: FileStorageConfig,
    pub redis_storage_config: RedisStorageConfig,
    pub fjall_storage_config: FjallStorageConfig,
    pub storage_backend: TrustStorageBackend,
}

fn load_storage_backend() -> TrustStorageBackend {
    let storage_backend_str = env_or("TR_STORAGE_BACKEND", "csv").to_lowercase();
    match storage_backend_str.as_str() {
        "dynamodb" | "ddb" => TrustStorageBackend::DynamoDb,
        "redis" => TrustStorageBackend::Redis,
        "fjall" => TrustStorageBackend::Fjall,
        _ => TrustStorageBackend::Csv,
    }
}

#[async_trait::async_trait]
impl Configs for FileStorageConfig {
    async fn load() -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        if load_storage_backend() == TrustStorageBackend::Csv {
            Ok(FileStorageConfig {
                is_enabled: true,
                path: env_or("FILE_STORAGE_PATH", DEFAULT_TRUST_REGISTRY_FILE_PATH),
                update_interval_sec: env_or(
                    "FILE_STORAGE_UPDATE_INTERVAL_SEC",
                    &DEFAULT_TRUST_REGISTRY_UPDATE_INTERVAL_SEC.to_string(),
                )
                .parse::<u64>()?,
            })
        } else {
            Ok(Default::default())
        }
    }
}

#[async_trait::async_trait]
impl Configs for DynamoDbStorageConfig {
    async fn load() -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        if load_storage_backend() == TrustStorageBackend::DynamoDb {
            Ok(DynamoDbStorageConfig {
                is_enabled: true,
                table_name: required_env("DDB_TABLE_NAME")?,
                region: Some(env_or("AWS_REGION", DEFAULT_REGION)),
                profile: optional_env("AWS_PROFILE"),
                endpoint_url: optional_env("AWS_ENDPOINT")
                    .or_else(|| optional_env("DYNAMODB_ENDPOINT")),
            })
        } else {
            Ok(Default::default())
        }
    }
}

#[async_trait::async_trait]
impl Configs for RedisStorageConfig {
    async fn load() -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        if load_storage_backend() == TrustStorageBackend::Redis {
            Ok(RedisStorageConfig {
                is_enabled: true,
                redis_url: required_env("REDIS_URL")?,
            })
        } else {
            Ok(Default::default())
        }
    }
}

#[async_trait::async_trait]
impl Configs for FjallStorageConfig {
    async fn load() -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        if load_storage_backend() == TrustStorageBackend::Fjall {
            Ok(FjallStorageConfig {
                is_enabled: true,
                path: env_or("TR_FJALL_PATH", DEFAULT_FJALL_PATH),
            })
        } else {
            Ok(Default::default())
        }
    }
}

#[async_trait::async_trait]
impl Configs for StorageConfig {
    async fn load() -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let storage_backend = load_storage_backend();
        Ok(StorageConfig {
            ddb_storage_config: DynamoDbStorageConfig::load().await?,
            file_storage_config: FileStorageConfig::load().await?,
            redis_storage_config: RedisStorageConfig::load().await?,
            fjall_storage_config: FjallStorageConfig::load().await?,
            storage_backend,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redaction_removes_username_and_password() {
        let redacted = redact_url_credentials("redis://alice:s3cr3t-pw@cache.internal:6380/2");
        assert_eq!(redacted, "redis://***:***@cache.internal:6380/2");
    }

    #[test]
    fn redaction_removes_password_without_username() {
        let redacted = redact_url_credentials("rediss://:s3cr3t-pw@cache.internal:6380");
        assert!(!redacted.contains("s3cr3t-pw"), "{redacted}");
        assert!(redacted.starts_with("rediss://"), "{redacted}");
        assert!(redacted.contains("cache.internal:6380"), "{redacted}");
    }

    #[test]
    fn redaction_removes_credential_query_parameters() {
        let redacted =
            redact_url_credentials("redis+unix:///run/redis.sock?db=3&user=alice&pass=s3cr3t-pw");
        assert!(!redacted.contains("s3cr3t-pw"), "{redacted}");
        assert!(!redacted.contains("alice"), "{redacted}");
        assert!(redacted.contains("db=3"), "{redacted}");
    }

    #[test]
    fn redaction_keeps_a_url_without_credentials() {
        assert_eq!(
            redact_url_credentials("redis://localhost:6379/"),
            "redis://localhost:6379/"
        );
        assert_eq!(redact_url_credentials(""), "");
    }

    #[test]
    fn redaction_hides_an_unparseable_value_entirely() {
        let redacted = redact_url_credentials("not a url but s3cr3t-pw");
        assert!(!redacted.contains("s3cr3t-pw"), "{redacted}");
    }

    #[test]
    fn config_debug_output_has_no_credentials() {
        let config = crate::configs::TrustRegistryConfig {
            storage_config: StorageConfig {
                redis_storage_config: RedisStorageConfig {
                    is_enabled: true,
                    redis_url: "redis://alice:s3cr3t-pw@cache.internal:6379".to_string(),
                },
                ddb_storage_config: DynamoDbStorageConfig {
                    endpoint_url: Some("https://bob:other-pw@ddb.internal".to_string()),
                    ..Default::default()
                },
                storage_backend: TrustStorageBackend::Redis,
                ..Default::default()
            },
            ..Default::default()
        };
        let dump = format!("{config:?}");
        assert!(!dump.contains("s3cr3t-pw"), "{dump}");
        assert!(!dump.contains("other-pw"), "{dump}");
        assert!(dump.contains("cache.internal:6379"), "{dump}");
    }
}
