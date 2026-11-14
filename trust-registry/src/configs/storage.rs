use tracing::{info, warn};

use super::{Configs, loaders::environment::*};

pub const DEFAULT_TRUST_REGISTRY_FILE_PATH: &str = "trust_records.csv";
pub const DEFAULT_TRUST_REGISTRY_UPDATE_INTERVAL_SEC: u64 = 60;

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

pub const DEFAULT_FJALL_PATH: &str = "./trust_records.fjall";

#[derive(Debug, Clone)]
pub struct FileStorageConfig {
    pub path: String,
    /// How often the file is checked for changes. Must be at least one.
    pub update_interval_sec: u64,
}

/// The same defaults `FILE_STORAGE_PATH` and `FILE_STORAGE_UPDATE_INTERVAL_SEC`
/// take when unset.
impl Default for FileStorageConfig {
    fn default() -> Self {
        Self {
            path: DEFAULT_TRUST_REGISTRY_FILE_PATH.to_string(),
            update_interval_sec: DEFAULT_TRUST_REGISTRY_UPDATE_INTERVAL_SEC,
        }
    }
}

#[derive(Clone, Default)]
pub struct DynamoDbStorageConfig {
    pub table_name: String,
    /// `None` lets the AWS SDK resolve the region (`AWS_DEFAULT_REGION`, the
    /// profile, instance metadata).
    pub region: Option<String>,
    pub profile: Option<String>,
    pub endpoint_url: Option<String>,
    /// Use the SDK's static test credentials, for DynamoDB Local or
    /// LocalStack. Never inferred from the endpoint.
    pub use_test_credentials: bool,
}

impl std::fmt::Debug for DynamoDbStorageConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DynamoDbStorageConfig")
            .field("table_name", &self.table_name)
            .field("region", &self.region)
            .field("profile", &self.profile)
            .field(
                "endpoint_url",
                &self.endpoint_url.as_deref().map(redact_url_credentials),
            )
            .field("use_test_credentials", &self.use_test_credentials)
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
    pub redis_url: String,
}

impl std::fmt::Debug for RedisStorageConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RedisStorageConfig")
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

#[derive(Debug, Clone)]
pub struct FjallStorageConfig {
    pub path: String,
}

/// The same default `TR_FJALL_PATH` takes when unset.
impl Default for FjallStorageConfig {
    fn default() -> Self {
        Self {
            path: DEFAULT_FJALL_PATH.to_string(),
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct StorageConfig {
    pub ddb_storage_config: DynamoDbStorageConfig,
    pub file_storage_config: FileStorageConfig,
    pub redis_storage_config: RedisStorageConfig,
    pub fjall_storage_config: FjallStorageConfig,
    pub storage_backend: TrustStorageBackend,
}

/// The values `TR_STORAGE_BACKEND` accepts, for error messages.
const ACCEPTED_BACKENDS: &str = "'csv', 'dynamodb' (or 'ddb'), 'redis', 'fjall'";

/// Parse a `TR_STORAGE_BACKEND` value. Unset or blank means `csv`; anything
/// that is not one of the accepted names is an error naming the variable, so a
/// typo such as `dynamo` cannot start the registry on the CSV file instead.
pub fn parse_storage_backend(raw: Option<&str>) -> Result<TrustStorageBackend, String> {
    let Some(raw) = raw.map(str::trim).filter(|v| !v.is_empty()) else {
        return Ok(TrustStorageBackend::Csv);
    };
    match raw.to_ascii_lowercase().as_str() {
        "csv" => Ok(TrustStorageBackend::Csv),
        "dynamodb" | "ddb" => Ok(TrustStorageBackend::DynamoDb),
        "redis" => Ok(TrustStorageBackend::Redis),
        "fjall" => Ok(TrustStorageBackend::Fjall),
        _ => Err(format!(
            "TR_STORAGE_BACKEND must be one of {ACCEPTED_BACKENDS} (got '{raw}'); \
             unset means 'csv'"
        )),
    }
}

fn load_storage_backend() -> Result<TrustStorageBackend, String> {
    parse_storage_backend(optional_env("TR_STORAGE_BACKEND").as_deref())
}

impl FileStorageConfig {
    fn from_env() -> Result<Self, String> {
        Ok(FileStorageConfig {
            path: env_or("FILE_STORAGE_PATH", DEFAULT_TRUST_REGISTRY_FILE_PATH),
            update_interval_sec: positive_env(
                "FILE_STORAGE_UPDATE_INTERVAL_SEC",
                DEFAULT_TRUST_REGISTRY_UPDATE_INTERVAL_SEC,
            )?,
        })
    }
}

impl DynamoDbStorageConfig {
    fn from_env() -> Result<Self, String> {
        Ok(DynamoDbStorageConfig {
            table_name: required_env("DDB_TABLE_NAME")?,
            // Unset: the AWS SDK resolves the region itself (AWS_DEFAULT_REGION,
            // the selected profile, instance metadata).
            region: non_empty_env("AWS_REGION"),
            profile: non_empty_env("AWS_PROFILE"),
            endpoint_url: ddb_endpoint_from_env()?,
            use_test_credentials: env_flag("DDB_USE_TEST_CREDENTIALS", false)?,
        })
    }
}

/// `DYNAMODB_ENDPOINT`, or the deprecated `AWS_ENDPOINT` spelling. Both set to
/// different values is an error rather than a silent pick of one.
fn ddb_endpoint_from_env() -> Result<Option<String>, String> {
    let current = non_empty_env("DYNAMODB_ENDPOINT");
    let deprecated = non_empty_env("AWS_ENDPOINT");
    match (current, deprecated) {
        (Some(current), Some(deprecated)) if current != deprecated => Err(
            "DYNAMODB_ENDPOINT and the deprecated AWS_ENDPOINT are both set, to different \
             values; set DYNAMODB_ENDPOINT only"
                .to_string(),
        ),
        (Some(current), _) => Ok(Some(current)),
        (None, Some(deprecated)) => {
            warn!("AWS_ENDPOINT is deprecated for the DynamoDB backend; use DYNAMODB_ENDPOINT");
            Ok(Some(deprecated))
        }
        (None, None) => Ok(None),
    }
}

impl RedisStorageConfig {
    fn from_env() -> Result<Self, String> {
        Ok(RedisStorageConfig {
            redis_url: required_env("REDIS_URL")?,
        })
    }
}

impl FjallStorageConfig {
    fn from_env() -> Self {
        FjallStorageConfig {
            path: env_or("TR_FJALL_PATH", DEFAULT_FJALL_PATH),
        }
    }
}

/// Each sub-config loads its own settings only when `TR_STORAGE_BACKEND`
/// selects it, and the default value otherwise.
macro_rules! load_when_selected {
    ($ty:ty, $backend:expr, $from_env:expr) => {
        #[async_trait::async_trait]
        impl Configs for $ty {
            async fn load() -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
                if load_storage_backend()? == $backend {
                    Ok($from_env)
                } else {
                    Ok(Default::default())
                }
            }
        }
    };
}

load_when_selected!(
    FileStorageConfig,
    TrustStorageBackend::Csv,
    FileStorageConfig::from_env()?
);
load_when_selected!(
    DynamoDbStorageConfig,
    TrustStorageBackend::DynamoDb,
    DynamoDbStorageConfig::from_env()?
);
load_when_selected!(
    RedisStorageConfig,
    TrustStorageBackend::Redis,
    RedisStorageConfig::from_env()?
);
load_when_selected!(
    FjallStorageConfig,
    TrustStorageBackend::Fjall,
    FjallStorageConfig::from_env()
);

#[async_trait::async_trait]
impl Configs for StorageConfig {
    async fn load() -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        // Read once: every sub-config below follows this one value.
        let storage_backend = load_storage_backend()?;
        let mut config = StorageConfig {
            storage_backend,
            ..Default::default()
        };
        let location = match storage_backend {
            TrustStorageBackend::Csv => {
                config.file_storage_config = FileStorageConfig::from_env()?;
                config.file_storage_config.path.clone()
            }
            TrustStorageBackend::DynamoDb => {
                config.ddb_storage_config = DynamoDbStorageConfig::from_env()?;
                format!("table {}", config.ddb_storage_config.table_name)
            }
            TrustStorageBackend::Redis => {
                config.redis_storage_config = RedisStorageConfig::from_env()?;
                redact_url_credentials(&config.redis_storage_config.redis_url)
            }
            TrustStorageBackend::Fjall => {
                config.fjall_storage_config = FjallStorageConfig::from_env();
                config.fjall_storage_config.path.clone()
            }
        };
        info!(backend = ?storage_backend, location = %location, "trust record storage selected");
        Ok(config)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serial_test::serial;

    const STORAGE_VARS: &[&str] = &[
        "TR_STORAGE_BACKEND",
        "FILE_STORAGE_PATH",
        "FILE_STORAGE_UPDATE_INTERVAL_SEC",
        "DDB_TABLE_NAME",
        "AWS_REGION",
        "AWS_PROFILE",
        "AWS_ENDPOINT",
        "DYNAMODB_ENDPOINT",
        "DDB_USE_TEST_CREDENTIALS",
        "REDIS_URL",
        "TR_FJALL_PATH",
    ];

    fn clear_storage_env() {
        for k in STORAGE_VARS {
            unsafe { std::env::remove_var(k) };
        }
    }

    #[test]
    fn storage_backend_accepts_each_documented_name() {
        assert_eq!(parse_storage_backend(None), Ok(TrustStorageBackend::Csv));
        assert_eq!(
            parse_storage_backend(Some(" ")),
            Ok(TrustStorageBackend::Csv)
        );
        for (raw, expected) in [
            ("csv", TrustStorageBackend::Csv),
            ("DynamoDB", TrustStorageBackend::DynamoDb),
            ("ddb", TrustStorageBackend::DynamoDb),
            (" redis ", TrustStorageBackend::Redis),
            ("fjall", TrustStorageBackend::Fjall),
        ] {
            assert_eq!(parse_storage_backend(Some(raw)), Ok(expected), "{raw}");
        }
    }

    /// A misspelt backend used to start the registry on the CSV file.
    #[test]
    fn an_unknown_storage_backend_is_an_error_naming_the_variable() {
        for raw in ["dynamo", "reddis", "fjal", "file"] {
            let err = parse_storage_backend(Some(raw)).expect_err(raw);
            assert!(err.contains("TR_STORAGE_BACKEND"), "{err}");
            assert!(err.contains(raw), "{err}");
            assert!(err.contains("'redis'"), "{err}");
        }
    }

    #[tokio::test]
    #[serial]
    async fn an_unknown_storage_backend_stops_configuration() {
        clear_storage_env();
        unsafe { std::env::set_var("TR_STORAGE_BACKEND", "dynamo") };
        let err = StorageConfig::load().await.expect_err("refused");
        assert!(err.to_string().contains("TR_STORAGE_BACKEND"), "{err}");
        let err = FileStorageConfig::load().await.expect_err("refused");
        assert!(err.to_string().contains("TR_STORAGE_BACKEND"), "{err}");
        clear_storage_env();
    }

    #[tokio::test]
    #[serial]
    async fn the_csv_defaults_match_the_default_impl() {
        clear_storage_env();
        let loaded = StorageConfig::load().await.expect("defaults load");
        let default = FileStorageConfig::default();
        assert_eq!(loaded.storage_backend, TrustStorageBackend::Csv);
        assert_eq!(loaded.file_storage_config.path, default.path);
        assert_eq!(
            loaded.file_storage_config.update_interval_sec,
            default.update_interval_sec
        );
        assert_eq!(
            FjallStorageConfig::default().path,
            FjallStorageConfig::from_env().path
        );
    }

    #[tokio::test]
    #[serial]
    async fn a_bad_or_zero_update_interval_is_an_error_naming_the_variable() {
        for raw in ["0", "sixty", "-1"] {
            clear_storage_env();
            unsafe { std::env::set_var("FILE_STORAGE_UPDATE_INTERVAL_SEC", raw) };
            let err = StorageConfig::load().await.expect_err(raw);
            assert!(
                err.to_string().contains("FILE_STORAGE_UPDATE_INTERVAL_SEC"),
                "{err}"
            );
        }
        clear_storage_env();
    }

    /// The region is the SDK's to resolve unless `AWS_REGION` is set, and the
    /// test credentials are used only on request, never because the endpoint
    /// URL happens to contain "local".
    #[tokio::test]
    #[serial]
    async fn ddb_region_and_test_credentials_are_explicit() {
        clear_storage_env();
        unsafe {
            std::env::set_var("TR_STORAGE_BACKEND", "ddb");
            std::env::set_var("DDB_TABLE_NAME", "records");
            std::env::set_var(
                "DYNAMODB_ENDPOINT",
                "http://dynamodb.data.svc.cluster.local:8000",
            );
        }
        let ddb = StorageConfig::load()
            .await
            .expect("loads")
            .ddb_storage_config;
        assert_eq!(ddb.region, None);
        assert!(!ddb.use_test_credentials);
        assert_eq!(
            ddb.endpoint_url.as_deref(),
            Some("http://dynamodb.data.svc.cluster.local:8000")
        );

        unsafe {
            std::env::set_var("AWS_REGION", "eu-west-1");
            std::env::set_var("DDB_USE_TEST_CREDENTIALS", "true");
        }
        let ddb = StorageConfig::load()
            .await
            .expect("loads")
            .ddb_storage_config;
        assert_eq!(ddb.region.as_deref(), Some("eu-west-1"));
        assert!(ddb.use_test_credentials);

        unsafe { std::env::set_var("DDB_USE_TEST_CREDENTIALS", "local") };
        let err = StorageConfig::load().await.expect_err("not a boolean");
        assert!(
            err.to_string().contains("DDB_USE_TEST_CREDENTIALS"),
            "{err}"
        );
        clear_storage_env();
    }

    #[tokio::test]
    #[serial]
    async fn ddb_endpoint_spellings_must_agree() {
        clear_storage_env();
        unsafe {
            std::env::set_var("TR_STORAGE_BACKEND", "dynamodb");
            std::env::set_var("DDB_TABLE_NAME", "records");
            std::env::set_var("AWS_ENDPOINT", "http://127.0.0.1:4566");
        }
        let ddb = StorageConfig::load()
            .await
            .expect("loads")
            .ddb_storage_config;
        assert_eq!(ddb.endpoint_url.as_deref(), Some("http://127.0.0.1:4566"));

        unsafe { std::env::set_var("DYNAMODB_ENDPOINT", "http://127.0.0.1:8000") };
        let err = StorageConfig::load().await.expect_err("conflict");
        assert!(err.to_string().contains("DYNAMODB_ENDPOINT"), "{err}");
        clear_storage_env();
    }

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
