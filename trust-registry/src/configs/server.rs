use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use super::{Configs, loaders::environment::*};
use crate::http::limits::HttpLimits;

const DEFAULT_LISTEN_ADDRESS: &str = "0.0.0.0:3232";
pub const DEFAULT_CAPABILITY_STATE_PATH: &str = "./.trust-registry/capabilities.json";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProfileConfig {
    pub did: String,
}

#[derive(Debug, Clone)]
pub struct ServerConfig {
    pub listen_address: String,
    /// Origins the standalone service answers cross-origin browser requests
    /// from. Empty means none (no CORS layer, so browsers allow same-origin
    /// requests only); `["*"]` means any. Otherwise each entry is a serialized
    /// origin such as `https://app.example.com`; see
    /// [`validate_cors_origins`].
    pub cors_allowed_origins: Vec<String>,
    /// Where capability enablement state is persisted.
    ///
    /// `None` means "use [`DEFAULT_CAPABILITY_STATE_PATH`]", which is relative
    /// to the process working directory. A host embedding the registry should
    /// set this explicitly: the default would otherwise land the registry's
    /// state file in whatever directory the host happens to run from, and two
    /// embedded registries in one process would silently share it.
    pub capability_state_path: Option<PathBuf>,
    /// Bounds on HTTP requests and connections. The body limit applies to the
    /// application routes wherever they are mounted; the rest are applied by
    /// the standalone service.
    pub http_limits: HttpLimits,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            listen_address: DEFAULT_LISTEN_ADDRESS.to_string(),
            cors_allowed_origins: Vec::new(),
            capability_state_path: None,
            http_limits: HttpLimits::default(),
        }
    }
}

impl ServerConfig {
    /// The capability state path to use, applying the default when unset.
    pub fn capability_state_path(&self) -> PathBuf {
        self.capability_state_path
            .clone()
            .unwrap_or_else(|| PathBuf::from(DEFAULT_CAPABILITY_STATE_PATH))
    }
}

#[async_trait::async_trait]
impl Configs for ServerConfig {
    async fn load() -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let listen_address = env_or("LISTEN_ADDRESS", DEFAULT_LISTEN_ADDRESS);

        let cors_allowed_origins: Vec<String> = optional_env("CORS_ALLOWED_ORIGINS")
            .unwrap_or_default()
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();
        validate_cors_origins(&cors_allowed_origins)
            .map_err(|e| format!("CORS_ALLOWED_ORIGINS: {e}"))?;

        Ok(ServerConfig {
            listen_address,
            cors_allowed_origins,
            capability_state_path: optional_env("TR_CAPABILITY_STATE").map(PathBuf::from),
            http_limits: HttpLimits::from_env()?,
        })
    }
}

/// Check a CORS origin list: empty (no cross-origin access), exactly `*`
/// (any origin), or `http`/`https` origins written as a browser sends them in
/// the `Origin` header (`scheme://host[:port]`, lower-case host, no default
/// port, no path or trailing `/`). An entry in any other form could never
/// match a request, so it is an error naming the entry rather than being
/// dropped.
pub fn validate_cors_origins(origins: &[String]) -> Result<(), String> {
    if origins.iter().any(|o| o == "*") {
        return if origins.len() == 1 {
            Ok(())
        } else {
            Err("'*' allows every origin and cannot be combined with other entries".to_string())
        };
    }
    for origin in origins {
        let parsed =
            url::Url::parse(origin).map_err(|e| format!("'{origin}' is not an origin ({e})"))?;
        if !matches!(parsed.scheme(), "http" | "https") {
            return Err(format!("'{origin}' must be an http or https origin"));
        }
        let canonical = parsed.origin().ascii_serialization();
        if canonical != *origin {
            return Err(format!(
                "'{origin}' is not an origin as a browser sends it; did you mean '{canonical}'?"
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::validate_cors_origins;

    fn list(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn empty_wildcard_and_origin_lists_are_accepted() {
        assert!(validate_cors_origins(&[]).is_ok());
        assert!(validate_cors_origins(&list(&["*"])).is_ok());
        assert!(
            validate_cors_origins(&list(&[
                "http://localhost:3000",
                "https://app.example.com",
                "https://[::1]:8443",
            ]))
            .is_ok()
        );
    }

    #[test]
    fn an_entry_that_is_not_an_origin_is_an_error_naming_it() {
        for bad in [
            "localhost:3000",
            "app.example.com",
            "ftp://files.example.com",
            "https://app.example.com/",
            "https://app.example.com/path",
            "https://App.Example.com",
            "https://app.example.com:443",
            "https://user@app.example.com",
            "null",
        ] {
            let err = validate_cors_origins(&list(&["https://ok.example", bad])).expect_err(bad);
            assert!(err.contains(bad), "{bad}: {err}");
        }
    }

    #[test]
    fn a_wildcard_cannot_be_combined_with_origins() {
        let err = validate_cors_origins(&list(&["*", "https://app.example.com"])).unwrap_err();
        assert!(err.contains('*'), "{err}");
    }
}
