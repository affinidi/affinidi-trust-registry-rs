//! The `trust-registry` binary under test, spawned against the mediator.

use std::fs::File;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use serde_json::{Value, json};

use super::client::{IdentityKeys, generate_identity};
use super::docker::{env_or, free_port};

/// Seed rows for the CSV store, in `sample-data/data.csv`'s format.
pub const CSV_HEADER: &str =
    "entity_id,authority_id,action,resource,recognized,authorized,context,record_type";

pub struct RegistrySettings<'a> {
    pub mediator_did: &'a str,
    /// DIDs allowed to write records (`ADMIN_DIDS`).
    pub admin_did: &'a str,
    /// CSV rows (without the header) the registry starts with.
    pub records: &'a [&'a str],
    pub keys: IdentityKeys,
    /// `ACL_MODE`: `ExplicitDeny` (public) or `ExplicitAllow` (private).
    pub acl_mode: &'a str,
}

pub struct RegistryProcess {
    child: Child,
    pub base_url: String,
    /// The registry's DIDComm identity (`PROFILE_CONFIG.did`).
    pub did: String,
    log_path: PathBuf,
    // The working directory: holds the CSV store and the log, and has no `.env`
    // for the binary's `dotenv()` to pick up.
    _workdir: tempfile::TempDir,
}

impl RegistryProcess {
    pub async fn start(settings: &RegistrySettings<'_>) -> Result<Self, String> {
        let (did, secrets) = generate_identity(settings.mediator_did, settings.keys)?;
        let profile = json!({ "did": did, "alias": "Trust Registry (e2e)", "secrets": secrets });
        let port = free_port()?;
        let workdir = tempfile::tempdir().map_err(|e| format!("temp dir: {e}"))?;

        let csv_path = workdir.path().join("data.csv");
        let mut csv = vec![CSV_HEADER];
        csv.extend(settings.records);
        std::fs::write(&csv_path, csv.join("\n") + "\n").map_err(|e| format!("CSV: {e}"))?;

        let log_path = workdir.path().join("trust-registry.log");
        let log = File::create(&log_path).map_err(|e| format!("log: {e}"))?;
        let stderr = log.try_clone().map_err(|e| format!("log: {e}"))?;

        // A clean environment: nothing from the developer's shell or `.env`
        // (another storage backend, a secret store, TSP) leaks into the run.
        let child = Command::new(env!("CARGO_BIN_EXE_trust-registry"))
            .current_dir(workdir.path())
            .env_clear()
            .env("PATH", std::env::var("PATH").unwrap_or_default())
            .env("RUST_LOG", env_or("E2E_TR_LOG", "info"))
            .env("LISTEN_ADDRESS", format!("127.0.0.1:{port}"))
            .env("ENABLE_REST", "true")
            .env("ENABLE_DIDCOMM", "true")
            .env("ENABLE_TSP", "false")
            .env("TR_STORAGE_BACKEND", "csv")
            .env("FILE_STORAGE_PATH", &csv_path)
            .env("TR_SECRETS_DATA_DIR", workdir.path())
            .env("MEDIATOR_DID", settings.mediator_did)
            .env("PROFILE_CONFIG", profile.to_string())
            .env("ADMIN_DIDS", settings.admin_did)
            .env("ACL_MODE", settings.acl_mode)
            .env("AUDIT_LOG_FORMAT", "json")
            .stdin(Stdio::null())
            .stdout(log)
            .stderr(stderr)
            .spawn()
            .map_err(|e| format!("spawn trust-registry: {e}"))?;

        let mut registry = Self {
            child,
            base_url: format!("http://127.0.0.1:{port}"),
            did,
            log_path,
            _workdir: workdir,
        };
        registry
            .wait_for_health(Duration::from_secs(60), |_| true)
            .await?;
        Ok(registry)
    }

    /// Poll `/health` until its body satisfies `ready`, and return that body.
    /// `"status"` is `"OK"` while the DIDComm write path is up and
    /// `"degraded"` once the listener has stopped, with the reason in
    /// `"detail"`.
    pub async fn wait_for_health(
        &mut self,
        timeout: Duration,
        ready: impl Fn(&Value) -> bool,
    ) -> Result<Value, String> {
        let url = format!("{}/health", self.base_url);
        let client = reqwest::Client::new();
        let deadline = Instant::now() + timeout;
        let mut last = Value::Null;
        while Instant::now() < deadline {
            self.ensure_running()?;
            if let Ok(response) = client
                .get(&url)
                .timeout(Duration::from_secs(2))
                .send()
                .await
            {
                last = response.json().await.unwrap_or(Value::Null);
                if !last.is_null() && ready(&last) {
                    return Ok(last);
                }
            }
            tokio::time::sleep(Duration::from_millis(300)).await;
        }
        Err(format!(
            "trust-registry /health not as expected after {timeout:?} (last: {last})\n{}",
            self.log_tail(60)
        ))
    }

    pub fn ensure_running(&mut self) -> Result<(), String> {
        match self.child.try_wait() {
            Ok(None) => Ok(()),
            Ok(Some(status)) => Err(format!(
                "trust-registry exited ({status})\n{}",
                self.log_tail(80)
            )),
            Err(e) => Err(format!("trust-registry status: {e}")),
        }
    }

    /// Whether the registry's log contains `needle`.
    pub fn log_contains(&self, needle: &str) -> bool {
        std::fs::read_to_string(&self.log_path)
            .map(|log| log.contains(needle))
            .unwrap_or(false)
    }

    pub fn log_tail(&self, lines: usize) -> String {
        let log = std::fs::read_to_string(&self.log_path).unwrap_or_default();
        let mut tail: Vec<&str> = log.lines().rev().take(lines).collect();
        tail.reverse();
        format!(
            "--- trust-registry log (last {lines} lines) ---\n{}",
            tail.join("\n")
        )
    }
}

impl Drop for RegistryProcess {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}
