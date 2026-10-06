//! A throwaway mediator for the end-to-end tests: Redis and the published
//! mediator image on a private Docker network.
//!
//! The mediator's identity is generated per run by the `mediator-setup` binary
//! that ships in the same image, so no keys live in the repo and the mediator
//! DID's endpoints always name the host port this run picked. Everything is
//! removed on drop unless `E2E_KEEP_STACK=1`.

use std::net::TcpListener;
use std::path::Path;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use tokio::process::Command;

pub const DEFAULT_MEDIATOR_IMAGE: &str = "public.ecr.aws/affinidi/messaging-mediator:v0.33.1";
const DEFAULT_REDIS_IMAGE: &str = "redis:7-alpine";

/// The port the mediator listens on inside its container.
const MEDIATOR_CONTAINER_PORT: u16 = 7037;

/// Tells apart stacks started by tests running in parallel in one process.
static STACKS_STARTED: AtomicU32 = AtomicU32::new(0);

pub struct MediatorStack {
    prefix: String,
    keep: bool,
    /// The mediator's DID: a did:peer whose service names `url`.
    pub did: String,
    /// The mediator's REST base, as published in its DID document.
    pub url: String,
    // Holds the generated mediator config (and its secrets) for the stack's life.
    conf_dir: tempfile::TempDir,
}

impl MediatorStack {
    /// `p256_suite` gives the mediator a P-256 key pair besides its Curve25519
    /// one, which P-256 identities need to talk to it at all.
    pub async fn start(p256_suite: bool) -> Result<Self, String> {
        docker(&["version", "--format", "{{.Server.Version}}"])
            .await
            .map_err(|e| format!("Docker is required for the e2e tests: {e}"))?;

        let image = env_or("E2E_MEDIATOR_IMAGE", DEFAULT_MEDIATOR_IMAGE);
        let redis_image = env_or("E2E_REDIS_IMAGE", DEFAULT_REDIS_IMAGE);
        let millis = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| e.to_string())?;
        let port = free_port()?;

        // From here on, a failure must still tear down what was started.
        let mut stack = Self {
            prefix: format!(
                "trust-registry-e2e-{}-{}-{}",
                std::process::id(),
                millis.as_millis(),
                STACKS_STARTED.fetch_add(1, Ordering::Relaxed)
            ),
            keep: env_or("E2E_KEEP_STACK", "") == "1",
            did: String::new(),
            url: format!("http://localhost:{port}/mediator/v1"),
            conf_dir: tempfile::tempdir().map_err(|e| format!("temp dir: {e}"))?,
        };
        let conf = stack.conf_dir.path().to_path_buf();
        let network = stack.prefix.clone();
        let redis = stack.container("redis");
        let mediator = stack.container("mediator");
        let redis_url = format!("redis://{redis}:6379/");

        docker(&["network", "create", &network]).await?;
        generate_mediator_config(&image, &conf, port, &redis_url, p256_suite).await?;
        stack.did = read_mediator_did(&conf.join("conf/mediator.toml"))?;

        docker(&[
            "run",
            "-d",
            "--name",
            &redis,
            "--network",
            &network,
            &redis_image,
        ])
        .await?;
        docker(&[
            "run",
            "-d",
            "--name",
            &mediator,
            "--network",
            &network,
            "-p",
            &format!("127.0.0.1:{port}:{MEDIATOR_CONTAINER_PORT}"),
            "-v",
            &format!("{}:/out", conf.display()),
            // The generated config names `./atm-functions.lua` relative to it.
            "-w",
            "/out/conf",
            "-e",
            &format!("DATABASE_URL={redis_url}"),
            // Lets the mediator recognise its own URL in a DID document and
            // deliver locally instead of forwarding to itself.
            "-e",
            &format!("LOCAL_ENDPOINTS=http://localhost:{port}"),
            // Pinned rather than taken from the setup default: refuse Trust
            // Tasks without a valid proof and `issuedAt`, so a registry or client
            // that sends them unsigned fails here instead of in a deployment.
            "-e",
            "TRUST_TASK_VERIFICATION=enforce",
            &image,
            "-c",
            "mediator.toml",
        ])
        .await?;

        let ready = format!("{}/readyz", stack.url);
        if let Err(e) = wait_for_http(&ready, Duration::from_secs(60)).await {
            return Err(format!("mediator not ready: {e}\n{}", stack.logs().await));
        }
        Ok(stack)
    }

    fn container(&self, name: &str) -> String {
        format!("{}-{name}", self.prefix)
    }

    /// The last lines of the mediator's log, for failure messages.
    pub async fn logs(&self) -> String {
        let name = self.container("mediator");
        match Command::new("docker")
            .args(["logs", "--tail", "60", &name])
            .output()
            .await
        {
            Ok(o) => format!(
                "--- docker logs {name} ---\n{}{}",
                String::from_utf8_lossy(&o.stdout),
                String::from_utf8_lossy(&o.stderr)
            ),
            Err(e) => format!("(no logs for {name}: {e})"),
        }
    }
}

impl Drop for MediatorStack {
    fn drop(&mut self) {
        if self.keep {
            eprintln!(
                "E2E_KEEP_STACK=1: leaving containers {}-* running",
                self.prefix
            );
            return;
        }
        let _ = std::process::Command::new("docker")
            .args([
                "rm",
                "-f",
                &self.container("mediator"),
                &self.container("redis"),
            ])
            .output();
        let _ = std::process::Command::new("docker")
            .args(["network", "rm", &self.prefix])
            .output();
    }
}

/// Run the image's own `mediator-setup` non-interactively: a did:peer whose
/// endpoints are `http://localhost:<port>`, file-backed secrets, no TLS.
async fn generate_mediator_config(
    image: &str,
    dir: &Path,
    host_port: u16,
    redis_url: &str,
    p256_suite: bool,
) -> Result<(), String> {
    std::fs::create_dir_all(dir.join("conf")).map_err(|e| format!("conf dir: {e}"))?;
    let volume = format!("{}:/out", dir.display());
    let public_url = format!("http://localhost:{host_port}");
    let listen = format!("0.0.0.0:{MEDIATOR_CONTAINER_PORT}");
    let mut args = vec!["run", "--rm"];
    // Write the files as the caller, so the test can read them and the temp
    // dir can be removed afterwards (a root-owned 0600 file blocks both on
    // Linux).
    let user = host_user().await;
    if let Some(user) = &user {
        args.extend(["--user", user.as_str()]);
    }
    args.extend([
        "-v",
        &volume,
        "-w",
        "/out",
        "--entrypoint",
        "/usr/local/bin/mediator-setup",
        image,
        "--non-interactive",
        "--deployment",
        "container",
        "--protocol",
        "didcomm",
        "--did-method",
        "peer",
    ]);
    // By default the mediator holds Curve25519 keys only, as `mediator-setup`
    // provisions it. A P-256 identity needs a P-256 key-agreement key on the
    // mediator too, or authcrypt between them is impossible.
    if p256_suite {
        args.extend(["--key-suite", "p256"]);
    }
    args.extend([
        "--public-url",
        &public_url,
        "--secret-storage",
        "file",
        "--ssl",
        "none",
        "--database-url",
        redis_url,
        // A config without an admin DID does not load.
        "--admin",
        "generate",
        "--listen-address",
        &listen,
        "-c",
        "conf/mediator.toml",
    ]);
    docker(&args).await.map(|_| ())
}

fn read_mediator_did(path: &Path) -> Result<String, String> {
    let toml = std::fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
    toml.lines()
        .find_map(|line| {
            let value = line
                .trim()
                .strip_prefix("mediator_did")?
                .trim()
                .strip_prefix('=')?;
            let value = value.trim().trim_matches('"');
            Some(value.strip_prefix("did://").unwrap_or(value).to_string())
        })
        .ok_or_else(|| format!("no mediator_did in {}", path.display()))
}

#[cfg(unix)]
async fn host_user() -> Option<String> {
    async fn id(flag: &str) -> Option<String> {
        let out = Command::new("id").arg(flag).output().await.ok()?;
        out.status
            .success()
            .then(|| String::from_utf8_lossy(&out.stdout).trim().to_string())
    }
    Some(format!("{}:{}", id("-u").await?, id("-g").await?))
}

#[cfg(not(unix))]
async fn host_user() -> Option<String> {
    None
}

async fn docker(args: &[&str]) -> Result<String, String> {
    let output = Command::new("docker")
        .args(args)
        .output()
        .await
        .map_err(|e| format!("could not run docker: {e}"))?;
    if !output.status.success() {
        return Err(format!(
            "`docker {}` failed: {}",
            args.first().copied().unwrap_or_default(),
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

/// Poll `url` until it answers 2xx.
async fn wait_for_http(url: &str, timeout: Duration) -> Result<(), String> {
    let client = reqwest::Client::new();
    let deadline = Instant::now() + timeout;
    let mut last = String::from("no response yet");
    while Instant::now() < deadline {
        match client.get(url).timeout(Duration::from_secs(3)).send().await {
            Ok(response) if response.status().is_success() => return Ok(()),
            Ok(response) => last = format!("HTTP {}", response.status()),
            Err(e) => last = e.to_string(),
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    Err(format!("{url} after {timeout:?}: {last}"))
}

/// A port that was free a moment ago. The OS may hand it out again before the
/// caller binds it, which is acceptable for a test harness.
pub fn free_port() -> Result<u16, String> {
    let listener = TcpListener::bind("127.0.0.1:0").map_err(|e| format!("free port: {e}"))?;
    listener
        .local_addr()
        .map(|a| a.port())
        .map_err(|e| format!("free port: {e}"))
}

pub fn env_or(name: &str, default: &str) -> String {
    std::env::var(name)
        .ok()
        .filter(|v| !v.is_empty())
        .unwrap_or_else(|| default.to_string())
}
