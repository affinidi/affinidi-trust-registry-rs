//! The standalone binary stops cleanly on SIGTERM: it drains, flushes and
//! exits 0 within a few seconds, instead of ignoring the signal (as PID 1 in a
//! container it has no default disposition) until the orchestrator kills it.
//!
//! Runs the real `trust-registry` binary REST-only over a CSV file, so it
//! needs no mediator or external service.
#![cfg(all(unix, feature = "standalone", feature = "storage-csv"))]
#![allow(clippy::expect_used)]

use std::io::{BufRead, BufReader};
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::time::Duration;

#[test]
fn sigterm_stops_the_binary_with_exit_status_zero() {
    let dir = tempfile::tempdir().expect("tempdir");
    let csv = dir.path().join("records.csv");
    std::fs::write(
        &csv,
        "entity_id,authority_id,action,resource,recognized,authorized,context,record_type\n",
    )
    .expect("csv written");

    let mut child = Command::new(env!("CARGO_BIN_EXE_trust-registry"))
        // No `.env` above a fresh temp dir is picked up by `dotenvy`.
        .current_dir(dir.path())
        .env_clear()
        .env("PATH", std::env::var_os("PATH").unwrap_or_default())
        .env("RUST_LOG", "info")
        .env("ENABLE_REST", "true")
        .env("ENABLE_DIDCOMM", "false")
        .env("LISTEN_ADDRESS", "127.0.0.1:0")
        .env("TR_STORAGE_BACKEND", "csv")
        .env("FILE_STORAGE_PATH", &csv)
        .env("TR_CAPABILITY_STATE", dir.path().join("capabilities.json"))
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("binary starts");

    // Logs go to stdout; wait for the HTTP server to be up.
    let stdout = child.stdout.take().expect("stdout");
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        for line in BufReader::new(stdout).lines().map_while(Result::ok) {
            let _ = tx.send(line);
        }
    });
    let mut seen = Vec::new();
    let started = loop {
        match rx.recv_timeout(Duration::from_secs(30)) {
            Ok(line) => {
                let up = line.contains("HTTP server is starting");
                seen.push(line);
                if up {
                    break true;
                }
            }
            Err(_) => break false,
        }
    };
    if !started {
        let _ = child.kill();
        let output = child.wait_with_output().expect("output");
        panic!(
            "the registry did not start:\nstdout:\n{}\nstderr:\n{}",
            seen.join("\n"),
            String::from_utf8_lossy(&output.stderr)
        );
    }

    let status = Command::new("kill")
        .args(["-TERM", &child.id().to_string()])
        .status()
        .expect("kill runs");
    assert!(status.success());

    let deadline = std::time::Instant::now() + Duration::from_secs(15);
    let exit = loop {
        if let Some(exit) = child.try_wait().expect("waits") {
            break exit;
        }
        if std::time::Instant::now() > deadline {
            let _ = child.kill();
            panic!("the registry did not stop within 15s of SIGTERM");
        }
        std::thread::sleep(Duration::from_millis(50));
    };
    seen.extend(rx.try_iter());
    assert!(
        exit.success(),
        "a requested stop exits 0, got {exit:?}\n{}",
        seen.join("\n")
    );
    assert!(
        seen.iter().any(|l| l.contains("SIGTERM received")),
        "{}",
        seen.join("\n")
    );
    assert!(
        seen.iter().any(|l| l.contains("Trust Registry stopped")),
        "{}",
        seen.join("\n")
    );
}
