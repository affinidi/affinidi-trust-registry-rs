//! Phase 1 of `trust-registry setup`: mint and persist the ephemeral setup key.

use std::path::Path;

use vta_sdk::provision_client::driver::run_phase1_init;

use super::TrustRegistryMessages;

/// `trust-registry setup --setup-key-out <path> [--context <id>]`.
///
/// Writes the key (0600, the `EphemeralSetupKey::persist_to` format phase 2
/// loads as `setup_key_file`) and prints to stderr, through the driver every
/// VTI integration shares, a block an automated caller parses the DID from:
/// the line after `Setup DID (ephemeral):`. Makes no VTA call and writes no
/// configuration.
pub async fn run_setup_phase1(out_path: &Path, context_id: &str) -> Result<(), String> {
    let finalise = format!(
        "trust-registry setup --from <your-setup.toml>   (with setup_key_file = \"{}\")",
        out_path.display()
    );
    run_phase1_init(
        &mut std::io::stderr(),
        out_path,
        context_id,
        &TrustRegistryMessages,
        Some(&finalise),
    )
    .await
    .map_err(|e| format!("could not create the setup key: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use vta_sdk::provision_client::EphemeralSetupKey;

    #[tokio::test]
    async fn writes_a_key_phase_two_can_load() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("setup-key.json");
        run_setup_phase1(&path, "trust-registry").await.unwrap();

        let key = EphemeralSetupKey::load_from(&path).unwrap();
        assert!(key.did.starts_with("did:key:"));

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600, "the setup key is a private key");
        }
    }
}
