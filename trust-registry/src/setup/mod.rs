//! `trust-registry setup`: headless provisioning of the registry at a VTA.
//!
//! The same two-phase flow the VTC (`vtc setup`), the mediator and the
//! did-hosting daemon use, so an automated deployment (a VTA farm's Job
//! pipeline) drives the registry exactly as it drives them:
//!
//! 1. `trust-registry setup --setup-key-out <path> [--context <id>]` mints an
//!    ephemeral setup `did:key`, persists it (0600), and prints the DID with
//!    the grant the VTA operator has to make. No VTA call.
//! 2. The VTA operator grants it, offline or online:
//!    `vta contexts create --id <id> --name "Trust Registry" --admin-did <did>
//!    --admin-expires 1h --admin-handoff` (or the same under `pnm`).
//! 3. `trust-registry setup --from <file>` authenticates to the running VTA as
//!    the setup key and asks it to provision the registry from the
//!    `trust-registry` DID template. The VTA mints the registry's `did:webvh`,
//!    publishes it to the named DID-hosting server, keeps its keys in the
//!    context, and rolls the setup key over to a VTA-minted long-term admin.
//!    That admin is written out as the `TR_VTA_CREDENTIAL` file.
//!
//! The registry holds no keys of its own afterwards: at every boot it pulls its
//! DID and keys from the VTA with that credential (`configs::vta`). The keys
//! the provisioning reply also carries are therefore not written anywhere.

mod from_toml;
mod phase1;

use std::ffi::OsString;
use std::path::PathBuf;

use clap::{ArgGroup, Parser};
use vta_sdk::provision_client::OperatorMessages;

pub use from_toml::{SetupFile, run_setup_from_file};
pub use phase1::run_setup_phase1;

/// The VTA context the registry lives in unless told otherwise.
pub const DEFAULT_CONTEXT: &str = "trust-registry";

/// The built-in VTA DID template the registry is provisioned from.
pub const TEMPLATE_NAME: &str = "trust-registry";

#[derive(Parser, Debug)]
#[command(
    name = "trust-registry setup",
    about = "Provision this Trust Registry at a VTA, headless, in two phases",
    group(ArgGroup::new("phase").required(true).args(["setup_key_out", "from"]))
)]
struct SetupArgs {
    /// Phase 1: mint an ephemeral setup key, write it here (0600), and print
    /// the grant the VTA operator has to make for it.
    #[arg(long, value_name = "PATH")]
    setup_key_out: Option<PathBuf>,

    /// The VTA context to name in the printed grant (default
    /// `trust-registry`). Use the same value as `context` in the phase-2 file.
    #[arg(long, conflicts_with = "from")]
    context: Option<String>,

    /// Phase 2: provision the registry at the VTA as described by this TOML
    /// file (see `examples/vta-setup.example.toml`).
    #[arg(long, value_name = "FILE")]
    from: Option<PathBuf>,
}

/// Run `trust-registry setup` with `args` (the arguments after the binary
/// name, starting with `setup`). Returns the process exit code.
pub async fn run_cli(args: impl IntoIterator<Item = OsString>) -> i32 {
    let args = match SetupArgs::try_parse_from(args) {
        Ok(args) => args,
        Err(e) => {
            // `--help` and `--version` are errors to clap but not failures.
            let _ = e.print();
            return e.exit_code();
        }
    };
    let result = match (args.setup_key_out, args.from) {
        (Some(out), None) => {
            let context = args.context.as_deref().unwrap_or(DEFAULT_CONTEXT);
            run_setup_phase1(&out, context).await
        }
        (None, Some(file)) => run_setup_from_file(&file).await,
        // The `phase` group makes exactly one of the two present.
        _ => unreachable!("clap enforces exactly one of --setup-key-out / --from"),
    };
    match result {
        Ok(()) => 0,
        Err(e) => {
            eprintln!("Error: {e}");
            1
        }
    }
}

/// How the shared provisioning driver names this integration to the operator.
pub(crate) struct TrustRegistryMessages;

impl OperatorMessages for TrustRegistryMessages {
    fn integration_label(&self) -> &str {
        "Trust Registry"
    }

    fn integration_label_lower(&self) -> &str {
        "trust registry"
    }

    fn pnm_admin_command_hint(&self, context_id: &str, setup_did: &str) -> String {
        format!(
            "pnm contexts create --id {context_id} --name \"Trust Registry\" \\\n  \
             --admin-did {setup_did} --admin-expires 1h --admin-handoff"
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(args: &[&str]) -> Result<SetupArgs, clap::Error> {
        SetupArgs::try_parse_from(args)
    }

    #[test]
    fn exactly_one_phase_is_required() {
        assert!(parse(&["setup"]).is_err());
        assert!(parse(&["setup", "--setup-key-out", "k.json", "--from", "s.toml"]).is_err());
        assert!(parse(&["setup", "--setup-key-out", "k.json"]).is_ok());
        assert!(
            parse(&["setup", "--from", "s.toml"])
                .unwrap()
                .from
                .is_some()
        );
    }

    /// `--context` only shapes the phase-1 grant; on phase 2 the file names the
    /// context, and accepting the flag there would let the two disagree.
    #[test]
    fn context_belongs_to_phase_one() {
        assert!(parse(&["setup", "--from", "s.toml", "--context", "x"]).is_err());
    }

    /// The grant must carry `--admin-handoff`: without it the VTA refuses to
    /// roll the setup key over to the long-term admin (VTI-ACL-053), and the
    /// marker cannot be added to an entry afterwards.
    #[test]
    fn grant_hint_allows_the_admin_handoff() {
        let hint = TrustRegistryMessages.pnm_admin_command_hint("tr", "did:key:z6MkSetup");
        assert!(hint.contains("--id tr"));
        assert!(hint.contains("--admin-did did:key:z6MkSetup"));
        assert!(hint.contains("--admin-expires 1h --admin-handoff"));
    }
}
