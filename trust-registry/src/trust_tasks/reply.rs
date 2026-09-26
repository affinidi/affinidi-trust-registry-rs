//! Signing the registry's replies.
//!
//! Every document the registry sends back — a `#response` or a
//! `trust-task-error` — is an operational message from the registry
//! (VTI-OPS-021, VTI-KEY-106): it names the registry as its `issuer` and
//! carries a Data Integrity proof by the registry's operational key, with the
//! proof purpose `authentication`.
//!
//! A transport that authenticates its sender does not relieve the registry of
//! this. A requester correlates a reply by its `threadId`, which is a value it
//! put on the wire itself, so without a proof anyone who saw a request could
//! answer it. Rejections are signed for the same reason as successes: a forged
//! `permissionDenied` would make a requester give up on a write that would have
//! succeeded, and a requester that accepted unsigned errors would have no way
//! to tell it from the real one.

use std::sync::Arc;

use affinidi_tdk::secrets_resolver::secrets::{KeyType, Secret};
use serde::Serialize;
use serde::de::DeserializeOwned;
use trust_tasks_proof::affinidi::{CryptoSuite, SignOptions, sign_trust_task};
use trust_tasks_rs::TrustTask;

use crate::trust_tasks::proof::WRITE_PROOF_PURPOSE;

/// The registry's operational signing key, which signs every reply.
#[derive(Clone)]
pub struct ReplySigner {
    secret: Arc<Secret>,
    suite: CryptoSuite,
}

impl std::fmt::Debug for ReplySigner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ReplySigner")
            .field("verification_method", &self.secret.id)
            .finish_non_exhaustive()
    }
}

/// The cryptosuite a key of `key_type` signs with, or `None` for a key that
/// cannot sign a Trust Task (an X25519 key-agreement key, say).
fn suite_for(key_type: KeyType) -> Option<CryptoSuite> {
    match key_type {
        KeyType::Ed25519 => Some(CryptoSuite::EddsaJcs2022),
        KeyType::P256 | KeyType::P384 => Some(CryptoSuite::EcdsaJcs2019),
        _ => None,
    }
}

impl ReplySigner {
    /// Sign with `secret`. Its `id` must be a verification method of the
    /// registry's DID, listed there under `authentication`; `None` if it is not
    /// a key type that can sign.
    pub fn new(secret: Secret) -> Option<Self> {
        let suite = suite_for(secret.get_key_type())?;
        Some(Self {
            secret: Arc::new(secret),
            suite,
        })
    }

    /// The operational key among a DIDComm profile's `secrets`: the first
    /// signing key that is a verification method of `did`. The profile's other
    /// keys are key-agreement keys, which cannot sign.
    pub fn from_profile(did: &str, secrets: &[Secret]) -> Option<Self> {
        secrets
            .iter()
            .filter(|s| s.id.split('#').next() == Some(did) && s.id.contains('#'))
            .find_map(|s| Self::new(s.clone()))
    }

    /// The operational key of the registry `config` describes: its DIDComm
    /// profile's signing key.
    pub fn for_config(config: &crate::configs::TrustRegistryConfig) -> Option<Self> {
        let profile = &config.didcomm_config.profile_config;
        Self::from_profile(&profile.did, &profile.secrets)
    }

    /// The verification method replies are signed with.
    pub fn verification_method(&self) -> &str {
        &self.secret.id
    }

    /// `doc` with a proof by this key. `doc.issuer` must already be the DID
    /// this key belongs to.
    pub async fn sign<P: Serialize + DeserializeOwned>(
        &self,
        doc: &TrustTask<P>,
    ) -> Result<TrustTask<P>, String> {
        let value = serde_json::to_value(doc).map_err(|e| e.to_string())?;
        let signed = sign_trust_task(
            &value,
            self.secret.as_ref(),
            SignOptions::new()
                .with_proof_purpose(WRITE_PROOF_PURPOSE)
                .with_cryptosuite(self.suite),
        )
        .await
        .map_err(|e| e.to_string())?;
        serde_json::from_value(signed).map_err(|e| e.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_operational_key_is_picked_over_the_key_agreement_key() {
        let did = "did:peer:2.Vz6Mk.Ez6LS";
        let mut agreement = Secret::generate_x25519(None, Some(&[2; 32])).expect("x25519");
        agreement.id = format!("{did}#key-2");
        let mut signing = Secret::generate_ed25519(None, Some(&[1; 32]));
        signing.id = format!("{did}#key-1");

        let signer = ReplySigner::from_profile(did, &[agreement, signing]).expect("a signer");
        assert_eq!(signer.verification_method(), format!("{did}#key-1"));
    }

    #[test]
    fn a_key_of_another_did_is_never_picked() {
        let mut other = Secret::generate_ed25519(None, Some(&[1; 32]));
        other.id = "did:example:someone-else#key-1".to_string();
        assert!(ReplySigner::from_profile("did:example:registry", &[other]).is_none());
    }
}
