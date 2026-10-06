//! A DIDComm client of the registry on the same mediator, as a verifier or a
//! community admin would be.

use std::collections::VecDeque;
use std::sync::Arc;
use std::time::Duration;

use affinidi_tdk::{
    did_common::{DID, PeerCreateKey, PeerKeyPurpose, PeerService, PeerServiceEndpoint},
    didcomm::Message,
    messaging::{ATM, profiles::ATMProfile},
    secrets_resolver::secrets::{KeyType, Secret},
};
use serde_json::Value;
use sha256::digest;
use tokio::sync::Mutex;
use tokio::time::Instant;
use trust_registry::didcomm::prepare_atm_and_profile;
use trust_tasks_didcomm::ENVELOPE_TYPE;
use trust_tasks_proof::affinidi::{CryptoSuite, SignOptions, sign_trust_task};
use trust_tasks_rs::TrustTask;
use trust_tasks_rs::specs::messaging::account::update::v0_1::{
    MediatorAcl, MediatorAclAccessListMode,
};

/// The key types of the identities the test mints (`E2E_IDENTITY_KEYS`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IdentityKeys {
    /// Ed25519 signing + X25519 key agreement. The messaging SDK signs Trust
    /// Tasks only with an Ed25519 key, so this is the shape whose
    /// `messaging/account/update` an enforcing mediator accepts.
    Ed25519,
    /// P-256 signing + P-256 key agreement, the shape `setup-trust-registry`
    /// and `generate-secrets` generated before they moved to Curve25519. The
    /// SDK sends this identity's Trust Tasks unsigned, so an enforcing mediator
    /// refuses them (`proof_required`); it also needs a mediator that holds a
    /// P-256 key, which `mediator-setup` adds only when asked.
    P256,
}

impl IdentityKeys {
    pub fn from_env() -> Result<Self, String> {
        match super::docker::env_or("E2E_IDENTITY_KEYS", "ed25519").as_str() {
            "ed25519" => Ok(Self::Ed25519),
            "p256" => Ok(Self::P256),
            other => Err(format!(
                "E2E_IDENTITY_KEYS must be ed25519 or p256, not {other}"
            )),
        }
    }
}

/// A `did:peer` with a signing key (`#key-1`) and a key-agreement key
/// (`#key-2`) of the given type, routed through `mediator_did`.
pub fn generate_identity(
    mediator_did: &str,
    keys: IdentityKeys,
) -> Result<(String, Vec<Secret>), String> {
    let (mut signing, mut agreement) = match keys {
        IdentityKeys::Ed25519 => (
            Secret::generate_ed25519(None, None),
            Secret::generate_x25519(None, None).map_err(|e| format!("X25519: {e}"))?,
        ),
        IdentityKeys::P256 => (
            Secret::generate_p256(None, None).map_err(|e| format!("P-256: {e}"))?,
            Secret::generate_p256(None, None).map_err(|e| format!("P-256: {e}"))?,
        ),
    };
    let keys = vec![
        PeerCreateKey::from_multibase(
            PeerKeyPurpose::Verification,
            signing
                .get_public_keymultibase()
                .map_err(|e| format!("signing key: {e}"))?,
        ),
        PeerCreateKey::from_multibase(
            PeerKeyPurpose::Encryption,
            agreement
                .get_public_keymultibase()
                .map_err(|e| format!("agreement key: {e}"))?,
        ),
    ];
    let services = vec![PeerService {
        id: None,
        type_: "dm".into(),
        endpoint: PeerServiceEndpoint::Uri(mediator_did.to_string()),
    }];
    let (did, _) =
        DID::generate_peer(&keys, Some(&services)).map_err(|e| format!("did:peer: {e}"))?;
    let did = did.to_string();
    signing.id = format!("{did}#key-1");
    agreement.id = format!("{did}#key-2");
    Ok((did, vec![signing, agreement]))
}

pub struct Client {
    pub did: String,
    mediator_did: String,
    signing_key: Secret,
    atm: Arc<ATM>,
    profile: Arc<ATMProfile>,
    /// Messages that arrived while a wait was looking for a different one.
    pending: Mutex<VecDeque<Message>>,
}

impl Client {
    /// Mint an identity, authenticate to the mediator and open the live stream.
    pub async fn connect(
        alias: &str,
        mediator_did: &str,
        keys: IdentityKeys,
    ) -> Result<Self, String> {
        let (did, secrets) = generate_identity(mediator_did, keys)?;
        let signing_key = secrets
            .iter()
            .find(|s| s.id.ends_with("#key-1"))
            .cloned()
            .ok_or("no signing key")?;
        let (atm, profile) = prepare_atm_and_profile(alias, &did, mediator_did, secrets, true)
            .await
            .map_err(|e| format!("{alias} connect: {e}"))?;
        Ok(Self {
            did,
            mediator_did: mediator_did.to_string(),
            signing_key,
            atm,
            profile,
            pending: Mutex::new(VecDeque::new()),
        })
    }

    /// Accept messages from anyone not on the deny list, so the registry's
    /// replies reach this client. A signed `messaging/account/update`, which a
    /// mediator enforcing Trust Task verification accepts only with a proof.
    pub async fn accept_replies(&self) -> Result<(), String> {
        let acl: MediatorAcl = MediatorAcl::builder()
            .access_list_mode(Some(MediatorAclAccessListMode::ExplicitDeny))
            .try_into()
            .map_err(|e| format!("mediator ACL: {e}"))?;
        self.atm
            .trust_tasks()
            .account_update(
                &self.profile,
                Some(digest(&self.profile.inner.did)),
                None,
                Some(acl),
                None,
            )
            .await
            .map(|_| ())
            .map_err(|e| format!("account/update: {e}"))
    }

    /// Authcrypt `body` to `to` and send it through the mediator. Returns the
    /// message id.
    pub async fn send(
        &self,
        to: &str,
        typ: &str,
        body: Value,
        thid: Option<&str>,
    ) -> Result<String, String> {
        let id = uuid::Uuid::new_v4().to_string();
        let mut builder = Message::build(id.clone(), typ.to_string(), body)
            .from(self.did.clone())
            .to(to.to_string());
        if let Some(thid) = thid {
            builder = builder.thid(thid.to_string());
        }
        let message = builder.finalize();
        let (packed, _) = self
            .atm
            .pack_encrypted(&message, to, Some(&self.did), Some(&self.did))
            .await
            .map_err(|e| format!("pack {typ}: {e}"))?;
        self.atm
            .forward_and_send_message(
                &self.profile,
                false,
                &packed,
                Some(&id),
                &self.mediator_did,
                to,
                None,
                None,
                false,
            )
            .await
            .map_err(|e| format!("send {typ}: {e}"))?;
        Ok(id)
    }

    /// A Trust Task from this client to `recipient`, signed with its key when
    /// `sign` is set.
    pub async fn trust_task(
        &self,
        recipient: &str,
        type_uri: &str,
        payload: Value,
        sign: bool,
    ) -> Result<TrustTask<Value>, String> {
        let mut doc = TrustTask::new(
            format!("urn:uuid:{}", uuid::Uuid::new_v4()),
            type_uri
                .parse()
                .map_err(|e| format!("type URI {type_uri}: {e:?}"))?,
            payload,
        );
        doc.issuer = Some(self.did.clone());
        doc.recipient = Some(recipient.to_string());
        doc.issued_at = Some(chrono::Utc::now());
        if !sign {
            return Ok(doc);
        }
        let cryptosuite = match self.signing_key.get_key_type() {
            KeyType::Ed25519 => CryptoSuite::EddsaJcs2022,
            _ => CryptoSuite::EcdsaJcs2019,
        };
        let value = serde_json::to_value(&doc).map_err(|e| e.to_string())?;
        let signed = sign_trust_task(
            &value,
            &self.signing_key,
            SignOptions::new()
                .with_cryptosuite(cryptosuite)
                .with_proof_purpose("authentication"),
        )
        .await
        .map_err(|e| format!("sign Trust Task: {e}"))?;
        serde_json::from_value(signed).map_err(|e| e.to_string())
    }

    /// Send `doc` in the DIDComm Trust Task envelope and wait for the reply on
    /// its thread.
    pub async fn round_trip(
        &self,
        to: &str,
        doc: &TrustTask<Value>,
        timeout: Duration,
    ) -> Result<TrustTask<Value>, String> {
        let body = serde_json::to_value(doc).map_err(|e| e.to_string())?;
        self.send(to, ENVELOPE_TYPE, body, Some(&doc.id)).await?;
        let reply = self
            .wait_for(timeout, |m| {
                m.typ == ENVELOPE_TYPE
                    && m.body.get("threadId").and_then(Value::as_str) == Some(doc.id.as_str())
            })
            .await?
            .ok_or_else(|| format!("no reply to Trust Task {} within {timeout:?}", doc.id))?;
        serde_json::from_value(reply.body).map_err(|e| format!("reply: {e}"))
    }

    /// The first message of type `typ`, or an error after `timeout`.
    pub async fn message_of_type(&self, typ: &str, timeout: Duration) -> Result<Message, String> {
        self.wait_for(timeout, |m| m.typ == typ)
            .await?
            .ok_or_else(|| format!("no {typ} within {timeout:?}"))
    }

    pub async fn shutdown(&self) {
        self.atm.graceful_shutdown().await;
    }

    async fn wait_for(
        &self,
        timeout: Duration,
        matches: impl Fn(&Message) -> bool,
    ) -> Result<Option<Message>, String> {
        {
            let mut pending = self.pending.lock().await;
            if let Some(index) = pending.iter().position(&matches) {
                return Ok(pending.remove(index));
            }
        }
        let deadline = Instant::now() + timeout;
        loop {
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() {
                return Ok(None);
            }
            let next = self
                .atm
                .message_pickup()
                .live_stream_next(&self.profile, Some(left.min(Duration::from_secs(2))), true)
                .await
                .map_err(|e| format!("live stream: {e}"))?;
            if let Some((message, _)) = next {
                if matches(&message) {
                    return Ok(Some(message));
                }
                self.pending.lock().await.push_back(message);
            }
        }
    }
}
