//! Record management over the `registry/record/*` Trust Tasks.
//!
//! Writes are operational messages signed with the admin's authentication key
//! (`proofPurpose` `authentication`) and may only name the
//! admin's own DID as `authority_id` (or an authority the registry's
//! `ADMIN_AUTHORITIES` grants it).

use std::sync::Arc;

use affinidi_tdk::{
    didcomm::Message,
    messaging::{ATM, profiles::ATMProfile},
    secrets_resolver::secrets::{KeyType, Secret},
};
use serde_json::{Value, json};
use trust_tasks_didcomm::ENVELOPE_TYPE;
use trust_tasks_proof::affinidi::{CryptoSuite, SignOptions, sign_trust_task};
use trust_tasks_rs::TrustTask;
use uuid::Uuid;

const RECORD_PUT: &str = "https://trusttasks.org/spec/registry/record/put/0.1";
const RECORD_QUERY: &str = "https://trusttasks.org/spec/registry/record/query/0.1";
const RECORD_DELETE: &str = "https://trusttasks.org/spec/registry/record/delete/0.1";

pub struct CommonCrudInput {
    pub atm: Arc<ATM>,
    pub profile: Arc<ATMProfile>,
    /// The admin's secrets; its authentication key signs writes.
    pub secrets: Vec<Secret>,
    pub trust_registry_did: String,
    pub entity_id: String,
    pub authority_id: String,
    pub action: String,
    pub resource: String,
    pub record_type: String,
}

impl CommonCrudInput {
    fn key(&self) -> Value {
        json!({
            "entity_id": self.entity_id,
            "authority_id": self.authority_id,
            "action": self.action,
            "resource": self.resource,
        })
    }

    fn record(&self, recognized: bool, authorized: bool, context: Option<Value>) -> Value {
        let mut record = self.key();
        record["recognized"] = json!(recognized);
        record["authorized"] = json!(authorized);
        record["record_type"] = json!(self.record_type);
        if let Some(context) = context {
            record["context"] = context;
        }
        record
    }
}

/// Create a record; refused if its key already exists.
pub async fn create_record(
    input: CommonCrudInput,
    recognized: bool,
    authorized: bool,
    context: Option<Value>,
) -> Result<(), Box<dyn std::error::Error>> {
    let payload = json!({
        "record": input.record(recognized, authorized, context),
        "expectedExisting": false,
    });
    send_trust_task(&input, RECORD_PUT, payload, true).await
}

/// Replace a record; refused if its key does not exist.
pub async fn update_record(
    input: CommonCrudInput,
    recognized: bool,
    authorized: bool,
    context: Option<Value>,
) -> Result<(), Box<dyn std::error::Error>> {
    let payload = json!({
        "record": input.record(recognized, authorized, context),
        "expectedExisting": true,
    });
    send_trust_task(&input, RECORD_PUT, payload, true).await
}

pub async fn delete_record(input: CommonCrudInput) -> Result<(), Box<dyn std::error::Error>> {
    send_trust_task(&input, RECORD_DELETE, input.key(), true).await
}

pub async fn read_record(input: CommonCrudInput) -> Result<(), Box<dyn std::error::Error>> {
    send_trust_task(&input, RECORD_QUERY, input.key(), false).await
}

/// List the records held under the input's authority.
pub async fn list_records(input: CommonCrudInput) -> Result<(), Box<dyn std::error::Error>> {
    let payload = json!({ "authority_id": input.authority_id });
    send_trust_task(&input, RECORD_QUERY, payload, false).await
}

/// Build the Trust Task, sign it when `sign` is set, and send it to the
/// registry in the DIDComm Trust Task envelope.
async fn send_trust_task(
    input: &CommonCrudInput,
    type_uri: &str,
    payload: Value,
    sign: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let did = input.profile.inner.did.clone();
    let mut doc = TrustTask::new(
        format!("urn:uuid:{}", Uuid::new_v4()),
        type_uri.parse()?,
        payload,
    );
    doc.issuer = Some(did.clone());
    doc.recipient = Some(input.trust_registry_did.clone());
    doc.issued_at = Some(chrono::Utc::now());

    let mut body = serde_json::to_value(&doc)?;
    if sign {
        let key = input
            .secrets
            .iter()
            .find(|secret| {
                secret.id.starts_with(&did)
                    && matches!(secret.get_key_type(), KeyType::Ed25519 | KeyType::P256)
            })
            .ok_or("the admin has no Ed25519 or P-256 verification key to sign with")?;
        let cryptosuite = match key.get_key_type() {
            KeyType::Ed25519 => CryptoSuite::EddsaJcs2022,
            _ => CryptoSuite::EcdsaJcs2019,
        };
        body = sign_trust_task(
            &body,
            key,
            SignOptions::new()
                .with_cryptosuite(cryptosuite)
                .with_proof_purpose("authentication"),
        )
        .await?;
    }

    println!(
        "\nSending Trust Task: {}",
        type_uri.trim_start_matches("https://trusttasks.org/spec/")
    );
    println!("   Document ID: {}", doc.id);
    println!(
        "   Payload: {}",
        serde_json::to_string_pretty(&doc.payload)?
    );

    let message_id = Uuid::new_v4().to_string();
    let message = Message::build(message_id.clone(), ENVELOPE_TYPE.to_string(), body)
        .from(did.clone())
        .to(input.trust_registry_did.clone())
        .thid(doc.id.clone())
        .finalize();

    let packed_msg = input
        .atm
        .pack_encrypted(&message, &input.trust_registry_did, Some(&did), Some(&did))
        .await?;

    let mediator = input
        .profile
        .to_tdk_profile()
        .mediator
        .clone()
        .ok_or("missing mediator")?;
    input
        .atm
        .forward_and_send_message(
            &input.profile,
            false,
            &packed_msg.0,
            Some(&message_id),
            &mediator,
            &input.trust_registry_did,
            None,
            None,
            false,
        )
        .await?;
    println!("Trust Task sent successfully");
    Ok(())
}
