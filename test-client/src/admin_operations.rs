//! Record management over the `registry/record/*` Trust Tasks.
//!
//! Writes are operational messages signed with the admin's authentication key
//! (`proofPurpose` `authentication`) and may only name the
//! admin's own DID as `authority_id` (or an authority the registry's
//! `ADMIN_AUTHORITIES` grants it).

use std::sync::Arc;
use std::time::Duration;

use tokio::time::Instant;

use affinidi_tdk::{
    didcomm::Message,
    messaging::{ATM, profiles::ATMProfile},
    secrets_resolver::secrets::{KeyType, Secret},
};
use serde::Serialize;
use serde_json::{Map, Value};
use trust_tasks_didcomm::ENVELOPE_TYPE;
use trust_tasks_proof::affinidi::{CryptoSuite, SignOptions, sign_trust_task};
use trust_tasks_rs::{ErrorPayload, ErrorResponse, Payload, TrustTask};
use uuid::Uuid;

use crate::specs::registry::record::{
    delete::v0_2 as delete, put::v0_3 as put, query::v0_3 as query,
};

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

type BoxError = Box<dyn std::error::Error>;

impl CommonCrudInput {
    /// The `registry/record/put/0.3` record at this input's key. `context`, the
    /// record's opaque governance context, must be a JSON object.
    fn record(
        &self,
        recognized: bool,
        authorized: bool,
        context: Option<Value>,
    ) -> Result<put::TrustRecord, BoxError> {
        let context = match context {
            None => Map::new(),
            Some(Value::Object(context)) => context,
            Some(_) => return Err("a record's context must be a JSON object".into()),
        };
        Ok(put::TrustRecord::builder()
            .entity_id(self.entity_id.clone())
            .authority_id(self.authority_id.clone())
            .action(self.action.clone())
            .resource(self.resource.clone())
            .recognized(Some(recognized))
            .authorized(Some(authorized))
            .record_type(self.record_type.parse::<put::RecordType>()?)
            .context(context)
            .try_into()?)
    }

    /// A `registry/record/put/0.3` request for this input's record.
    fn put(
        &self,
        recognized: bool,
        authorized: bool,
        context: Option<Value>,
        expected_existing: bool,
    ) -> Result<put::Payload, BoxError> {
        Ok(put::Payload::builder()
            .record(self.record(recognized, authorized, context)?)
            .expected_existing(Some(expected_existing))
            .try_into()?)
    }

    /// A `registry/record/query/0.3` request for exactly this input's key.
    fn read(&self) -> Result<query::Payload, BoxError> {
        Ok(query::Payload::builder()
            .entity_id(Some(self.entity_id.clone()))
            .authority_id(Some(self.authority_id.clone()))
            .action(Some(self.action.clone()))
            .resource(Some(self.resource.clone()))
            .try_into()?)
    }

    /// A `registry/record/delete/0.2` request for this input's key.
    fn delete(&self) -> Result<delete::Payload, BoxError> {
        Ok(delete::Payload::builder()
            .entity_id(self.entity_id.clone())
            .authority_id(self.authority_id.clone())
            .action(self.action.clone())
            .resource(self.resource.clone())
            .try_into()?)
    }
}

/// Create a record; refused if its key already exists.
pub async fn create_record(
    input: CommonCrudInput,
    recognized: bool,
    authorized: bool,
    context: Option<Value>,
) -> Result<String, BoxError> {
    let payload = input.put(recognized, authorized, context, false)?;
    send_trust_task(&input, payload).await
}

/// Replace a record; refused if its key does not exist.
pub async fn update_record(
    input: CommonCrudInput,
    recognized: bool,
    authorized: bool,
    context: Option<Value>,
) -> Result<String, BoxError> {
    let payload = input.put(recognized, authorized, context, true)?;
    send_trust_task(&input, payload).await
}

pub async fn delete_record(input: CommonCrudInput) -> Result<String, BoxError> {
    let payload = input.delete()?;
    send_trust_task(&input, payload).await
}

pub async fn read_record(input: CommonCrudInput) -> Result<String, BoxError> {
    let payload = input.read()?;
    send_trust_task(&input, payload).await
}

/// List the records held under the input's authority.
pub async fn list_records(input: CommonCrudInput) -> Result<String, BoxError> {
    let payload: query::Payload = query::Payload::builder()
        .authority_id(Some(input.authority_id.clone()))
        .try_into()?;
    send_trust_task(&input, payload).await
}

/// Build the Trust Task, sign it, and send it to the registry in the DIDComm
/// Trust Task envelope. Reads are signed too: `registry/record/query` is only
/// answered for an admin, under the same rules as a write.
///
/// Returns the document id, which the registry's reply carries as its
/// `threadId` (and as the envelope's `thid`).
async fn send_trust_task<P: Payload + Serialize>(
    input: &CommonCrudInput,
    payload: P,
) -> Result<String, BoxError> {
    let did = input.profile.inner.did.clone();
    let mut doc = TrustTask::new(
        format!("urn:uuid:{}", Uuid::new_v4()),
        P::type_uri(),
        payload,
    );
    doc.issuer = Some(did.clone());
    doc.recipient = Some(input.trust_registry_did.clone());
    doc.issued_at = Some(chrono::Utc::now());

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
    let body = sign_trust_task(
        &serde_json::to_value(&doc)?,
        key,
        SignOptions::new()
            .with_cryptosuite(cryptosuite)
            .with_proof_purpose("authentication"),
    )
    .await?;

    println!(
        "\nSending Trust Task: {}/{}.{}",
        doc.type_uri.slug(),
        doc.type_uri.major(),
        doc.type_uri.minor()
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
    println!("Trust Task sent");
    Ok(doc.id)
}

/// How the registry answered a Trust Task.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Reply {
    /// A `#response` document.
    Response(Value),
    /// A `trust-task-error` document (or anything else that is not a
    /// `#response`), with its `code`.
    Error { code: String, document: Value },
}

/// Wait up to `timeout` for the registry's reply to the Trust Task whose id is
/// `thread_id`. Other messages that arrive meanwhile (replies to earlier
/// requests, say) are taken off the mediator and reported, not matched.
pub async fn await_reply(
    atm: &ATM,
    profile: &Arc<ATMProfile>,
    thread_id: &str,
    timeout: Duration,
) -> Result<Reply, Box<dyn std::error::Error>> {
    let deadline = Instant::now() + timeout;
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(format!("no reply to {thread_id} within {timeout:?}").into());
        }
        let Some((message, _)) = atm
            .message_pickup()
            .live_stream_next(profile, Some(remaining), true)
            .await?
        else {
            continue;
        };
        let body_thread = message.body.get("threadId").and_then(Value::as_str);
        if message.thid.as_deref() != Some(thread_id) && body_thread != Some(thread_id) {
            println!(
                "   (ignoring a message of type {} for thread {:?})",
                message.typ, message.thid
            );
            continue;
        }
        return Ok(classify(message.body));
    }
}

fn classify(document: Value) -> Reply {
    let Ok(doc) = serde_json::from_value::<TrustTask<Value>>(document.clone()) else {
        return Reply::Error {
            code: "unexpected-document-type".to_string(),
            document,
        };
    };
    if doc.type_uri.is_response() {
        return Reply::Response(document);
    }
    let code = if doc.type_uri.slug() == ErrorPayload::type_uri().slug() {
        serde_json::from_value::<ErrorResponse>(document.clone())
            .map(|error| error.payload.code.to_string())
            .unwrap_or_else(|_| "unknown".to_string())
    } else {
        "unexpected-document-type".to_string()
    };
    Reply::Error { code, document }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;
    use trust_tasks_rs::{ErrorPayload, StandardCode};

    /// A request the registry would answer.
    fn request() -> TrustTask<delete::Payload> {
        let payload: delete::Payload = delete::Payload::builder()
            .entity_id("did:example:entity")
            .authority_id("did:example:authority")
            .action("issue")
            .resource("vc")
            .try_into()
            .unwrap();
        TrustTask::new("urn:uuid:1", delete::Payload::type_uri(), payload)
    }

    #[test]
    fn a_response_document_is_a_response() {
        let response: delete::Response = delete::Response::builder().ok(true).try_into().unwrap();
        let doc = serde_json::to_value(request().respond_with("urn:uuid:2", response)).unwrap();
        assert_eq!(classify(doc.clone()), Reply::Response(doc));
    }

    #[test]
    fn an_error_document_carries_its_code() {
        let doc = serde_json::to_value(request().reject_with(
            "urn:uuid:2",
            ErrorPayload::new(StandardCode::PermissionDenied),
        ))
        .unwrap();
        assert_eq!(
            classify(doc.clone()),
            Reply::Error {
                code: "permissionDenied".to_string(),
                document: doc
            }
        );
    }

    #[test]
    fn anything_else_is_not_mistaken_for_success() {
        // Raw JSON: a document of a type no specification here defines.
        let doc = serde_json::json!({ "type": "https://example.com/other", "payload": {} });
        assert!(matches!(
            classify(doc),
            Reply::Error { code, .. } if code == "unexpected-document-type"
        ));
    }

    /// The requests the demo sends keep their wire form (R3.6).
    #[test]
    fn requests_keep_their_wire_form() {
        let record: put::TrustRecord = put::TrustRecord::builder()
            .entity_id("did:example:entity")
            .authority_id("did:example:authority")
            .action("issue")
            .resource("vc")
            .recognized(Some(true))
            .authorized(Some(false))
            .record_type(put::RecordType::Authorization)
            .try_into()
            .unwrap();
        let put: put::Payload = put::Payload::builder()
            .record(record)
            .expected_existing(Some(false))
            .try_into()
            .unwrap();
        assert_eq!(
            serde_json::to_string(&put).unwrap(),
            r#"{"expectedExisting":false,"record":{"action":"issue","authorityId":"did:example:authority","authorized":false,"entityId":"did:example:entity","recognized":true,"recordType":"authorization","resource":"vc"}}"#
        );
        assert_eq!(
            serde_json::to_string(&request().payload).unwrap(),
            r#"{"action":"issue","authorityId":"did:example:authority","entityId":"did:example:entity","resource":"vc"}"#
        );
    }
}
