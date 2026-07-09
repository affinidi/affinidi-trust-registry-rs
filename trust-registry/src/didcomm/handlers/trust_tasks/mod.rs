//! DIDComm transport binding for the Trust Registry's Trust Task family.
//!
//! Inbound DIDComm messages of type [`ENVELOPE_TYPE`] carry a `TrustTask` JSON
//! document in their body (the `trusttasks.org/binding/didcomm/0.1` binding).
//! The ATM has already authcrypt-verified the sender, so this handler:
//!
//! 1. parses the envelope body into a `TrustTask<Value>`;
//! 2. resolves the framework's parties via [`DidcommHandler`] (SPEC §4.8.1) —
//!    the authcrypt sender is the `issuer`, our profile DID the `recipient`;
//! 3. applies the framework freshness/recipient checks ([`TrustTask::validate_basic`]);
//! 4. gates record **writes** on the admin-DID ACL, proof presence
//!    (`IS_PROOF_REQUIRED`), and cryptographic Data-Integrity proof
//!    verification via [`crate::trust_tasks::verify_write_proof`];
//! 5. routes the document through the shared [`RegistryDispatcher`] (see
//!    [`crate::trust_tasks`]); and
//! 6. packs the resulting success or error document back into an [`ENVELOPE_TYPE`]
//!    message and returns it to the sender through the mediator.
//!
//! The legacy `trqp/1.0` and `tr-admin/1.0` handlers remain registered for
//! backward compatibility.

use std::sync::Arc;

use affinidi_tdk::didcomm::Message;
use affinidi_tdk::messaging::messages::compat::UnpackMetadata;
use async_trait::async_trait;
use chrono::Utc;
use serde::Serialize;
use serde_json::Value;
use tracing::{error, info, warn};
use trust_tasks_didcomm::ENVELOPE_TYPE;
use trust_tasks_rs::{RejectReason, TransportHandler, TrustTask};
use uuid::Uuid;

use trust_tasks_didcomm::DidcommHandler as TtDidcommHandler;

use crate::configs::AdminConfig;
use crate::didcomm::error::DIDCommError;
use crate::didcomm::handlers::{HandlerContext, ProtocolHandler};
use crate::storage::repository::TrustRecordAdminRepository;
use crate::trust_tasks::{RegistryDispatcher, build_dispatcher, handle_document};

/// DIDComm binding handler for the `registry/*` Trust Task family.
pub struct TrustTasksHandler {
    dispatcher: RegistryDispatcher,
    admin_config: AdminConfig,
    verifier: std::sync::Arc<dyn trust_tasks_rs::DynProofVerifier>,
}

impl TrustTasksHandler {
    /// Build the handler over `repository`, wiring the shared dispatcher, the
    /// admin-DID ACL used to gate record writes, and the Data Integrity proof
    /// verifier applied to writes.
    pub fn new<R>(
        repository: Arc<R>,
        admin_config: AdminConfig,
        verifier: std::sync::Arc<dyn trust_tasks_rs::DynProofVerifier>,
    ) -> Self
    where
        R: TrustRecordAdminRepository + ?Sized + 'static,
    {
        Self {
            dispatcher: build_dispatcher(repository),
            admin_config,
            verifier,
        }
    }
}

/// Slugs whose operations mutate the registry and therefore require the
/// admin-DID ACL plus a proof (per the `IS_PROOF_REQUIRED` policy).
fn is_write_slug(slug: &str) -> bool {
    matches!(
        slug,
        "registry/record/create" | "registry/record/update" | "registry/record/delete"
    )
}

/// Apply the write-only preconditions (proof presence + admin ACL) that the
/// transport-agnostic dispatcher does not enforce. Reads pass through.
fn authorize_write(
    doc: &TrustTask<Value>,
    sender_did: &str,
    admin_dids: &[String],
) -> Result<(), RejectReason> {
    if !is_write_slug(doc.type_uri.slug()) {
        return Ok(());
    }
    if doc.proof.is_none() {
        return Err(RejectReason::ProofRequired);
    }
    if !admin_dids.iter().any(|d| d == sender_did) {
        return Err(RejectReason::PermissionDenied {
            reason: format!("DID {sender_did} is not authorised to modify the registry"),
        });
    }
    Ok(())
}

fn new_id() -> String {
    Uuid::new_v4().to_string()
}

#[async_trait]
impl ProtocolHandler for TrustTasksHandler {
    fn get_supported_inbound_message_types(&self) -> Vec<String> {
        vec![ENVELOPE_TYPE.to_string()]
    }

    async fn handle(
        &self,
        ctx: &Arc<HandlerContext>,
        message: Message,
        _meta: UnpackMetadata,
    ) -> Result<(), Box<dyn std::error::Error>> {
        // 1. Decode the envelope body into a framework document.
        let doc: TrustTask<Value> = match serde_json::from_value(message.body) {
            Ok(doc) => doc,
            Err(e) => {
                // A malformed envelope has no usable thread/issuer to address a
                // conformant error response to; log and drop.
                warn!(
                    "[profile = {}] Dropping malformed Trust Task envelope from {}: {}",
                    ctx.profile.inner.alias, ctx.sender_did, e
                );
                return Ok(());
            }
        };

        // 2. §4.8.1 party resolution: authcrypt sender -> issuer, us -> recipient.
        let transport = TtDidcommHandler::new(
            Some(ctx.profile.inner.did.clone()),
            Some(ctx.sender_did.clone()),
        );
        if let Err(consistency) = transport.resolve_parties(&doc) {
            // In-band issuer contradicts the transport-authenticated sender.
            let err = doc.reject_with_recipient(
                new_id(),
                RejectReason::from(consistency),
                Some(ctx.sender_did.clone()),
            );
            self.send(ctx, &err).await;
            return Ok(());
        }

        // 3. Framework freshness + recipient checks (§7.2 items 4/5).
        if let Err(reason) = doc.validate_basic(Utc::now(), &ctx.profile.inner.did) {
            let err = doc.reject_with(new_id(), reason);
            self.send(ctx, &err).await;
            return Ok(());
        }

        // 4. Write-only ACL + proof presence.
        if let Err(reason) = authorize_write(&doc, &ctx.sender_did, &self.admin_config.admin_dids) {
            let err = doc.reject_with(new_id(), reason);
            self.send(ctx, &err).await;
            return Ok(());
        }

        // 4b. Cryptographically verify the write's Data Integrity proof.
        if let Err(reason) = crate::trust_tasks::verify_write_proof(&self.verifier, &doc).await {
            let err = doc.reject_with(new_id(), reason);
            self.send(ctx, &err).await;
            return Ok(());
        }

        // 5. Route through the shared dispatcher.
        info!(
            "[profile = {}, type = {}, from = {}] Trust Task",
            ctx.profile.inner.alias,
            doc.type_uri.slug(),
            ctx.sender_did
        );
        match handle_document(&self.dispatcher, doc).await {
            Ok(response) => self.send(ctx, &response).await,
            Err(err) => self.send(ctx, &err).await,
        }
        Ok(())
    }
}

impl TrustTasksHandler {
    /// Pack `doc` as an [`ENVELOPE_TYPE`] DIDComm message and forward it to the
    /// original sender through the mediator. Errors are logged, not propagated —
    /// a failed reply must not tear down the listener.
    async fn send<T: Serialize>(&self, ctx: &Arc<HandlerContext>, doc: &T) {
        if let Err(e) = self.try_send(ctx, doc).await {
            error!(
                "[profile = {}] Failed to send Trust Task response to {}: {}",
                ctx.profile.inner.alias, ctx.sender_did, e
            );
        }
    }

    async fn try_send<T: Serialize>(
        &self,
        ctx: &Arc<HandlerContext>,
        doc: &T,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let body = serde_json::to_value(doc)?;
        let message_id = new_id();
        let envelope = Message::build(message_id.clone(), ENVELOPE_TYPE.to_string(), body)
            .from(ctx.profile.inner.did.clone())
            .to(ctx.sender_did.clone())
            .finalize();

        let packed = ctx
            .atm
            .pack_encrypted(
                &envelope,
                &ctx.sender_did,
                Some(&ctx.profile.inner.did),
                Some(&ctx.profile.inner.did),
            )
            .await?;

        let mediator = ctx
            .profile
            .to_tdk_profile()
            .mediator
            .clone()
            .ok_or(DIDCommError::MissingMediator)?;

        ctx.atm
            .forward_and_send_message(
                &ctx.profile,
                false,
                &packed.0,
                Some(&message_id),
                &mediator,
                &ctx.sender_did,
                None,
                None,
                false,
            )
            .await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::trust_tasks::payloads::type_uris;

    fn doc_with(type_uri: &str, proof: bool) -> TrustTask<Value> {
        let mut doc = TrustTask::new(
            new_id(),
            type_uri.parse().expect("valid type uri"),
            serde_json::json!({}),
        );
        if proof {
            // Any non-null proof satisfies the presence check; verification is
            // a separate concern.
            doc.proof = Some(
                serde_json::from_value(serde_json::json!({
                    "type": "DataIntegrityProof",
                    "cryptosuite": "eddsa-jcs-2022",
                    "created": "2026-07-07T00:00:00Z",
                    "proofPurpose": "assertionMethod",
                    "verificationMethod": "did:example:admin#key-1",
                    "proofValue": "z0000"
                }))
                .expect("valid proof fixture"),
            );
        }
        doc
    }

    const ADMIN: &str = "did:example:admin";
    const CREATE: &str = type_uris::RECORD_CREATE;
    const RECOGNITION: &str = type_uris::RECOGNITION;

    #[test]
    fn reads_bypass_write_authorization() {
        let doc = doc_with(RECOGNITION, false);
        assert!(authorize_write(&doc, "did:example:anyone", &[]).is_ok());
    }

    #[test]
    fn write_without_proof_is_rejected() {
        let doc = doc_with(CREATE, false);
        let err = authorize_write(&doc, ADMIN, &[ADMIN.to_string()]).unwrap_err();
        assert!(matches!(err, RejectReason::ProofRequired));
    }

    #[test]
    fn write_from_non_admin_is_denied() {
        let doc = doc_with(CREATE, true);
        let err = authorize_write(&doc, "did:example:intruder", &[ADMIN.to_string()]).unwrap_err();
        assert!(matches!(err, RejectReason::PermissionDenied { .. }));
    }

    #[test]
    fn write_from_admin_with_proof_is_allowed() {
        let doc = doc_with(CREATE, true);
        assert!(authorize_write(&doc, ADMIN, &[ADMIN.to_string()]).is_ok());
    }

    #[test]
    fn envelope_type_is_the_binding_envelope() {
        let handler_types = vec![ENVELOPE_TYPE.to_string()];
        assert_eq!(
            handler_types[0],
            "https://trusttasks.org/binding/didcomm/0.1/envelope"
        );
    }
}
