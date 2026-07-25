//! DIDComm transport binding for the Trust Registry's Trust Task family.
//!
//! Inbound DIDComm messages of type [`ENVELOPE_TYPE`] carry a `TrustTask` JSON
//! document in their body (the `trusttasks.org/binding/didcomm/0.1` binding).
//! The ATM has already authcrypt-verified the sender, so this handler:
//!
//! 1. parses the envelope body into a `TrustTask<Value>`;
//! 2. resolves the framework's parties via [`DidcommHandler`] (SPEC §4.8.1) —
//!    the authcrypt sender is the `issuer`, our profile DID the `recipient`;
//! 3. hands the document to the shared
//!    [`TaskHandler`](crate::trust_tasks::TaskHandler), which applies the
//!    freshness checks, the write ACL and proof verification, and dispatches;
//!    and
//! 4. packs the resulting success or error document back into an [`ENVELOPE_TYPE`]
//!    message and returns it to the sender through the mediator.
//!
//! Steps 1, 2 and 4 are the only parts specific to DIDComm. Step 3 is shared
//! with the TSP and HTTP bindings — and with any host driving an embedded
//! registry — so the transports cannot drift apart on authorisation.
//!
//! The legacy `trqp/1.0` and `tr-admin/1.0` handlers remain registered for
//! backward compatibility.

use std::sync::Arc;

use affinidi_tdk::didcomm::Message;
use affinidi_tdk::messaging::messages::compat::UnpackMetadata;
use async_trait::async_trait;

use serde::Serialize;
use serde_json::Value;
use tracing::{error, info, warn};
use trust_tasks_didcomm::ENVELOPE_TYPE;
use trust_tasks_rs::{RejectReason, TransportHandler, TrustTask};
use uuid::Uuid;

use trust_tasks_didcomm::DidcommHandler as TtDidcommHandler;

use crate::capabilities::DispatcherHandle;
use crate::configs::AdminConfig;
use crate::dedup::MessageIdStore;
use crate::didcomm::error::DIDCommError;
use crate::didcomm::handlers::{HandlerContext, ProtocolHandler};
use crate::trust_tasks::TaskHandler;

/// DIDComm binding handler for the `registry/*` Trust Task family.
///
/// Owns only what is specific to this transport: decoding the envelope,
/// resolving the framework's parties from the authcrypt sender, and packing the
/// reply. Everything from the freshness checks through dispatch lives in the
/// shared [`TaskHandler`].
pub struct TrustTasksHandler {
    tasks: TaskHandler,
}

impl TrustTasksHandler {
    /// Build the handler over the live dispatcher handle (owned by the
    /// CapabilitySet, so capability enable/disable swaps take effect here
    /// without a restart), the admin-DID ACL used to gate writes, and the
    /// Data Integrity proof verifier applied to writes.
    ///
    /// `my_did` is the registry's own DID. It comes from the same
    /// `ProfileConfig` the listener builds its `ATMProfile` from, so it always
    /// matches the `profile.inner.did` seen per message.
    pub fn new(
        dispatcher: DispatcherHandle,
        admin_config: AdminConfig,
        verifier: std::sync::Arc<dyn trust_tasks_rs::DynProofVerifier>,
        dedup: std::sync::Arc<dyn MessageIdStore>,
        my_did: impl Into<String>,
    ) -> Self {
        Self {
            tasks: TaskHandler::new(dispatcher, my_did, admin_config.admin_dids, verifier)
                .with_dedup(dedup),
        }
    }
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

        info!(
            "[profile = {}, type = {}, from = {}] Trust Task",
            ctx.profile.inner.alias,
            doc.type_uri.slug(),
            ctx.sender_did
        );

        // 3. Everything else — freshness, the write ACL, proof verification,
        // DID rotation and dispatch — is transport-agnostic and lives in the
        // shared handler.
        match self.tasks.handle(doc, Some(&ctx.sender_did)).await {
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
        // Mirror the client-side binding (`pack_trust_task` sets the DIDComm
        // `thid`): carry the document's `threadId` on the envelope too, so
        // clients can correlate replies at the transport layer without
        // parsing the body first.
        let thread_id = body
            .get("threadId")
            .and_then(Value::as_str)
            .map(str::to_string);
        let message_id = new_id();
        let mut builder = Message::build(message_id.clone(), ENVELOPE_TYPE.to_string(), body)
            .from(ctx.profile.inner.did.clone())
            .to(ctx.sender_did.clone());
        if let Some(thid) = thread_id {
            builder = builder.thid(thid);
        }
        let envelope = builder.finalize();

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

    // The write ACL these tests used to cover moved to
    // `crate::trust_tasks::handler` along with `authorize_write` itself, which
    // the TSP binding had its own copy of. It is tested once at its new home.

    #[test]
    fn envelope_type_is_the_binding_envelope() {
        let handler_types = vec![ENVELOPE_TYPE.to_string()];
        assert_eq!(
            handler_types[0],
            "https://trusttasks.org/binding/didcomm/0.1/envelope"
        );
    }
}
