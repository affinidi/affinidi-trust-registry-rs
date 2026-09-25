//! DIDComm transport binding for the Trust Registry's Trust Task family.
//!
//! Inbound DIDComm messages of type [`ENVELOPE_TYPE`] carry a `TrustTask` JSON
//! document in their body (the `trusttasks.org/binding/didcomm/0.1` binding).
//! This handler:
//!
//! 1. parses the envelope body into a `TrustTask<Value>`;
//! 2. hands the document, with the authcrypt sender (if any) as the transport
//!    identity, to the shared [`TaskHandler`](crate::trust_tasks::TaskHandler),
//!    which resolves the parties (SPEC §4.8.1), applies the freshness checks,
//!    the write ACL, proof verification and the authority binding, and
//!    dispatches; and
//! 3. packs the resulting success or error document back into an [`ENVELOPE_TYPE`]
//!    message and returns it to the sender through the mediator.
//!
//! Steps 1 and 3 are the only parts specific to DIDComm. Step 2 is shared
//! with the TSP and HTTP bindings — and with any host driving an embedded
//! registry — so the transports cannot drift apart on authorisation.
//!
//! The legacy read-only `trqp/1.0` handler remains registered for backward
//! compatibility. The legacy `tr-admin/1.0` record-management protocol is no
//! longer served; record changes go through `registry/record/*`.

use std::sync::Arc;

use affinidi_tdk::didcomm::Message;
use affinidi_tdk::messaging::messages::compat::UnpackMetadata;
use async_trait::async_trait;

use serde::Serialize;
use serde_json::Value;
use tracing::{error, warn};
use trust_tasks_didcomm::ENVELOPE_TYPE;
use trust_tasks_rs::{ErrorResponse, TrustTask};
use uuid::Uuid;

use crate::capabilities::DispatcherHandle;
use crate::configs::AdminConfig;
use crate::dedup::MessageIdStore;
use crate::didcomm::error::DIDCommError;
use crate::didcomm::handlers::{HandlerContext, ProtocolHandler};
use crate::trust_tasks::TaskHandler;

/// DIDComm binding handler for the `registry/*` Trust Task family.
///
/// Owns only what is specific to this transport: decoding the envelope and
/// packing the reply. Everything from party resolution through dispatch lives
/// in the shared [`TaskHandler`].
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
                .with_admin_authorities(admin_config.admin_authorities)
                .with_dedup(dedup),
        }
    }
}

fn new_id() -> String {
    Uuid::new_v4().to_string()
}

/// Decode an inbound DIDComm envelope body and route it through `tasks`.
///
/// The DIDComm-specific half of handling a Trust Task: parse the body into a
/// framework document. Everything after that, party resolution included, is
/// the shared handler.
///
/// `sender_did` is the sender the unpack authenticated, or `None` for an
/// anoncrypt or plaintext envelope; an unauthenticated sender can read but
/// never write.
///
/// `None` means the body is not a usable Trust Task document: there is no
/// thread or issuer to address a conformant error response to, so the caller
/// should log and drop it rather than reply.
///
/// Public because a host that owns the mediator socket itself
/// ([`DidCommSource::HostDriven`](crate::didcomm::listener::DidCommSource::HostDriven))
/// needs exactly this, and should not have to reimplement the envelope
/// contract. Reached via
/// [`TrustRegistry::route_didcomm_envelope`](crate::TrustRegistry::route_didcomm_envelope).
pub async fn route_envelope_body(
    tasks: &TaskHandler,
    body: Value,
    sender_did: Option<&str>,
) -> Option<Result<TrustTask<Value>, ErrorResponse>> {
    let doc: TrustTask<Value> = match serde_json::from_value(body) {
        Ok(doc) => doc,
        Err(e) => {
            warn!(
                "Dropping malformed Trust Task envelope from {}: {e}",
                sender_did.unwrap_or("an unauthenticated sender")
            );
            return None;
        }
    };

    Some(tasks.handle(doc, sender_did).await)
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
        // Decode + resolve parties + route. The same function a host driving
        // its own mediator socket calls, so the two paths cannot diverge on
        // the envelope contract.
        let Some(outcome) = route_envelope_body(
            &self.tasks,
            message.body,
            ctx.authenticated_sender.as_deref(),
        )
        .await
        else {
            // A malformed envelope has no usable thread/issuer to address a
            // conformant error response to; already logged, so just drop it.
            return Ok(());
        };

        match outcome {
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
