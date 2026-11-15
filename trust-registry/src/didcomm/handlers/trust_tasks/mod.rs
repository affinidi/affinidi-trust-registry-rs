//! DIDComm transport binding for the Trust Registry's Trust Task family.
//!
//! Inbound DIDComm messages of type [`ENVELOPE_TYPE`] carry a `TrustTask` JSON
//! document in their body (the `trusttasks.org/binding/didcomm/0.1` binding).
//! This handler:
//!
//! 1. parses the envelope body into a `TrustTask<Value>`;
//! 2. hands the document, with the authcrypt sender (if any) as the transport
//!    identity, to the shared [`crate::trust_tasks::TaskHandler`],
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

use crate::didcomm::handlers::{HandlerContext, ProtocolHandler};
use crate::didcomm::transport;
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
    /// Build the binding over the registry's shared Trust Task handler.
    pub fn new(tasks: TaskHandler) -> Self {
        Self { tasks }
    }
}

/// Decode an inbound DIDComm envelope body and route it through `tasks`.
///
/// The DIDComm-specific half of handling a Trust Task: parse the body into a
/// framework document. Everything after that, party resolution included, is
/// the shared handler.
///
/// `sender_did` is the sender the unpack authenticated, or `None` for an
/// anoncrypt or plaintext envelope; an unauthenticated sender can read but
/// never write. The registry's own listener calls this only for an
/// authenticated sender, the one its reply is addressed to (a message with
/// none is dropped before it gets here). A host calling it with `None` must
/// not address the outcome to the envelope's claimed `from`.
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
    fn handles(&self, message_type: &str) -> bool {
        message_type == ENVELOPE_TYPE
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
            Some(ctx.authenticated_sender.as_str()),
        )
        .await
        else {
            // A malformed envelope has no usable thread/issuer to address a
            // conformant error response to; already logged, so just drop it.
            return Ok(());
        };

        let reply_sent = match &outcome {
            Ok(response) => self.send(ctx, response).await,
            Err(err) => self.send(ctx, err).await,
        };
        // R1.6, handoff to the sender: see `delivery_result`.
        delivery_result(&outcome, reply_sent).map_err(Into::into)
    }
}

/// What the listener should be told about a message answered with `outcome`,
/// given whether the reply reached the mediator: `Ok` to ack it, `Err` to
/// leave it queued for redelivery ([`crate::trust_tasks::leave_queued`]).
///
/// R1.6, handoff to the sender: a retryable refusal (storage unavailable, the
/// same document in flight, a proof that could not be verified now because
/// the issuer's DID did not resolve) that was delivered transfers the retry to
/// the sender, so the message is acked. The registry retrying the original
/// as well could apply the same mutation twice (a sender such as vtc-service
/// re-sends it under a new document id) or land it after a later write. Only
/// a retryable refusal whose reply could not be sent is left queued, since
/// the sender never learned it must retry; it is tried again under the
/// give-up bounds of `didcomm::listener::delivery`. The TSP path applies the
/// same rule.
pub fn delivery_result(
    outcome: &Result<TrustTask<Value>, ErrorResponse>,
    reply_sent: bool,
) -> Result<(), RetryableRefusal> {
    if !crate::trust_tasks::leave_queued(outcome, reply_sent) {
        return Ok(());
    }
    Err(RetryableRefusal(
        outcome
            .as_ref()
            .err()
            .map(|err| err.payload.code.to_string())
            .unwrap_or_default(),
    ))
}

/// A Trust Task answered with a retryable refusal that could not be sent:
/// the message is left queued for redelivery rather than acked.
#[derive(Debug)]
pub struct RetryableRefusal(String);

impl std::fmt::Display for RetryableRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "a retryable `{}` refusal could not be sent; left queued for redelivery",
            self.0
        )
    }
}

impl std::error::Error for RetryableRefusal {}

impl TrustTasksHandler {
    /// Pack `doc` as an [`ENVELOPE_TYPE`] DIDComm message and forward it to the
    /// original sender through the mediator. Errors are logged, not propagated —
    /// a failed reply must not tear down the listener. Returns whether it was
    /// sent.
    async fn send<T: Serialize>(&self, ctx: &Arc<HandlerContext>, doc: &T) -> bool {
        match self.try_send(ctx, doc).await {
            Ok(()) => true,
            Err(e) => {
                error!(
                    "[profile = {}] Failed to send Trust Task response to {}: {}",
                    ctx.profile.inner.alias, ctx.authenticated_sender, e
                );
                false
            }
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
        transport::send_reply(
            ctx,
            ENVELOPE_TYPE,
            body,
            thread_id.or_else(|| ctx.thid.clone()),
        )
        .await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, deprecated)]

    use super::*;

    /// R1.6, handoff to the sender: a retryable refusal that was sent is
    /// acked (the sender owns the retry); one that could not be sent is left
    /// queued; a final answer is acked whether or not it was sent.
    #[test]
    fn a_delivered_retryable_refusal_is_acked_and_an_undelivered_one_kept() {
        use crate::specs::registry::record::put::v0_1 as put_spec;
        use trust_tasks_rs::{Payload as _, RejectReason};
        let doc = TrustTask::new("d1", put_spec::Payload::type_uri(), Value::Null);
        let unavailable =
            Err(doc.reject_with("r1", RejectReason::Unavailable { retry_after: None }));
        let invalid = Err(doc.reject_with(
            "r2",
            RejectReason::ProofInvalid {
                reason: "bad".into(),
            },
        ));
        assert!(delivery_result(&unavailable, true).is_ok(), "sent: acked");
        assert!(
            delivery_result(&unavailable, false).is_err(),
            "not sent: kept"
        );
        assert!(delivery_result(&invalid, true).is_ok());
        assert!(delivery_result(&invalid, false).is_ok(), "final: acked");
        let answered = Ok(doc.respond_with("r3", Value::Null));
        assert!(delivery_result(&answered, false).is_ok());
    }

    /// #302, the delivery-path consequence: a write refused because its
    /// issuer's DID did not resolve in time, whose refusal cannot be sent
    /// (no mediator here), is reported unhandled, so the pickup listener
    /// leaves it queued for redelivery; a write refused because the DID is
    /// not found is final, so it is acked even though its reply was not sent.
    #[tokio::test]
    async fn an_unsent_retryable_refusal_is_left_queued_and_a_final_one_acked() {
        use crate::didcomm::listener::delivery::{Ack, DeliveryLedger, Outcome};
        use crate::specs::registry::record::put::v0_1 as put_spec;
        use crate::storage::adapters::local_storage::LocalStorage;
        use crate::trust_tasks::build_dispatcher;
        use crate::trust_tasks::proof::tests::{TIMEOUT, not_found, verifier_failing_with};
        use affinidi_tdk::common::{TDKSharedState, config::TDKConfig};
        use affinidi_tdk::messaging::{ATM, config::ATMConfig, profiles::ATMProfile};
        use std::time::Duration;
        use tokio::sync::RwLock;
        use trust_tasks_rs::Payload as _;

        const REGISTRY: &str = "did:example:registry";
        const WRITER: &str = "did:example:writer";

        let tdk = TDKSharedState::new(
            TDKConfig::builder()
                .with_load_environment(false)
                .build()
                .unwrap(),
        )
        .await
        .unwrap();
        // No mediator: the reply is attempted and fails, which is logged.
        let atm = Arc::new(
            ATM::new(ATMConfig::builder().build().unwrap(), Arc::new(tdk))
                .await
                .unwrap(),
        );
        let profile = Arc::new(
            ATMProfile::new(&atm, Some("registry".into()), REGISTRY.into(), None)
                .await
                .unwrap(),
        );
        let ctx = Arc::new(HandlerContext {
            atm,
            profile,
            authenticated_sender: WRITER.to_string(),
            thid: None,
        });

        // A put by an admin carrying a proof; the failing resolver is reached
        // before the signature is looked at.
        let write = || {
            let record: put_spec::TrustRecord = put_spec::TrustRecord::builder()
                .entity_id("did:example:member")
                .authority_id(WRITER)
                .action("issue")
                .resource("vc")
                .recognized(Some(true))
                .authorized(Some(true))
                .record_type(put_spec::RecordType::Authorization)
                .try_into()
                .unwrap();
            let payload: put_spec::Payload = put_spec::Payload::builder()
                .record(record)
                .try_into()
                .unwrap();
            let mut doc = TrustTask::new(
                format!("urn:uuid:{}", uuid::Uuid::new_v4()),
                put_spec::Payload::type_uri(),
                serde_json::to_value(payload).unwrap(),
            );
            doc.issuer = Some(WRITER.to_string());
            doc.recipient = Some(REGISTRY.to_string());
            doc.issued_at = Some(chrono::Utc::now());
            doc.proof = Some(
                serde_json::from_value(serde_json::json!({
                    "type": "DataIntegrityProof",
                    "cryptosuite": "eddsa-jcs-2022",
                    "created": "2026-07-09T00:00:00Z",
                    "proofPurpose": "authentication",
                    "verificationMethod": format!("{WRITER}#key-1"),
                    "proofValue": "z0000"
                }))
                .unwrap(),
            );
            Message::build(
                "m".to_string(),
                ENVELOPE_TYPE.to_string(),
                serde_json::to_value(doc).unwrap(),
            )
            .finalize()
        };
        let binding = |resolver_error: String| {
            let repo = Arc::new(LocalStorage::new());
            let dispatcher = Arc::new(RwLock::new(Arc::new(build_dispatcher(repo))));
            TrustTasksHandler::new(
                TaskHandler::new(
                    dispatcher,
                    REGISTRY,
                    vec![WRITER.to_string()],
                    verifier_failing_with(resolver_error),
                )
                .with_dedup(Arc::new(crate::dedup::MemoryMessageIdStore::default())),
            )
        };
        let outcome = |result: Result<(), Box<dyn std::error::Error>>| match result {
            Ok(()) => Outcome::Handled,
            Err(_) => Outcome::Retry,
        };
        let mut ledger = DeliveryLedger::default();
        let now = tokio::time::Instant::now();

        let transient = tokio::time::timeout(
            Duration::from_secs(20),
            binding(TIMEOUT.to_string()).handle(&ctx, write(), UnpackMetadata::default()),
        )
        .await
        .expect("bounded");
        let err = transient.as_ref().expect_err("reported unhandled");
        assert!(err.to_string().contains("unavailable"), "{err}");
        ledger.claim("transient", now);
        assert_eq!(
            ledger.finish("transient", outcome(transient), now),
            Ack::Retain
        );

        let definitive = tokio::time::timeout(
            Duration::from_secs(20),
            binding(not_found()).handle(&ctx, write(), UnpackMetadata::default()),
        )
        .await
        .expect("bounded");
        assert!(definitive.is_ok());
        ledger.claim("definitive", now);
        assert_eq!(
            ledger.finish("definitive", outcome(definitive), now),
            Ack::Now
        );
    }

    // The write ACL these tests used to cover moved to
    // `crate::trust_tasks::handler` along with `authorize_write` itself, which
    // the TSP binding had its own copy of. It is tested once at its new home.

    #[test]
    fn envelope_type_is_the_binding_envelope() {
        let handler_types = [ENVELOPE_TYPE.to_string()];
        assert_eq!(
            handler_types[0],
            "https://trusttasks.org/binding/didcomm/0.1/envelope"
        );
    }
}
