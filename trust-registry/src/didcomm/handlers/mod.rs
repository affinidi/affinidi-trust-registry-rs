use std::sync::Arc;

use crate::storage::repository::TrustRecordRepository;
use affinidi_tdk::{
    didcomm::Message,
    messaging::{ATM, messages::compat::UnpackMetadata, profiles::ATMProfile},
};
use async_trait::async_trait;
use tracing::{debug, info, warn};

use crate::didcomm::{get_parent_thread_id, get_thread_id, listener::MessageHandler};

pub mod admin;
pub mod build;
pub mod problem_report;
pub mod trqp;
pub mod trust_tasks;

pub struct HandlerContext {
    pub atm: Arc<ATM>,
    pub profile: Arc<ATMProfile>,
    pub sender_did: String,
    pub thid: Option<String>,
    pub pthid: Option<String>,
}

#[async_trait]
pub trait ProtocolHandler: Send + Sync + 'static {
    fn get_supported_inbound_message_types(&self) -> Vec<String>;

    async fn handle(
        &self,
        ctx: &Arc<HandlerContext>,
        message: Message,
        meta: UnpackMetadata,
    ) -> Result<(), Box<dyn std::error::Error>>;
}

pub struct BaseHandler<R: ?Sized + TrustRecordRepository> {
    #[allow(dead_code)]
    repository: Arc<R>,
    protocols_handlers: Vec<Arc<dyn ProtocolHandler>>,
}

#[async_trait]
impl<R: ?Sized + TrustRecordRepository + 'static> MessageHandler for BaseHandler<R> {
    async fn handle(
        &self,
        atm: &Arc<ATM>,
        profile: &Arc<ATMProfile>,
        message: Message,
        meta: UnpackMetadata,
    ) -> Result<(), Box<dyn std::error::Error>> {
        // TODO: validate UnpackMetadata, so in config the admin of TR can define would they allow unsign / anon / etc messages
        let message_type = &message.typ;
        let from = message.from.clone().unwrap_or("anon".into());
        let thid = get_thread_id(&message).or_else(|| Some(message.id.clone()));
        let pthid = get_parent_thread_id(&message);

        let ctx = Arc::new(HandlerContext {
            atm: atm.clone(),
            profile: profile.clone(),
            sender_did: from.clone(),
            thid,
            pthid,
        });

        let ph = self.protocols_handlers.iter().find(|ph| {
            ph.get_supported_inbound_message_types()
                .contains(message_type)
        });

        if let Some(protocol_handler) = ph {
            info!(
                message_type = ?message_type,
                from = ?from,
                "[profile = {}] new message",
                &profile.inner.alias
            );
            protocol_handler.handle(&ctx, message, meta).await?;
        } else if is_mediator_transport_message(
            profile.dids().ok().map(|(_, mediator)| mediator),
            message_type,
            &from,
            // The SDK's own spoof guard: authcrypt binds `from` to the
            // encrypting key under the default `validate_addressing_consistency`
            // policy, anoncrypt does not bind it at all.
            meta.authenticated && !meta.anonymous_sender,
        ) {
            // A Message-Pickup frame the mediator addressed to us that no
            // pending request claimed — typically a `status` reply that arrived
            // after its requester stopped waiting, so the live-delivery stream
            // picked it up instead. It carries no registry work and answering a
            // mediator's own transport protocol with a problem report would be
            // wrong, so drop it quietly.
            debug!(
                message_type = ?message_type,
                "[profile = {}] unclaimed mediator transport message ignored",
                &profile.inner.alias
            );
        } else {
            // send problem report
            warn!(
                message_type = ?message.typ,
                from = ?from,
                "No handler found. Send problem report or ignore"
            );
        }
        Ok(())
    }
}

/// Message-Pickup 3.0 is the transport that carries our messages, not a
/// registry protocol: the mediator is the only party that legitimately speaks
/// it to us, so only frames genuinely from our mediator are treated as
/// transport chatter. Anyone else sending pickup-typed messages is still
/// surfaced as an unhandled message.
///
/// `from` is only trusted once the unpack has bound it to a key. On an
/// anoncrypt or plaintext envelope it is a header the sender chose freely, so
/// taking it at face value would let anyone forge the mediator's DID on a
/// pickup-typed frame and have their own traffic dropped at `debug` instead of
/// warned about. Unauthenticated senders fall through to the unhandled path.
fn is_mediator_transport_message(
    mediator_did: Option<&str>,
    message_type: &str,
    from: &str,
    authenticated_sender: bool,
) -> bool {
    const MESSAGE_PICKUP_PROTOCOL: &str = "https://didcomm.org/messagepickup/";

    let Some(mediator_did) = mediator_did else {
        return false;
    };

    authenticated_sender
        && from == mediator_did
        && message_type.starts_with(MESSAGE_PICKUP_PROTOCOL)
}

#[cfg(test)]
mod tests {
    use super::is_mediator_transport_message;

    const MEDIATOR: &str = "did:webvh:QmTS3a:webvh.storm.ws:mediator";
    const STATUS: &str = "https://didcomm.org/messagepickup/3.0/status";
    /// `meta.authenticated && !meta.anonymous_sender` as the call site computes it.
    const AUTHENTICATED: bool = true;
    const UNAUTHENTICATED: bool = false;

    #[test]
    fn pickup_frame_from_our_mediator_is_transport_chatter() {
        assert!(is_mediator_transport_message(
            Some(MEDIATOR),
            STATUS,
            MEDIATOR,
            AUTHENTICATED
        ));
    }

    #[test]
    fn pickup_frame_from_anyone_else_is_still_unhandled() {
        assert!(!is_mediator_transport_message(
            Some(MEDIATOR),
            STATUS,
            "did:webvh:QmXi1P:webvh.storm.ws:first-vtc",
            AUTHENTICATED
        ));
    }

    #[test]
    fn registry_message_from_the_mediator_is_still_unhandled() {
        assert!(!is_mediator_transport_message(
            Some(MEDIATOR),
            "registry/record/query",
            MEDIATOR,
            AUTHENTICATED
        ));
    }

    /// An anoncrypt or plaintext envelope carries a `from` its sender chose,
    /// so honouring it would let anyone forge the mediator's DID to keep their
    /// own frames out of the warn-level log.
    #[test]
    fn spoofed_mediator_did_on_an_unauthenticated_frame_is_still_unhandled() {
        assert!(!is_mediator_transport_message(
            Some(MEDIATOR),
            STATUS,
            MEDIATOR,
            UNAUTHENTICATED
        ));
    }

    #[test]
    fn an_authenticated_mediator_frame_is_unaffected_by_the_guard() {
        assert!(is_mediator_transport_message(
            Some(MEDIATOR),
            "https://didcomm.org/messagepickup/3.0/delivery",
            MEDIATOR,
            AUTHENTICATED
        ));
    }

    #[test]
    fn without_a_configured_mediator_nothing_is_transport_chatter() {
        assert!(!is_mediator_transport_message(
            None,
            STATUS,
            MEDIATOR,
            AUTHENTICATED
        ));
    }
}
