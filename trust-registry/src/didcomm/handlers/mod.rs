use std::sync::Arc;

use affinidi_tdk::{
    didcomm::Message,
    messaging::{ATM, messages::compat::UnpackMetadata, profiles::ATMProfile},
};
use async_trait::async_trait;
use tracing::{debug, info, warn};

use crate::didcomm::{get_thread_id, listener::MessageHandler};

pub mod build;
pub mod problem_report;
pub mod trqp;
pub mod trust_tasks;

pub struct HandlerContext {
    pub atm: Arc<ATM>,
    pub profile: Arc<ATMProfile>,
    /// The sender the unpack authenticated (authcrypt). Replies are addressed,
    /// resolved and encrypted to this DID only. [`BaseHandler`] calls a
    /// protocol handler only for a message with an authenticated sender; a
    /// message's `from` alone never chooses where a reply goes.
    ///
    /// Not sufficient to authorise a change: registry writes additionally need
    /// a Data Integrity proof by the same DID.
    pub authenticated_sender: String,
    /// The request's thread: its `thid`, or its `id` when it has none. Every
    /// reply is sent on this thread.
    pub thid: Option<String>,
}

/// The sender an unpack proved, or `None` when the envelope did not bind its
/// `from` to a key (anoncrypt, plaintext, or an anonymous sender).
fn authenticated_sender(message: &Message, meta: &UnpackMetadata) -> Option<String> {
    (meta.authenticated && !meta.anonymous_sender)
        .then(|| message.from.clone())
        .flatten()
}

#[async_trait]
pub trait ProtocolHandler: Send + Sync + 'static {
    /// Whether this handler serves inbound messages of type `message_type`.
    fn handles(&self, message_type: &str) -> bool;

    async fn handle(
        &self,
        ctx: &Arc<HandlerContext>,
        message: Message,
        meta: UnpackMetadata,
    ) -> Result<(), Box<dyn std::error::Error>>;
}

/// Routes each inbound DIDComm message to the [`ProtocolHandler`] for its type.
pub struct BaseHandler {
    protocols_handlers: Vec<Arc<dyn ProtocolHandler>>,
}

#[async_trait]
impl MessageHandler for BaseHandler {
    async fn handle(
        &self,
        atm: &Arc<ATM>,
        profile: &Arc<ATMProfile>,
        message: Message,
        meta: UnpackMetadata,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let message_type = &message.typ;
        // As the message states it; for logging and the mediator check below,
        // which requires an authenticated sender itself.
        let from = message.from.clone().unwrap_or_default();
        let authenticated_sender = authenticated_sender(&message, &meta);

        let ph = self
            .protocols_handlers
            .iter()
            .find(|ph| ph.handles(message_type));

        if let Some(protocol_handler) = ph {
            // Every handler answers its sender. Without an authenticated
            // sender there is no one the answer could safely go to: the `from`
            // of an anoncrypt or plaintext message is whatever its sender
            // wrote. Drop it before any work is done. The REST API answers
            // reads without authentication.
            let Some(authenticated_sender) = authenticated_sender else {
                debug!(
                    message_type = ?message_type,
                    "[profile = {}] message without an authenticated sender dropped",
                    &profile.inner.alias
                );
                return Ok(());
            };
            info!(
                message_type = ?message_type,
                from = %authenticated_sender,
                "[profile = {}] new message",
                &profile.inner.alias
            );
            let ctx = Arc::new(HandlerContext {
                atm: atm.clone(),
                profile: profile.clone(),
                authenticated_sender,
                thid: get_thread_id(&message),
            });
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
            // Not answered: replying to a type we do not speak (with a problem
            // report) invites a reply loop with an agent that does the same,
            // and the sender may not be authenticated. Handled, so acked.
            warn!(
                message_type = ?message.typ,
                from = ?from,
                "[profile = {}] no handler for this message type; dropped",
                &profile.inner.alias
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

    mod reply_addressing {
        use std::sync::{Arc, Mutex};

        use affinidi_tdk::{
            common::{TDKSharedState, config::TDKConfig},
            didcomm::Message,
            messaging::{
                ATM, config::ATMConfig, messages::compat::UnpackMetadata, profiles::ATMProfile,
            },
        };
        use async_trait::async_trait;
        use serde_json::json;

        use super::super::{BaseHandler, HandlerContext, ProtocolHandler, authenticated_sender};
        use crate::didcomm::listener::MessageHandler;

        const TYPE: &str = "https://example.org/test/1.0/ping";
        const CLAIMED: &str = "did:example:someone-else";

        /// Records the sender each call would answer, and sends nothing.
        #[derive(Default)]
        struct Recorder {
            replies_to: Mutex<Vec<String>>,
        }

        #[async_trait]
        impl ProtocolHandler for Recorder {
            fn handles(&self, message_type: &str) -> bool {
                message_type == TYPE
            }

            async fn handle(
                &self,
                ctx: &Arc<HandlerContext>,
                _message: Message,
                _meta: UnpackMetadata,
            ) -> Result<(), Box<dyn std::error::Error>> {
                self.replies_to
                    .lock()
                    .unwrap()
                    .push(ctx.authenticated_sender.clone());
                Ok(())
            }
        }

        fn message(from: Option<&str>) -> Message {
            let mut builder = Message::build("id-1", TYPE, json!({}));
            if let Some(from) = from {
                builder = builder.from(from.to_string());
            }
            builder.finalize()
        }

        fn meta(authenticated: bool, anonymous_sender: bool) -> UnpackMetadata {
            let mut meta = UnpackMetadata::default();
            meta.encrypted = true;
            meta.authenticated = authenticated;
            meta.anonymous_sender = anonymous_sender;
            meta
        }

        #[test]
        fn only_an_authcrypt_sender_is_authenticated() {
            let m = message(Some(CLAIMED));
            assert_eq!(
                authenticated_sender(&m, &meta(true, false)).as_deref(),
                Some(CLAIMED)
            );
            assert_eq!(authenticated_sender(&m, &meta(false, false)), None);
            assert_eq!(authenticated_sender(&m, &meta(true, true)), None);
            assert_eq!(
                authenticated_sender(&message(None), &meta(true, false)),
                None
            );
        }

        async fn handle(message: Message, meta: UnpackMetadata) -> Vec<String> {
            let tdk = TDKSharedState::new(
                TDKConfig::builder()
                    .with_load_environment(false)
                    .build()
                    .unwrap(),
            )
            .await
            .unwrap();
            let atm = Arc::new(
                ATM::new(ATMConfig::builder().build().unwrap(), Arc::new(tdk))
                    .await
                    .unwrap(),
            );
            let profile = Arc::new(
                ATMProfile::new(
                    &atm,
                    Some("registry".into()),
                    "did:example:registry".into(),
                    None,
                )
                .await
                .unwrap(),
            );
            let recorder = Arc::new(Recorder::default());
            let handler = BaseHandler {
                protocols_handlers: vec![recorder.clone()],
            };
            handler.handle(&atm, &profile, message, meta).await.unwrap();
            let replies = recorder.replies_to.lock().unwrap().clone();
            replies
        }

        /// A message whose `from` the envelope did not bind to a key reaches
        /// no handler, so nothing is resolved, encrypted or sent to the DID it
        /// names.
        #[tokio::test]
        async fn a_message_without_an_authenticated_sender_is_not_answered() {
            assert!(
                handle(message(Some(CLAIMED)), meta(false, false))
                    .await
                    .is_empty()
            );
            assert!(handle(message(None), meta(false, false)).await.is_empty());
            assert!(
                handle(message(Some(CLAIMED)), meta(true, true))
                    .await
                    .is_empty()
            );
        }

        #[tokio::test]
        async fn an_authenticated_message_is_answered_to_its_sender() {
            assert_eq!(
                handle(message(Some(CLAIMED)), meta(true, false)).await,
                vec![CLAIMED.to_string()]
            );
        }
    }
}
