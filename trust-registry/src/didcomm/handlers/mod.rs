use std::sync::Arc;

use crate::storage::repository::TrustRecordRepository;
use affinidi_tdk::{
    didcomm::{Message, UnpackMetadata},
    messaging::{ATM, profiles::ATMProfile},
};
use async_trait::async_trait;
use tracing::{info, warn};

use crate::didcomm::{get_parent_thread_id, get_thread_id, listener::MessageHandler};

pub mod admin;
pub mod build;
pub mod problem_report;
pub mod trqp;

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
        let message_type = &message.type_;
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
                "[profile = {}, type = {}, from = {}] new message",
                &profile.inner.alias, message_type, from
            );
            protocol_handler.handle(&ctx, message, meta).await?;
        } else {
            // send problem report
            warn!(
                "No handler found. Send problem report or ignore. message_type = {}, from = {}",
                &message.type_, from
            );
        }
        Ok(())
    }
}
