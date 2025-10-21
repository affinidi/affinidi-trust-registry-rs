use std::sync::Arc;

use affinidi_tdk::{
    didcomm::{Message, UnpackMetadata},
    messaging::{ATM, profiles::ATMProfile},
};
use app::storage::repository::TrustRecordRepository;
use async_trait::async_trait;
use tracing::{info, warn};

use crate::listener::MessageHandler;

pub mod build;
pub mod trqp;
// pub mod problem_report;

trait ProtocolHandler: MessageHandler {
    fn get_supported_inboud_message_types(&self) -> Vec<String>;
}

pub struct BaseHandler<R: TrustRecordRepository> {
    repository: Arc<R>,
    // TODO: any better way?
    // protocols_handlers: Arc<Vec<Box<dyn MessageHandler>>>
    protocols_handlers: Vec<Arc<dyn ProtocolHandler>>,
}

impl<R: TrustRecordRepository> BaseHandler<R> {
    pub fn new(repository: R, protocols_handlers: Vec<Arc<dyn ProtocolHandler>>) -> Self {
        Self {
            repository: Arc::new(repository),
            protocols_handlers,
        }
    }
}

#[async_trait]
impl<R: TrustRecordRepository + 'static> MessageHandler for BaseHandler<R> {
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
        let ph = self.protocols_handlers.iter().find(|ph| {
            ph.get_supported_inboud_message_types()
                .contains(message_type)
        });
        if let Some(protocol_handler) = ph {
            info!(
                "[profile = {}, type = {}, from = {}] new message",
                &profile.inner.alias, message_type, from
            );
            protocol_handler.handle(atm, profile, message, meta).await?;
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
