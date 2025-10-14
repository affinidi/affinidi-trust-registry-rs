use std::sync::Arc;

use affinidi_messaging_didcomm::{Message, UnpackMetadata};
use affinidi_messaging_sdk::{
    ATM,
    messages::{MessageList, MessageListElement},
    profiles::ATMProfile,
    protocols::Protocols,
};
use async_trait::async_trait;
use tracing::info;

// #[async_trait]
// pub trait MessageHandler: Send + Sync + 'static {
//     async fn process(&self, message: Message, meta: UnpackMetadata) -> Result<(), Box<dyn std::error::Error>>;
// }

pub struct OnlyLoggingHandler {}
pub struct Listener<H: MessageHandler> {
    pub atm: Arc<ATM>,
    pub profile: Arc<ATMProfile>,
    pub handler: Arc<H>,
}

#[async_trait]
pub trait MessageHandler: Send + Sync + 'static {
    async fn handle(
        &self,
        message: Message,
        meta: UnpackMetadata,
    ) -> Result<(), Box<dyn std::error::Error>> {
        info!("[OnlyLoggingHandler]: Message: {:?}", message);
        info!("[OnlyLoggingHandler]: UnpackMetadata: {:?}", meta);

        Ok(())
    }
}

impl<H: MessageHandler> Listener<H> {
    pub fn new(atm: Arc<ATM>, profile: Arc<ATMProfile>, handler: Arc<H>) -> Self {
        Self {
            atm,
            profile,
            handler,
        }
    }
}
