use tracing::{debug, error};

use crate::listener::*;

impl<H: MessageHandler> Listener<H> {
    pub async fn start_listening(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        loop {
            let offline_messages_result = self.sync_and_process_offline_messages().await;
            if let Err(e) = offline_messages_result {
                error!(
                    "[profile = {}] Error returned from offline_messages_result function. {}",
                    &self.profile.inner.alias, e
                );
            }

            let next_message_result = self.process_next_message().await;

            if let Err(e) = next_message_result {
                error!(
                    "[profile = {}] Error returned from next_message_result function. {}",
                    &self.profile.inner.alias, e
                );
            }

            debug!(
                "[profile = {}] iteration is done.",
                &self.profile.inner.alias
            );
        }
        // Ok(())
    }
}
