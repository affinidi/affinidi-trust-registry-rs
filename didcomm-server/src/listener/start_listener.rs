use tracing::{debug, error};

use crate::listener::*;

impl<H: MessageHandler> Listener<H> {
    pub async fn start_listening(
        self: Arc<Self>,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        self.clone().set_public_acls_mode().await?;
        let cloned_self = self.clone();
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(std::time::Duration::from_secs(30)).await;
                let offline_messages_result = cloned_self.sync_and_process_offline_messages().await;

                if let Err(e) = offline_messages_result {
                    error!(
                        "[profile = {}] Error returned from offline_messages_result function. {}",
                        &cloned_self.profile.inner.alias, e
                    );
                }
            }
        });

        loop {
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
