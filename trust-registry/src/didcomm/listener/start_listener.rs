use tracing::{debug, error, warn};

use crate::didcomm::listener::*;

impl<H: MessageHandler> Listener<H> {
    pub async fn start_listening(
        self: Arc<Self>,
        config: Arc<DidcommConfig>,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let _ = self
            .clone()
            .set_public_acls_mode(config.only_admin_operations)
            .await
            .inspect_err(|e| {
                warn!("Failed to change ACL mode to public. Error: {}", e);
            });
        let cloned_self = self.clone();
        cloned_self.spawn_periodic_offline_sync().await;

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
