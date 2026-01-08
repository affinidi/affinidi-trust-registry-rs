use tracing::{debug, error, warn};

use crate::didcomm::listener::*;

impl<H: MessageHandler> Listener<H> {
    pub async fn start_listening(
        self: Arc<Self>,
        config: Arc<DidcommConfig>,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        
        let _ = match config.acl_mode.as_str() {
            "ExplicitAllow" => self.set_private_acl_mode().await,
            "ExplicitDeny" => self.set_public_acl_mode().await,
            _ => self.set_public_acl_mode().await,
        }
        .inspect_err(|e| {
            warn!("Failed to set ACL mode for Trust Registry DID. Error: {}", e);
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
