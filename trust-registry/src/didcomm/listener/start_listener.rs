use tracing::{debug, error};

use crate::didcomm::{
    error::DIDCommError,
    listener::{mediator_functions::acl_failure_outcome, *},
};
use affinidi_tdk::messaging::protocols::mediator::acls::AccessListModeType;

impl<H: MessageHandler> Listener<H> {
    pub async fn start_listening(
        self: Arc<Self>,
        config: Arc<DidcommConfig>,
    ) -> Result<(), DIDCommError> {
        let applied = if config.acl_mode == AccessListModeType::ExplicitAllow {
            self.set_private_acl_mode().await
        } else {
            self.set_public_acl_mode().await
        };
        // A private registry whose mode was not applied does not start
        // serving; a public one only warns. See `acl_failure_outcome`.
        if let Err(e) = applied {
            acl_failure_outcome(&config.acl_mode, &e.to_string())?;
        }

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
