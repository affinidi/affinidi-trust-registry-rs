use std::sync::Arc;

use tokio_util::sync::CancellationToken;

use crate::didcomm::error::DIDCommError;
use crate::{
    configs::ProfileConfig,
    didcomm::{
        connect_profile,
        listener::{Listener, MessageHandler},
    },
};

impl<H: MessageHandler> Listener<H> {
    /// Open the registry's own mediator connection for `profile_config` and
    /// build a listener over it.
    pub async fn build_listener(
        profile_config: ProfileConfig,
        mediator_did: &str,
        handler: H,
        shutdown: CancellationToken,
    ) -> Result<Self, DIDCommError> {
        let (atm, profile) = connect_profile(
            &profile_config.alias,
            &profile_config.did,
            mediator_did,
            profile_config.secrets,
            true,
        )
        .await?;
        Ok(Self::new(atm, profile, Arc::new(handler), shutdown))
    }
}
