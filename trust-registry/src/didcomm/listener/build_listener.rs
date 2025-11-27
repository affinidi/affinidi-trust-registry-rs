use std::{sync::Arc, time::Duration};

use affinidi_tdk::messaging::profiles::ATMProfile;
use affinidi_tdk::{
    TDK,
    common::{config::TDKConfig, profiles::TDKProfile},
};
use tokio::time::timeout;

use crate::{
    configs::ProfileConfig,
    didcomm::listener::{Listener, MessageHandler},
};

impl<H: MessageHandler> Listener<H> {
    pub async fn build_listener(
        profile_config: ProfileConfig,
        mediator_did: &str,
        handler: H,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let alias = &profile_config.alias;
        let did = &profile_config.did;
        let secrets = profile_config.secrets;
        let live_stream = true;

        let listener_profile_tdk = TDKProfile::new(alias, did, Some(mediator_did), secrets);

        let tdk = TDK::new(
            TDKConfig::builder().with_load_environment(false).build()?,
            None,
        )
        .await?;

        tdk.add_profile(&listener_profile_tdk).await;

        let atm = tdk.atm.clone().ok_or("Value is missing")?;

        let listener_profile = timeout(
            Duration::from_secs(10),
            atm.profile_add(
                &ATMProfile::from_tdk_profile(&atm, &listener_profile_tdk).await?,
                live_stream,
            ),
        )
        .await??;

        Ok(Self::new(
            Arc::new(atm),
            listener_profile,
            Arc::new(handler),
        ))
    }
}
