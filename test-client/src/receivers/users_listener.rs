use crate::service_configs::ServiceConfig;
use affinidi_tdk::messaging::{ATM, profiles::ATMProfile};
use std::{sync::Arc, time::Duration};

pub async fn user_listener(
    did_config: ServiceConfig,
    atm: &Arc<ATM>,
    service_profile: &Arc<ATMProfile>,
) {
    loop {
        println!("[{}] waiting for messages", did_config.alias);
        match atm
            .message_pickup()
            .live_stream_next(service_profile, Some(Duration::from_secs(10)), true)
            .await
        {
            Ok(msg) => {
                if let Some(message) = msg {
                    println!("[{:?}] - Response: {:#?}", did_config.alias, message.0);
                }
            }
            Err(err) => {
                println!(
                    "Error in receiving message for {}: {:#?}",
                    did_config.alias, err
                )
            }
        };
    }
}
