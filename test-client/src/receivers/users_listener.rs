use crate::service_configs::ServiceConfig;
use affinidi_tdk::messaging::{ATM, profiles::ATMProfile, protocols::Protocols};
use std::{sync::Arc, time::Duration};

pub async fn user_listener(
    did_config: ServiceConfig,
    atm: &Arc<ATM>,
    protocols: Arc<Protocols>,
    service_profile: &Arc<ATMProfile>,
) {
    // let mut to_delete = get_messages_and_process(atm, &protocols, service_profile).await;
    // if !to_delete.is_empty() {
    //     delete_messages_received(atm, &protocols, service_profile, &to_delete).await;
    // }

    let mut empty_response_count = 0;
    let max_empty_responses = 3;

    loop {
        println!("[{}] waiting for messages", did_config.alias);
        match protocols
            .message_pickup
            .live_stream_next(atm, service_profile, Some(Duration::from_secs(10)), true)
            .await
        {
            Ok(msg) => {
                if let Some(message) = msg {
                    println!("[{:?}] - Response: {:#?}", did_config.alias, message.0);
                    empty_response_count = 0;
                } else {
                    empty_response_count += 1;
                    if empty_response_count >= max_empty_responses {
                        println!("[{}] No more messages received. Terminating listener.", did_config.alias);
                        break;
                    }
                }
            }
            Err(err) => {
                println!(
                    "Error in receiving message for {}: {:#?}",
                    did_config.alias, err
                );
                empty_response_count += 1;
                if empty_response_count >= max_empty_responses {
                    println!("[{}] Multiple errors or timeouts. Terminating listener.", did_config.alias);
                    break;
                }
            }
        };
    }
}
