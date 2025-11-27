use affinidi_tdk::{
    TDK,
    common::{config::TDKConfig, profiles::TDKProfile},
    didcomm::Message,
    messaging::{ATM, profiles::ATMProfile},
    secrets_resolver::secrets::Secret,
};
use std::{sync::Arc, time::Duration};
use tokio::time::timeout;
use tracing::error;
use uuid::Uuid;

pub mod handlers;
pub mod listener;
pub mod problem_report;
pub mod transport;

/// Returns the thread ID for a message, falling back to the message ID if no thread ID is set.
pub fn get_thread_id(msg: &Message) -> Option<String> {
    msg.thid.clone().or_else(|| Some(msg.id.clone()))
}

/// Returns the parent thread ID, falling back to thread ID, then message ID.
pub fn get_parent_thread_id(msg: &Message) -> Option<String> {
    msg.pthid.clone().or_else(|| get_thread_id(msg))
}

pub fn new_message_id() -> String {
    Uuid::new_v4().to_string()
}

pub async fn prepare_atm_and_profile(
    alias: &str,
    service_did: &str,
    mediator_did: &str,
    secrets: Vec<Secret>,
    live_stream: bool,
) -> Result<(Arc<ATM>, Arc<ATMProfile>), Box<dyn std::error::Error>> {
    let service_profile = TDKProfile::new(alias, service_did, Some(mediator_did), secrets);

    let tdk = TDK::new(
        TDKConfig::builder()
            .with_load_environment(false)
            .build()
            .map_err(|e| e.to_string())?,
        None,
    )
    .await
    .map_err(|e| e.to_string())?;
    tdk.add_profile(&service_profile).await;

    let atm = tdk
        .atm
        .clone()
        .ok_or_else(|| "Failed to initialize ATM client".to_owned())?;

    // When ACL is denied it keeps trying to authenticate in an infinite loop
    // https://github.com/affinidi/affinidi-messaging/blob/main/affinidi-messaging-sdk/src/transports/websockets/ws_connection.rs#L229
    // that's why it gets stuck if acl is denied without throwing any errors
    // that's why using timeout here so we can continue the loop and not get stuck
    let service_profile = match timeout(
        Duration::from_secs(5),
        atm.profile_add(
            &ATMProfile::from_tdk_profile(&atm, &service_profile)
                .await
                .map_err(|e| e.to_string())?,
            live_stream,
        ),
    )
    .await
    {
        Ok(profile) => profile.map_err(|e| e.to_string())?,
        Err(err) => {
            error!("Failed to add profile: {:?}, error: {:#?}", alias, err);
            return Err(format!("Failed to add profile: {:?}, error: {:#?}", alias, err).into());
        }
    };

    Ok((Arc::new(atm), service_profile))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_get_thread_id() {
        let msg = Message::build(new_message_id(), "test".to_string(), serde_json::json!({}))
            .thid("thread-123".to_string())
            .finalize();

        assert_eq!(get_thread_id(&msg), Some("thread-123".to_string()));
    }
    #[test]
    fn test_get_parent_thread_id() {
        let msg = Message::build(new_message_id(), "test".to_string(), serde_json::json!({}))
            .pthid("pthread-123".to_string())
            .finalize();

        assert_eq!(get_parent_thread_id(&msg), Some("pthread-123".to_string()));
    }
    #[test]
    fn test_get_parent_thread_id_not_found_getting_thid() {
        let msg = Message::build(new_message_id(), "test".to_string(), serde_json::json!({}))
            .thid("thread-123".to_string())
            .finalize();

        assert_eq!(get_parent_thread_id(&msg), Some("thread-123".to_string()));
    }

    #[test]
    fn test_new_message_id() {
        let id1 = new_message_id();
        let id2 = new_message_id();
        assert_ne!(id1, id2);
        assert!(Uuid::parse_str(&id1).is_ok());
    }
}
