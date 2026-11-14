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

use crate::didcomm::error::DIDCommError;

pub mod did_document;
pub mod error;
pub mod handlers;
pub mod listener;
pub mod problem_report;
pub mod transport;
pub mod transport_capability;

/// Returns the thread ID for a message, falling back to the message ID if no thread ID is set.
pub fn get_thread_id(msg: &Message) -> Option<String> {
    msg.thid.clone().or_else(|| Some(msg.id.clone()))
}

pub fn new_message_id() -> String {
    Uuid::new_v4().to_string()
}

/// How long adding a profile (and opening its mediator websocket) may take.
///
/// Bounded because the SDK retries authentication indefinitely when the
/// mediator's ACL denies the DID, so an unbounded `profile_add` would hang
/// without an error.
pub const PROFILE_ADD_TIMEOUT: Duration = Duration::from_secs(10);

/// Build a `TDK`/`ATM` holding one profile for `did` and register it with the
/// mediator (opening its websocket when `live_stream` is set), bounded by
/// [`PROFILE_ADD_TIMEOUT`].
///
/// The one bootstrap the pickup listener and the integration tests share.
pub(crate) async fn connect_profile(
    alias: &str,
    did: &str,
    mediator_did: &str,
    secrets: Vec<Secret>,
    live_stream: bool,
) -> Result<(Arc<ATM>, Arc<ATMProfile>), DIDCommError> {
    let tdk_profile = TDKProfile::new(alias, did, Some(mediator_did), secrets);
    let tdk = TDK::new(
        TDKConfig::builder().with_load_environment(false).build()?,
        None,
    )
    .await?;
    tdk.add_profile(&tdk_profile).await;

    let atm = tdk.atm.clone().ok_or(DIDCommError::MissingATM)?;
    let profile = ATMProfile::from_tdk_profile(&atm, &tdk_profile).await?;
    let profile = timeout(PROFILE_ADD_TIMEOUT, atm.profile_add(&profile, live_stream))
        .await
        .inspect_err(|_| {
            error!("Adding profile {alias:?} timed out after {PROFILE_ADD_TIMEOUT:?}");
        })??;
    Ok((Arc::new(atm), profile))
}

/// [`connect_profile`] for callers outside the crate (the integration tests
/// act as DIDComm clients with it).
pub async fn prepare_atm_and_profile(
    alias: &str,
    service_did: &str,
    mediator_did: &str,
    secrets: Vec<Secret>,
    live_stream: bool,
) -> Result<(Arc<ATM>, Arc<ATMProfile>), Box<dyn std::error::Error>> {
    Ok(connect_profile(alias, service_did, mediator_did, secrets, live_stream).await?)
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
    fn test_new_message_id() {
        let id1 = new_message_id();
        let id2 = new_message_id();
        assert_ne!(id1, id2);
        assert!(Uuid::parse_str(&id1).is_ok());
    }
}
