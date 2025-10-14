use std::sync::Arc;
use tokio::task::JoinError;
use tracing::error;

use crate::{
    configs::{DidcommServerConfigs, ProfileConfig},
    listener::listener::{Listener, MessageHandler},
};

pub mod build_listener;
pub mod listener;
pub mod start_listener;

pub struct DefaultHandler {}

impl MessageHandler for DefaultHandler {}

pub(crate) async fn start_one_did_listener(
    profile_config: ProfileConfig,
    config: Arc<DidcommServerConfigs>,
) {
    let listener =
        Listener::build_listener(profile_config, &config.mediator_did, DefaultHandler {})
            .await
            .unwrap(); // FIXME: handle error?
    listener.start_listening().await.unwrap(); // FIXME: handle error?
}

/// starts DIDComm listeners
/// the amount of listeners depends on amount of dids configured
/// for each did a separate listener will be configured
/// for now, one mediator for all.
/// TODO: each did may have its own mediator
pub(crate) async fn start_didcomm_listeners(config: DidcommServerConfigs) -> Result<(), JoinError> {
    let config = Arc::new(config);
    let handles: Vec<_> = config
        .profile_configs
        .clone()
        .into_iter()
        .map(|e| tokio::spawn(start_one_did_listener(e, config.clone())))
        .collect();

    for handle in handles {
        if let Err(e) = handle.await {
            error!("Service failed: {}", e);
            return Err(e);
        }
    }

    Ok(())
}
