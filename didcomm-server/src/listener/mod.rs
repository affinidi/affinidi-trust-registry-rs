use std::sync::Arc;
use app::storage::adapters::local_storage::LocalStorage;
use tokio::task::JoinError;
use tracing::error;

use affinidi_tdk::didcomm::{Message, UnpackMetadata};
use affinidi_tdk::messaging::{ATM, profiles::ATMProfile};
use async_trait::async_trait;
use tracing::info;

use crate::handlers::BaseHandler;
use crate::{
    configs::{DidcommServerConfigs, ProfileConfig},
};

pub mod build_listener;
pub mod start_listener;
pub mod mediator_functions;

#[async_trait]
pub trait MessageHandler: Send + Sync + 'static {
    // TODO: may grow a lot in case connection to DB and other possible things?
    async fn handle(
        &self,
        atm: &Arc<ATM>,
        profile: &Arc<ATMProfile>,
        message: Message,
        meta: UnpackMetadata,
    ) -> Result<(), Box<dyn std::error::Error>> {
        info!("[OnlyLoggingHandler]: Message: {:?}", message);
        info!("[OnlyLoggingHandler]: UnpackMetadata: {:?}", meta);
        info!("[OnlyLoggingHandler]: profile: {:?}", profile.inner.alias);
        let _no_warn_please = atm.clone();

        Ok(())
    }
}

pub struct DefaultHandler {}

impl MessageHandler for DefaultHandler {}
pub struct Listener<H: MessageHandler> {
    pub atm: Arc<ATM>,
    pub profile: Arc<ATMProfile>,
    pub handler: Arc<H>,
}

impl<H: MessageHandler> Listener<H> {
    pub fn new(atm: Arc<ATM>, profile: Arc<ATMProfile>, handler: Arc<H>) -> Self {
        Self {
            atm,
            profile,
            handler,
        }
    }
}


pub(crate) async fn start_one_did_listener(
    profile_config: ProfileConfig,
    config: Arc<DidcommServerConfigs>,
) {
    let local_storage = LocalStorage::new();
    let listener =
        Listener::build_listener(profile_config, &config.mediator_did, BaseHandler::build(Arc::new(local_storage)))
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
