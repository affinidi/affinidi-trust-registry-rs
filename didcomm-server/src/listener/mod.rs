use app::storage::adapters::csv_file_storage::FileStorage;
use app::storage::adapters::local_storage::LocalStorage;
use std::sync::Arc;
use tokio::task::JoinError;
use tracing::error;

use affinidi_tdk::didcomm::{Message, UnpackMetadata};
use affinidi_tdk::messaging::{ATM, profiles::ATMProfile};
use async_trait::async_trait;
use tracing::info;

use crate::configs::{DidcommServerConfigs, ProfileConfig};
use crate::handlers::BaseHandler;

pub mod build_listener;
pub mod mediator_functions;
pub mod start_listener;

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
    // TODO: should one instance be provided for all listeners?
    let file_storage_repository = if config.file_storage_config.is_some() {
        let file_storage_config = config.file_storage_config.as_ref().unwrap();
        let file_path = file_storage_config.file_path.clone();
        let update_interval_sec = file_storage_config.update_interval_sec;
        Some(
            FileStorage::try_new(file_path, update_interval_sec)
                .await
                .unwrap(),
        ) // FIXME: handle error?
    } else {
        None
    };
    if let Some(file_storage) = file_storage_repository {
        let listener = Listener::build_listener(
            profile_config,
            &config.mediator_did,
            BaseHandler::build(Arc::new(file_storage)),
        )
        .await
        .unwrap(); // FIXME: handle error?
        info!(
            "[profile = {}] Listener started with CSV file storage",
            &listener.profile.inner.alias
        );
        listener.start_listening().await.unwrap(); // FIXME: handle error?
    } else {
        let local_storage = LocalStorage::new();
        let listener = Listener::build_listener(
            profile_config,
            &config.mediator_did,
            BaseHandler::build(Arc::new(local_storage)),
        )
        .await
        .unwrap(); // FIXME: handle error?
        info!(
            "[profile = {}] Listener started with Local storage",
            &listener.profile.inner.alias
        );
        listener.start_listening().await.unwrap(); // FIXME: handle error?
    }
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
