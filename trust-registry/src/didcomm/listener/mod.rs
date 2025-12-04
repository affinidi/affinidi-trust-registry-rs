use crate::storage::repository::TrustRecordAdminRepository;
use std::sync::Arc;
use tokio::task::JoinError;
use tracing::error;

use affinidi_tdk::didcomm::{Message, UnpackMetadata};
use affinidi_tdk::messaging::{ATM, profiles::ATMProfile};
use async_trait::async_trait;
use tracing::info;

use super::handlers::BaseHandler;
use crate::configs::{DidcommConfig, ProfileConfig};

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
    config: Arc<DidcommConfig>,
    repository: Arc<dyn TrustRecordAdminRepository>,
) {
    let listener = Listener::build_listener(
        profile_config,
        &config.mediator_did,
        BaseHandler::build_from_arc(repository, config.clone()),
    )
    .await
    .map_err(|e| {
        error!("Build listener error: {:?}", e);
        e
    })
    .unwrap();

    info!(
        "[profile = {}] Listener started",
        &listener.profile.inner.alias
    );

    Arc::new(listener)
        .start_listening()
        .await
        .map_err(|e| {
            error!("Start listener error: {:?}", e);
            e
        })
        .unwrap()
}

/// starts DIDComm listener for the configured DID profile
pub(crate) async fn start_didcomm_listener(
    config: DidcommConfig,
    repository: Arc<dyn TrustRecordAdminRepository>,
) -> Result<(), JoinError> {
    let profile_config = config.profile_config.clone();
    let config = Arc::new(config);

    let handle = tokio::spawn(start_one_did_listener(profile_config, config, repository));

    handle.await
}
