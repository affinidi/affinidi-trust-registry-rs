use crate::didcomm::error::DIDCommError;
use crate::storage::repository::TrustRecordAdminRepository;
use std::sync::Arc;
use tokio::task::JoinError;
use tokio_util::sync::CancellationToken;

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
    pub(crate) shutdown: CancellationToken,
}

impl<H: MessageHandler> Listener<H> {
    pub fn new(
        atm: Arc<ATM>,
        profile: Arc<ATMProfile>,
        handler: Arc<H>,
        shutdown: CancellationToken,
    ) -> Self {
        Self {
            atm,
            profile,
            handler,
            shutdown,
        }
    }
}

pub(crate) async fn start_one_did_listener(
    profile_config: ProfileConfig,
    config: Arc<DidcommConfig>,
    repository: Arc<dyn TrustRecordAdminRepository>,
    shutdown: CancellationToken,
) -> Result<(), DIDCommError> {
    let listener = Listener::build_listener(
        profile_config,
        &config.mediator_did,
        BaseHandler::build_from_arc(repository, config.clone()),
        shutdown,
    )
    .await?;

    info!(
        "[profile = {}] Listener built",
        &listener.profile.inner.alias
    );

    Arc::new(listener).start_listening(config).await?;
    Ok(())
}

/// starts DIDComm listener for the configured DID profile
pub(crate) async fn start_didcomm_listener(
    config: DidcommConfig,
    repository: Arc<dyn TrustRecordAdminRepository>,
    shutdown: CancellationToken,
) -> Result<Result<(), DIDCommError>, JoinError> {
    let profile_config = config.profile_config.clone();
    let config = Arc::new(config);

    let handle = tokio::spawn(start_one_did_listener(
        profile_config,
        config,
        repository,
        shutdown,
    ));

    handle.await
}
