use crate::didcomm::error::DIDCommError;
use crate::storage::repository::TrustRecordAdminRepository;
use std::sync::Arc;
use std::time::Duration;
use tokio::task::JoinError;
use tokio::time::sleep;
use tokio_util::sync::CancellationToken;

use affinidi_tdk::didcomm::{Message, UnpackMetadata};
use affinidi_tdk::messaging::{ATM, profiles::ATMProfile};
use async_trait::async_trait;
use tracing::{info, warn};

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

/// Checks if /.well-known/did.json is reachable
async fn check_did_document_availability(
    profile_did: &str,
    max_attempts: u32,
    retry_delay: Duration,
) -> Result<(), DIDCommError> {
    // Extract the base URL from did:web
    let did_document_url = if let Some(did_path) = profile_did.strip_prefix("did:web:") {
        let parts: Vec<&str> = did_path.split(':').collect();
        let domain = parts[0];

        if parts.len() > 1 {
            let path = parts[1..].join("/");
            format!("https://{}/{}/.well-known/did.json", domain, path)
        } else {
            format!("https://{}/.well-known/did.json", domain)
        }
    } else {
        // Skip for other DID methods
        info!(
            "DID method is not did:web, skipping DID document availability check for: {}",
            profile_did
        );
        return Ok(());
    };

    info!(
        "Checking DID document availability at: {}",
        did_document_url
    );

    let client = reqwest::Client::new();

    for attempt in 1..=max_attempts {
        match client.get(&did_document_url).send().await {
            Ok(response) => {
                if response.status().is_success() {
                    info!("DID document is accessible at {}", did_document_url);
                    return Ok(());
                } else {
                    warn!(
                        "DID document endpoint returned status {} (attempt {}/{})",
                        response.status(),
                        attempt,
                        max_attempts
                    );
                }
            }
            Err(e) => {
                warn!(
                    "Failed to reach DID document endpoint (attempt {}/{}): {}",
                    attempt, max_attempts, e
                );
            }
        }

        if attempt < max_attempts {
            info!("Retrying in {:?}...", retry_delay);
            sleep(retry_delay).await;
        }
    }

    Err(DIDCommError::UnreachableDidDocument)
}

pub(crate) async fn start_one_did_listener(
    profile_config: ProfileConfig,
    config: Arc<DidcommConfig>,
    repository: Arc<dyn TrustRecordAdminRepository>,
    shutdown: CancellationToken,
) -> Result<(), DIDCommError> {
    // Check if DID document is available before building listener
    check_did_document_availability(&profile_config.did, 20, Duration::from_secs(3)).await?;

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
