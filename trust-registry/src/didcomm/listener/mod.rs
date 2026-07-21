use crate::didcomm::error::DIDCommError;
use crate::storage::repository::TrustRecordAdminRepository;
use std::sync::Arc;
use std::time::Duration;
use tokio::task::JoinError;
use tokio::time::sleep;
use tokio_util::sync::CancellationToken;
use urlencoding::decode;

use affinidi_tdk::didcomm::Message;
use affinidi_tdk::messaging::messages::compat::UnpackMetadata;
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

/// TSP routing context attached to a [`Listener`] when built with `--features
/// tsp`. The dispatcher is shared (`Arc`) so per-frame handlers can be spawned
/// without cloning the closures; the proof verifier is the same one the DIDComm
/// handler uses.
#[cfg(feature = "tsp")]
pub(crate) struct TspContext {
    pub(crate) dispatcher: crate::capabilities::DispatcherHandle,
    pub(crate) admin_dids: Vec<String>,
    pub(crate) verifier: Arc<dyn trust_tasks_rs::DynProofVerifier>,
    /// Write-path message-id dedup (R1.4), shared with the DIDComm binding so
    /// the same document redelivered over either transport is applied once.
    pub(crate) dedup: Arc<dyn crate::dedup::MessageIdStore>,
}

pub struct Listener<H: MessageHandler> {
    pub atm: Arc<ATM>,
    pub profile: Arc<ATMProfile>,
    pub handler: Arc<H>,
    pub(crate) shutdown: CancellationToken,
    /// Routing for TSP frames multiplexed onto the DIDComm pickup socket.
    #[cfg(feature = "tsp")]
    pub(crate) tsp: Option<TspContext>,
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
            #[cfg(feature = "tsp")]
            tsp: None,
        }
    }

    /// Attach the TSP dispatcher + proof verifier so TSP frames arriving on the
    /// shared pickup socket are routed through the same registry dispatcher as
    /// DIDComm.
    #[cfg(feature = "tsp")]
    pub(crate) fn with_tsp(
        mut self,
        dispatcher: crate::capabilities::DispatcherHandle,
        admin_dids: Vec<String>,
        verifier: Arc<dyn trust_tasks_rs::DynProofVerifier>,
        dedup: Arc<dyn crate::dedup::MessageIdStore>,
    ) -> Self {
        self.tsp = Some(TspContext {
            dispatcher,
            admin_dids,
            verifier,
            dedup,
        });
        self
    }
}

/// Checks if /.well-known/did.json is reachable with exponential retry
async fn check_did_document_availability(
    profile_did: &str,
    max_attempts: u32,
    initial_delay_secs: u64,
    max_delay_secs: u64,
) -> Result<(), DIDCommError> {
    // Extract the base URL from did:web
    let did_document_url = if let Some(did_path) = profile_did.strip_prefix("did:web:") {
        let parts: Vec<&str> = did_path.split(':').collect();
        // URL decode domain in case it contians port e.g. did:web:localhost%3A3232
        let domain = decode(parts[0]).map_err(|_| DIDCommError::InvalidDid)?;

        if parts.len() > 1 {
            let path = parts[1..].join("/");
            format!("https://{domain}/{path}/did.json")
        } else {
            format!("https://{domain}/.well-known/did.json")
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

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .map_err(DIDCommError::HttpRequest)?;

    let mut current_delay_secs = initial_delay_secs;

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
            let delay = Duration::from_secs(current_delay_secs);
            info!("Retrying in {:?}...", delay);
            sleep(delay).await;
            // Exponential backoff, cap at max_delay_secs
            current_delay_secs = (current_delay_secs * 2).min(max_delay_secs);
        }
    }

    Err(DIDCommError::UnreachableDidDocument)
}

pub(crate) async fn start_one_did_listener(
    profile_config: ProfileConfig,
    config: Arc<DidcommConfig>,
    repository: Arc<dyn TrustRecordAdminRepository>,
    dispatcher: crate::capabilities::DispatcherHandle,
    dedup: Arc<dyn crate::dedup::MessageIdStore>,
    shutdown: CancellationToken,
) -> Result<(), DIDCommError> {
    // Check if DID document is available before building listener
    check_did_document_availability(
        &profile_config.did,
        config.retry_config.max_attempts,
        config.retry_config.initial_delay_secs,
        config.retry_config.max_delay_secs,
    )
    .await?;

    // Build the Data Integrity proof verifier once and share it across the
    // DIDComm and TSP write paths.
    let verifier = crate::trust_tasks::build_verifier().await;

    let listener = Listener::build_listener(
        profile_config,
        &config.mediator_did,
        BaseHandler::build_from_arc(
            repository,
            config.clone(),
            verifier.clone(),
            dispatcher.clone(),
            dedup.clone(),
        ),
        shutdown,
    )
    .await?;

    info!(
        "[profile = {}] Listener built",
        &listener.profile.inner.alias
    );

    // TSP shares the DIDComm pickup socket (the mediator allows one websocket per
    // DID). Attach the TSP dispatcher + verifier so the receive loop routes
    // multiplexed `InboundFrame::Tsp` frames alongside DIDComm. Requires both the
    // `tsp` build feature and ENABLE_TSP=true — the same flag that decides whether
    // the DID document advertises `TSPTransport`, so the two cannot disagree.
    #[cfg(feature = "tsp")]
    let listener = if config.transport_flags.tsp {
        info!(
            "[profile = {}] TSP frames multiplexed on the DIDComm socket",
            &listener.profile.inner.alias
        );
        listener.with_tsp(
            dispatcher.clone(),
            config.admin_config.admin_dids.clone(),
            verifier.clone(),
            dedup.clone(),
        )
    } else {
        info!(
            "[profile = {}] TSP disabled (ENABLE_TSP is not 'true'); \
             multiplexed TSP frames will be ignored",
            &listener.profile.inner.alias
        );
        listener
    };

    Arc::new(listener).start_listening(config).await?;
    Ok(())
}

/// starts DIDComm listener for the configured DID profile
pub(crate) async fn start_didcomm_listener(
    config: DidcommConfig,
    repository: Arc<dyn TrustRecordAdminRepository>,
    dispatcher: crate::capabilities::DispatcherHandle,
    dedup: Arc<dyn crate::dedup::MessageIdStore>,
    shutdown: CancellationToken,
) -> Result<Result<(), DIDCommError>, JoinError> {
    let profile_config = config.profile_config.clone();
    let config = Arc::new(config);

    let handle = tokio::spawn(start_one_did_listener(
        profile_config,
        config,
        repository,
        dispatcher,
        dedup,
        shutdown,
    ));

    handle.await
}
