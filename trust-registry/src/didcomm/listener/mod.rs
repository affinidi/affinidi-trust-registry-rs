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

/// Where the registry's DIDComm connection comes from.
///
/// The mediator permits **one websocket per DID**. That single constraint is
/// why this enum exists: a host that already holds a mediator connection for
/// the registry's DID cannot have the registry open a second one, so it must
/// either lend its connection ([`SharedAtm`](Self::SharedAtm)) or keep the
/// receive loop to itself ([`HostDriven`](Self::HostDriven)). It is the same
/// constraint that makes TSP frames arrive multiplexed on the DIDComm pickup
/// socket rather than on a socket of their own.
#[derive(Default, Clone)]
pub enum DidCommSource {
    /// The registry opens and owns its own mediator connection, building a
    /// `TDK`/`ATM` from `config.didcomm_config.profile_config`.
    ///
    /// The standalone default, and correct whenever the registry's DID is not
    /// already connected elsewhere.
    #[default]
    Managed,
    /// The host lends its existing connection. The registry attaches its
    /// handlers and drives the receive loop on the host's socket, opening none
    /// of its own.
    ///
    /// The host must **not** also be draining this profile's live stream:
    /// frames go to whichever reader takes them first, so two readers on one
    /// socket silently split the traffic. If the host needs to keep reading,
    /// use [`HostDriven`](Self::HostDriven) instead.
    SharedAtm {
        atm: Arc<ATM>,
        profile: Arc<ATMProfile>,
    },
    /// The registry never touches a socket. The host owns the receive loop and
    /// feeds documents in through
    /// [`TrustRegistry::route_didcomm_envelope`](crate::TrustRegistry::route_didcomm_envelope)
    /// or [`TrustRegistry::task_handler`](crate::TrustRegistry::task_handler),
    /// then sends the returned document back itself.
    HostDriven,
}

impl std::fmt::Debug for DidCommSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Managed => write!(f, "Managed"),
            Self::SharedAtm { profile, .. } => {
                write!(f, "SharedAtm({})", profile.inner.alias)
            }
            Self::HostDriven => write!(f, "HostDriven"),
        }
    }
}

/// TSP routing context attached to a [`Listener`] when built with `--features
/// tsp`. The dispatcher is shared (`Arc`) so per-frame handlers can be spawned
/// without cloning the closures; the proof verifier is the same one the DIDComm
/// handler uses.
#[cfg(feature = "tsp")]
pub(crate) struct TspContext {
    /// The same [`TaskHandler`](crate::trust_tasks::TaskHandler) the DIDComm
    /// binding routes through, so a document arriving over either transport
    /// gets the same freshness checks, write ACL, proof verification and
    /// message-id dedup — including replaying rather than re-applying a
    /// mutation redelivered over the *other* transport.
    pub(crate) tasks: crate::trust_tasks::TaskHandler,
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
    pub(crate) fn with_tsp(mut self, tasks: crate::trust_tasks::TaskHandler) -> Self {
        self.tsp = Some(TspContext { tasks });
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

#[allow(clippy::too_many_arguments)]
pub(crate) async fn start_one_did_listener(
    profile_config: ProfileConfig,
    config: Arc<DidcommConfig>,
    repository: Arc<dyn TrustRecordAdminRepository>,
    dispatcher: crate::capabilities::DispatcherHandle,
    dedup: Arc<dyn crate::dedup::MessageIdStore>,
    verifier: Arc<dyn trust_tasks_rs::DynProofVerifier>,
    source: DidCommSource,
    shutdown: CancellationToken,
) -> Result<(), DIDCommError> {
    // Does the document peers actually resolve match what this binary serves?
    // Checked here, before any source-specific setup, because every source has
    // the same exposure — the published document is written by the provisioning
    // VTA, not by us, so no runtime flag validation can catch a stale entry.
    // Advisory only: it logs, it never refuses to start.
    crate::didcomm::transport_capability::report_at_startup(
        &profile_config.did,
        &config.transport_flags,
    )
    .await;

    let handler = BaseHandler::build_from_arc(
        repository,
        config.clone(),
        verifier.clone(),
        dispatcher.clone(),
        dedup.clone(),
    );

    let listener = match source {
        DidCommSource::Managed => {
            // We are about to publish this DID as reachable, so refuse to start
            // until its DID document actually resolves.
            check_did_document_availability(
                &profile_config.did,
                config.retry_config.max_attempts,
                config.retry_config.initial_delay_secs,
                config.retry_config.max_delay_secs,
            )
            .await?;

            Listener::build_listener(
                profile_config.clone(),
                &config.mediator_did,
                handler,
                shutdown,
            )
            .await?
        }
        DidCommSource::SharedAtm { atm, profile } => {
            // The host already holds the connection, so there is no second
            // socket to open — the mediator would not allow one anyway (one
            // websocket per DID). Skipping `check_did_document_availability`
            // with it: the host resolved this DID to authenticate the
            // connection it is lending us, so the check is already answered.
            info!(
                "[profile = {}] Attaching to a host-provided mediator connection",
                &profile.inner.alias
            );
            Listener::new(atm, profile, Arc::new(handler), shutdown)
        }
        DidCommSource::HostDriven => {
            // Nothing to run: the host drives the receive loop and calls into
            // the registry itself. Reaching here means the listener was started
            // for a source that has no listener, which is a wiring bug.
            warn!(
                "DIDComm listener asked to start with DidCommSource::HostDriven; \
                 the host owns the receive loop, so nothing will be started"
            );
            return Ok(());
        }
    };

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
            crate::trust_tasks::TaskHandler::new(
                dispatcher.clone(),
                profile_config.did.clone(),
                config.admin_config.admin_dids.clone(),
                verifier.clone(),
            )
            .with_dedup(dedup.clone()),
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
#[allow(clippy::too_many_arguments)]
pub(crate) async fn start_didcomm_listener(
    config: DidcommConfig,
    repository: Arc<dyn TrustRecordAdminRepository>,
    dispatcher: crate::capabilities::DispatcherHandle,
    dedup: Arc<dyn crate::dedup::MessageIdStore>,
    verifier: Arc<dyn trust_tasks_rs::DynProofVerifier>,
    source: DidCommSource,
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
        verifier,
        source,
        shutdown,
    ));

    handle.await
}
