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
pub(crate) mod delivery;
pub mod mediator_functions;
pub mod start_listener;
#[cfg(test)]
mod tests;

/// Handles one unpacked inbound DIDComm message.
///
/// The pickup listener acks (deletes) the message at the mediator only after
/// `handle` returns `Ok`. An `Err` leaves it queued for a bounded redelivery,
/// so return `Err` only for a failure that may succeed on a later attempt, and
/// `Ok` once the message has been handled — including when it was answered
/// with an error or a problem report.
#[async_trait]
pub trait MessageHandler: Send + Sync + 'static {
    async fn handle(
        &self,
        atm: &Arc<ATM>,
        profile: &Arc<ATMProfile>,
        message: Message,
        meta: UnpackMetadata,
    ) -> Result<(), Box<dyn std::error::Error>>;
}

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
    ///
    /// With TSP enabled the registry receives through the SDK's
    /// `DidCommTransport` over this connection (see `crate::messaging`), and
    /// inbound TSP relationships are recorded in the lent ATM's relationship
    /// store, whose durability and bound are the host's to configure. The
    /// profile's websocket must already be enabled.
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

pub struct Listener<H: MessageHandler> {
    pub atm: Arc<ATM>,
    pub profile: Arc<ATMProfile>,
    pub handler: Arc<H>,
    pub(crate) shutdown: CancellationToken,
    /// Which mediator message ids are in flight or handled, so a message the
    /// live stream and the offline sync both fetch is handled once.
    pub(crate) ledger: Arc<std::sync::Mutex<delivery::DeliveryLedger>>,
    /// Handler slots; see [`delivery::MAX_INFLIGHT_HANDLERS`].
    pub(crate) permits: Arc<tokio::sync::Semaphore>,
    pub(crate) max_inflight: usize,
    /// Where mediator round trips and given-up messages are reported.
    pub(crate) health: Option<Arc<crate::health::RegistryHealth>>,
    /// Ids recently queued for background deletion, sent again directly on
    /// shutdown ([`mediator_functions::RecentAcks`]).
    pub(crate) acks: Arc<mediator_functions::RecentAcks>,
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
            ledger: Arc::default(),
            permits: Arc::new(tokio::sync::Semaphore::new(delivery::MAX_INFLIGHT_HANDLERS)),
            max_inflight: delivery::MAX_INFLIGHT_HANDLERS,
            health: None,
            acks: Arc::default(),
        }
    }

    /// Report mediator round trips (`writes`) and given-up messages
    /// (`givenUpMessages`) on `health`.
    pub(crate) fn with_health(
        mut self,
        health: Option<Arc<crate::health::RegistryHealth>>,
    ) -> Self {
        if let Some(health) = &health {
            health.attach_pickup_listener();
        }
        self.health = health;
        self
    }

    /// Bound concurrent handlers to `max` instead of
    /// [`delivery::MAX_INFLIGHT_HANDLERS`].
    #[cfg(test)]
    pub(crate) fn with_max_inflight(mut self, max: usize) -> Self {
        self.permits = Arc::new(tokio::sync::Semaphore::new(max));
        self.max_inflight = max;
        self
    }
}

/// The URL a `did:web` DID document is fetched from: `https://{domain}/.well-known/did.json`,
/// or `https://{domain}/{path}/did.json` for a DID with a path. `None` for any
/// other DID method.
fn did_web_document_url(profile_did: &str) -> Result<Option<String>, DIDCommError> {
    let Some(did_path) = profile_did.strip_prefix("did:web:") else {
        return Ok(None);
    };
    let parts: Vec<&str> = did_path.split(':').collect();
    // URL-decode the domain, which may carry a port: did:web:localhost%3A3232
    let domain = decode(parts[0]).map_err(|_| DIDCommError::InvalidDid)?;
    Ok(Some(if parts.len() > 1 {
        format!("https://{domain}/{}/did.json", parts[1..].join("/"))
    } else {
        format!("https://{domain}/.well-known/did.json")
    }))
}

/// Checks, with exponential retry, that a `did:web` DID document can be
/// fetched from [`did_web_document_url`]. Other DID methods are not checked.
async fn check_did_document_availability(
    profile_did: &str,
    max_attempts: u32,
    initial_delay_secs: u64,
    max_delay_secs: u64,
) -> Result<(), DIDCommError> {
    let Some(did_document_url) = did_web_document_url(profile_did)? else {
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

    Err(DIDCommError::UnreachableDidDocument(did_document_url))
}

pub(crate) async fn start_one_did_listener(
    profile_config: ProfileConfig,
    config: Arc<DidcommConfig>,
    repository: Arc<dyn TrustRecordAdminRepository>,
    tasks: crate::trust_tasks::TaskHandler,
    source: DidCommSource,
    health: Option<Arc<crate::health::RegistryHealth>>,
    shutdown: CancellationToken,
) -> Result<(), DIDCommError> {
    // The advertised-vs-served transport check runs from `TrustRegistryBuilder::build`
    // for every transport configuration, not here.
    let handler = BaseHandler::build_from_arc(repository, tasks.clone());

    // Only a connection the registry opened is the registry's to close; a
    // host's lent ATM is left alone.
    let owns_connection = matches!(source, DidCommSource::Managed);
    let listener = match source {
        DidCommSource::Managed => {
            // We are about to publish this DID as reachable, so refuse to start
            // until its DID document actually resolves. Its retries can take
            // minutes, so a shutdown meanwhile stops it rather than waiting.
            tokio::select! {
                checked = check_did_document_availability(
                    &profile_config.did,
                    config.retry_config.max_attempts,
                    config.retry_config.initial_delay_secs,
                    config.retry_config.max_delay_secs,
                ) => checked?,
                _ = shutdown.cancelled() => return Ok(()),
            }

            // A TSP-enabled registry receives through the SDK's
            // `DidCommTransport` instead of the pickup loop: that transport
            // records inbound TSP relationship-control frames (Rev 3 §7.2.2),
            // which an `atm.tsp().unpack()` on the pickup loop cannot, and this
            // path persists the relationship state across a restart. DIDComm
            // messages on the same socket go to the same `handler`; see
            // `crate::messaging` for how the two receive paths differ.
            #[cfg(feature = "tsp")]
            if config.transport_flags.tsp {
                return crate::messaging::service::start_managed_delivery(
                    profile_config,
                    config,
                    Arc::new(handler),
                    tasks,
                    health,
                    shutdown,
                )
                .await;
            }

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
            // TSP needs the delivery-layer receive path here too: the pickup
            // loop cannot record relationship-control frames, so with the
            // SDK's default §7.2.2 gating every TSP Trust Task from a peer
            // would be dropped. Relationship state is recorded in the lent
            // ATM's own relationship store.
            #[cfg(feature = "tsp")]
            if config.transport_flags.tsp {
                return crate::messaging::service::start_shared_delivery(
                    atm,
                    profile,
                    config,
                    Arc::new(handler),
                    tasks,
                    health,
                    shutdown,
                )
                .await;
            }
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

    // Only a registry with TSP disabled gets here; a TSP frame that reaches
    // this listener is acked as unservable (`mediator_functions::Work`).
    #[cfg(feature = "tsp")]
    info!(
        "[profile = {}] TSP disabled (ENABLE_TSP is not 'true'); TSP frames on this socket \
         will be dropped",
        &listener.profile.inner.alias
    );

    let atm = listener.atm.clone();
    let result = Arc::new(listener.with_health(health))
        .start_listening(config)
        .await;
    if owns_connection {
        close_owned_connection(&atm).await;
    }
    result
}

/// How long closing the registry's own mediator connection may take.
pub(crate) const CONNECTION_CLOSE_TIMEOUT: Duration = Duration::from_secs(10);

/// Close a mediator connection the registry opened itself, once the listener
/// has drained its handlers and sent their deletions directly
/// ([`Listener::flush_acks`]). Bounded by [`CONNECTION_CLOSE_TIMEOUT`].
async fn close_owned_connection(atm: &ATM) {
    if tokio::time::timeout(CONNECTION_CLOSE_TIMEOUT, atm.graceful_shutdown())
        .await
        .is_err()
    {
        warn!("closing the mediator connection took longer than {CONNECTION_CLOSE_TIMEOUT:?}");
    }
}

/// starts DIDComm listener for the configured DID profile
pub(crate) async fn start_didcomm_listener(
    config: DidcommConfig,
    repository: Arc<dyn TrustRecordAdminRepository>,
    tasks: crate::trust_tasks::TaskHandler,
    source: DidCommSource,
    health: Option<Arc<crate::health::RegistryHealth>>,
    shutdown: CancellationToken,
) -> Result<Result<(), DIDCommError>, JoinError> {
    let profile_config = config.profile_config.clone();
    let config = Arc::new(config);

    let handle = tokio::spawn(start_one_did_listener(
        profile_config,
        config,
        repository,
        tasks,
        source,
        health,
        shutdown,
    ));

    handle.await
}
