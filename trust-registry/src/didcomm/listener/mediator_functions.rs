use std::future::Future;
use std::sync::Arc;
use std::time::Duration;

use affinidi_tdk::didcomm::Message;
use affinidi_tdk::messaging::errors::ATMError;
use affinidi_tdk::messaging::messages::compat::UnpackMetadata;
use affinidi_tdk::messaging::protocols::mediator::acls::AccessListModeType;
use affinidi_tdk::messaging::protocols::message_pickup::InboundFrame;
use affinidi_tdk::messaging::{ATM, profiles::ATMProfile};
use tokio::time::Instant;
use tracing::{debug, error, info, warn};

use crate::didcomm::error::DIDCommError;
use crate::didcomm::listener::delivery::{ACK_TIMEOUT, Ack, Claim, HANDLER_TIMEOUT, Outcome};
use crate::didcomm::listener::*;

pub const OFFLINE_SYNC_INTERVAL_SECS: u64 = 30;
pub const MESSAGE_WAIT_DURATION_SECS: u64 = 5;
/// Most queued messages one offline-sync cycle fetches.
const OFFLINE_BATCH_LIMIT: usize = 100;

/// Set the mediator's access-list mode for `profile`. Shared by the pickup
/// listener and the delivery-layer receive path ([`crate::messaging::service`]),
/// which builds no [`Listener`], so both apply the identical mode before they
/// start receiving.
pub(crate) async fn set_mediator_acl_mode(
    atm: &std::sync::Arc<affinidi_tdk::messaging::ATM>,
    profile: &std::sync::Arc<affinidi_tdk::messaging::profiles::ATMProfile>,
    acl_mode: AccessListModeType,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    info!("ACL_MODE: Configured to {:?}", acl_mode);
    let mode = match acl_mode {
        AccessListModeType::ExplicitAllow => crate::mediator_acl::AccessListMode::ExplicitAllow,
        AccessListModeType::ExplicitDeny => crate::mediator_acl::AccessListMode::ExplicitDeny,
    };
    crate::mediator_acl::set_access_list_mode(atm, profile, mode).await
}

/// What a refused or failed access-list update means for the listener.
///
/// A private registry (`ExplicitAllow`) fails closed: its mediator account may
/// still accept messages from anyone, so serving DIDComm would expose a
/// registry configured to answer only its allow list. The listener does not
/// start, and `/health` reports the reason. A public registry (`ExplicitDeny`)
/// only warns: if its mode did not change it is, at worst, still private,
/// which makes it unreachable rather than exposed.
pub(crate) fn acl_failure_outcome(
    acl_mode: &AccessListModeType,
    error: &str,
) -> Result<(), DIDCommError> {
    match acl_mode {
        AccessListModeType::ExplicitAllow => {
            Err(DIDCommError::PrivateAclNotApplied(error.to_string()))
        }
        AccessListModeType::ExplicitDeny => {
            warn!("Failed to set ACL mode for Trust Registry DID. Error: {error}");
            Ok(())
        }
    }
}

/// One message taken off the mediator queue, ready to be handled.
pub(crate) enum Work {
    DidComm(Box<Message>, Box<UnpackMetadata>),
    /// A TSP frame, for a listener with TSP enabled.
    #[cfg(feature = "tsp")]
    Tsp(String),
    /// A frame this listener can never handle as configured: a TSP frame when
    /// TSP is not enabled (or not built). Acked like poison — see
    /// [`Listener::dispatch`].
    Unservable(&'static str),
}

impl<H: MessageHandler> Listener<H> {
    fn ledger(&self) -> std::sync::MutexGuard<'_, delivery::DeliveryLedger> {
        lock_ledger(&self.ledger)
    }

    /// Hand one message to its handler, at most once per mediator message id,
    /// and ack it at the mediator only once the handler has finished.
    ///
    /// Waits for a handler slot first ([`delivery::MAX_INFLIGHT_HANDLERS`]),
    /// so the receive loop stops taking messages off the socket while the
    /// handlers are saturated. Returns without dispatching on shutdown.
    pub(crate) async fn dispatch(&self, id: String, work: Work) {
        // Bound first: the ledger lock must not be held across an await.
        let claim = self.ledger().claim(&id, Instant::now());
        match claim {
            Claim::Dispatch => {}
            Claim::InFlight => {
                // The other consumer of this queue (live stream or offline
                // sync) is handling it; that handler acks it when it is done.
                debug!(
                    "[profile = {}] message {id} is already being handled; skipped",
                    self.profile.inner.alias
                );
                return;
            }
            Claim::AlreadyHandled => {
                // Handled, but still queued: the earlier ack did not land.
                // Ack again; do not answer or apply it a second time.
                debug!(
                    "[profile = {}] message {id} was already handled; acking it again",
                    self.profile.inner.alias
                );
                ack(&self.atm, &self.profile, &id).await;
                return;
            }
        }

        let permit = tokio::select! {
            permit = self.permits.clone().acquire_owned() => permit.ok(),
            _ = self.shutdown.cancelled() => None,
        };
        let Some(permit) = permit else {
            // Not handled, so not acked: it stays queued for the next start.
            self.ledger().release(&id);
            return;
        };

        let atm = self.atm.clone();
        let profile = self.profile.clone();
        let ledger = self.ledger.clone();
        // Boxed: with every feature on, the handler futures nest deeply enough
        // to overflow the compiler's layout depth limit.
        let attempt = Box::pin(self.attempt(work));
        tokio::spawn(async move {
            // Held until the ack is sent, so a shutdown drain waits for it.
            let _permit = permit;
            let outcome = attempt.await;
            let decision = lock_ledger(&ledger).finish(&id, outcome, Instant::now());
            match decision {
                Ack::Now => ack(&atm, &profile, &id).await,
                Ack::Retain => warn!(
                    "[profile = {}] message {id} not handled; left queued at the mediator \
                     for redelivery",
                    profile.inner.alias
                ),
                Ack::GiveUp => {
                    error!(
                        "[profile = {}] message {id} still failing after {} attempts over at \
                         least {:?}; deleting it from the mediator as undeliverable",
                        profile.inner.alias,
                        delivery::GIVE_UP_ATTEMPTS,
                        delivery::GIVE_UP_MIN_AGE
                    );
                    ack(&atm, &profile, &id).await;
                }
            }
        });
    }

    /// The handling of `work` as a `'static` future, bounded by
    /// [`HANDLER_TIMEOUT`].
    fn attempt(&self, work: Work) -> impl Future<Output = Outcome> + Send + 'static {
        let atm = self.atm.clone();
        let profile = self.profile.clone();
        let handler = self.handler.clone();
        #[cfg(feature = "tsp")]
        let tsp = self.tsp.as_ref().map(|t| t.tasks.clone());
        async move {
            let alias = profile.inner.alias.clone();
            match work {
                Work::DidComm(message, meta) => {
                    let message_type = message.typ.clone();
                    bounded(&alias, &message_type, async move {
                        match handler.handle(&atm, &profile, *message, *meta).await {
                            Ok(()) => Ok(()),
                            Err(e) => Err(e.to_string()),
                        }
                    })
                    .await
                }
                #[cfg(feature = "tsp")]
                Work::Tsp(packed) => {
                    let Some(tasks) = tsp else {
                        return Outcome::Poison;
                    };
                    let task = async move {
                        Ok::<_, String>(
                            Box::pin(crate::tsp::process_tsp_frame(
                                &atm, &profile, &tasks, &packed,
                            ))
                            .await,
                        )
                    };
                    match bounded_value(&alias, "TSP frame", task).await {
                        Some(crate::tsp::FrameOutcome::Handled) => Outcome::Handled,
                        // Poison (it can never unpack, or its contents are not
                        // a Trust Task): acked so it stops being redelivered.
                        Some(crate::tsp::FrameOutcome::Poison) => Outcome::Poison,
                        Some(crate::tsp::FrameOutcome::Transient) | None => Outcome::Retry,
                    }
                }
                Work::Unservable(why) => {
                    // R1.6, deliberate ack without handling: nothing in this
                    // process will ever be able to handle it, so leaving it
                    // queued would only have it redelivered until the
                    // mediator's expiry. The SDK's DIDComm-only drain purges
                    // the same frames for the same reason.
                    warn!("[profile = {alias}] dropping a frame this listener cannot serve: {why}");
                    Outcome::Poison
                }
            }
        }
    }

    pub(crate) async fn process_next_message(&self) -> Result<(), ATMError> {
        let wait_duration = Duration::from_secs(MESSAGE_WAIT_DURATION_SECS);
        // `auto_delete = false` (R1.6): the mediator keeps its copy until the
        // handler has finished and `dispatch` acks it. A frame that fails to
        // unpack never reaches us — the SDK's receive leg retains a transient
        // failure and deletes a permanent one itself.
        //
        // `live_stream_next_frame` pulls DIDComm *and* TSP frames off the single
        // pickup socket (the mediator allows one websocket per DID), so both
        // transports are multiplexed here instead of on a second TSP socket.
        let frame = self
            .atm
            .message_pickup()
            .live_stream_next_frame(&self.profile, Some(wait_duration), false)
            .await?;

        match frame {
            Some(InboundFrame::DidComm(message, meta)) => {
                let id = meta.sha256_hash.clone();
                self.dispatch(id, Work::DidComm(message, meta)).await;
            }
            Some(InboundFrame::Tsp(packed)) => {
                // The live path carries no attachment id; the mediator's id
                // for a TSP frame is sha256 of the stored frame, which is what
                // the SDK deletes by too.
                let id = sha256::digest(packed.as_str());
                self.dispatch(id, self.tsp_work(*packed)).await;
            }
            Some(_) => {
                // A frame kind this SDK version added: no id to ack it by, so
                // it is left queued.
                warn!(
                    "[profile = {}] ignoring an inbound frame of an unknown kind",
                    self.profile.inner.alias
                );
            }
            None => {}
        }
        Ok(())
    }

    #[cfg(feature = "tsp")]
    fn tsp_work(&self, packed: String) -> Work {
        if self.tsp.is_some() {
            Work::Tsp(packed)
        } else {
            Work::Unservable("a TSP frame, and TSP is not enabled (ENABLE_TSP is not 'true')")
        }
    }

    #[cfg(not(feature = "tsp"))]
    fn tsp_work(&self, _packed: String) -> Work {
        Work::Unservable("a TSP frame, and this build has no `tsp` feature")
    }

    /// An idle registry polls the mediator every 30s and almost always finds
    /// nothing, so an empty batch is logged at debug and only a batch with work
    /// in it reaches info.
    fn log_offline_batch(&self, count: usize) {
        if count == 0 {
            debug!(
                "[profile = {}] Offline sync: mediator queue is empty.",
                self.profile.inner.alias
            );
        } else {
            info!(
                "[profile = {}] Messages received offline. messages_count = {}",
                self.profile.inner.alias, count
            );
        }
    }

    /// Fetch the mediator's queued backlog and dispatch it.
    ///
    /// Nothing is acked here: each message is acked by its own handler task
    /// once handled (see [`dispatch`](Self::dispatch)). A message the live
    /// stream is already handling is skipped, and one already handled whose
    /// ack did not land is acked again without being handled again.
    ///
    /// Ask the mediator for the queued messages directly rather than first
    /// asking for a queue-depth status: a status reply that goes astray — it is
    /// answered on the same socket the live-delivery loop is draining — is
    /// indistinguishable from a genuine zero.
    pub(crate) async fn sync_and_process_offline_messages(&self) -> Result<(), ATMError> {
        #[cfg(feature = "tsp")]
        if self.tsp.is_some() {
            return self.sync_offline_frames().await;
        }

        // DIDComm only. The SDK unpacks each queued message and classifies a
        // failure itself: poison (bad encoding, a bad signature, a policy
        // rejection) is deleted, a transient failure (a resolver hiccup) is
        // left queued for the next sync. A TSP frame cannot be served here and
        // is purged by the SDK.
        //
        // The SDK replaces each message's `id` with the mediator's id for it,
        // which is the id to ack it by — and, for a request without a `thid`,
        // also the thread a reply falls back to.
        let messages = self
            .atm
            .message_pickup()
            .send_delivery_request(&self.profile, Some(OFFLINE_BATCH_LIMIT), true)
            .await?;
        self.log_offline_batch(messages.len());
        for (message, meta) in messages {
            if self.shutdown.is_cancelled() {
                break;
            }
            let id = message.id.clone();
            self.dispatch(id, Work::DidComm(Box::new(message), Box::new(meta)))
                .await;
        }
        Ok(())
    }

    /// The TSP-aware drain: queued messages come back as classified frames, so
    /// a TSP frame is routed to the TSP handler instead of being purged.
    #[cfg(feature = "tsp")]
    async fn sync_offline_frames(&self) -> Result<(), ATMError> {
        let frames = self
            .atm
            .message_pickup()
            .send_delivery_request_frames(&self.profile, Some(OFFLINE_BATCH_LIMIT), true)
            .await?;
        self.log_offline_batch(frames.len());
        for (frame, id) in frames {
            if self.shutdown.is_cancelled() {
                break;
            }
            match frame {
                Some(InboundFrame::DidComm(message, meta)) => {
                    self.dispatch(id, Work::DidComm(message, meta)).await
                }
                Some(InboundFrame::Tsp(packed)) => self.dispatch(id, self.tsp_work(*packed)).await,
                Some(_) => {
                    self.dispatch(id, Work::Unservable("an inbound frame of an unknown kind"))
                        .await
                }
                None => self.undeliverable(id).await,
            }
        }
        Ok(())
    }

    /// A queued message the SDK could not decode or unpack (`(None, id)`).
    ///
    /// The SDK does not say why, so a transient failure (the sender's DID
    /// briefly unresolvable) cannot be told from poison here. Acking it at
    /// once would turn a resolver hiccup into a lost signed write (R1.6), so
    /// it is treated as transient: left queued, offered again by the next
    /// sync, and given up on — acked, logged at `error` — only after it has
    /// failed [`delivery::GIVE_UP_ATTEMPTS`] times over
    /// [`delivery::GIVE_UP_MIN_AGE`].
    #[cfg(feature = "tsp")]
    async fn undeliverable(&self, id: String) {
        let now = Instant::now();
        let decision = {
            let mut ledger = self.ledger();
            match ledger.claim(&id, now) {
                Claim::InFlight => return,
                Claim::AlreadyHandled => Ack::Now,
                Claim::Dispatch => ledger.finish(&id, Outcome::Retry, now),
            }
        };
        match decision {
            Ack::Retain => warn!(
                "[profile = {}] queued message {id} could not be unpacked; left queued to \
                 retry on the next sync",
                self.profile.inner.alias
            ),
            Ack::Now => ack(&self.atm, &self.profile, &id).await,
            Ack::GiveUp => {
                error!(
                    "[profile = {}] queued message {id} still cannot be unpacked after {} \
                     attempts over at least {:?}; deleting it from the mediator as undeliverable",
                    self.profile.inner.alias,
                    delivery::GIVE_UP_ATTEMPTS,
                    delivery::GIVE_UP_MIN_AGE
                );
                ack(&self.atm, &self.profile, &id).await;
            }
        }
    }

    /// Drain the mediator's queued backlog once at start, then every
    /// [`OFFLINE_SYNC_INTERVAL_SECS`] until shutdown.
    ///
    /// The periodic drain is also the redelivery path: the live stream pushes
    /// a message once, so a message left queued after a failed attempt is
    /// offered again only by this sync.
    pub(crate) async fn run_offline_sync(self: Arc<Self>) {
        let interval = Duration::from_secs(OFFLINE_SYNC_INTERVAL_SECS);
        loop {
            tokio::select! {
                _ = self.shutdown.cancelled() => break,
                result = self.sync_and_process_offline_messages() => {
                    if let Err(e) = result {
                        error!(
                            "[profile = {}] Offline sync failed: {}",
                            self.profile.inner.alias, e
                        );
                    }
                }
            }
            tokio::select! {
                _ = self.shutdown.cancelled() => break,
                _ = tokio::time::sleep(interval) => {}
            }
        }
        info!(
            "[profile = {}] Offline sync task shutting down",
            self.profile.inner.alias
        );
    }
}

pub(crate) fn lock_ledger(
    ledger: &std::sync::Mutex<delivery::DeliveryLedger>,
) -> std::sync::MutexGuard<'_, delivery::DeliveryLedger> {
    // The ledger is only ever updated by short, non-panicking critical
    // sections; a poisoned lock still holds a consistent ledger.
    ledger
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// Delete `id` at the mediator. A failure is not lost: the message is still
/// queued, the next sync offers it again, and the ledger acks it again
/// without handling it again.
async fn ack(atm: &Arc<ATM>, profile: &Arc<ATMProfile>, id: &str) {
    match tokio::time::timeout(ACK_TIMEOUT, atm.delete_message_background(profile, id)).await {
        Ok(Ok(())) => debug!("[profile = {}] message {id} acked", profile.inner.alias),
        Ok(Err(e)) => warn!(
            "[profile = {}] could not ack message {id} (it will be redelivered and acked \
             again): {e}",
            profile.inner.alias
        ),
        Err(_) => warn!(
            "[profile = {}] acking message {id} timed out (it will be redelivered and acked \
             again)",
            profile.inner.alias
        ),
    }
}

/// Run `task` on its own task under [`HANDLER_TIMEOUT`], mapping a returned
/// error, a panic or a timeout to [`Outcome::Retry`].
async fn bounded<F>(alias: &str, what: &str, task: F) -> Outcome
where
    F: Future<Output = Result<(), String>> + Send + 'static,
{
    match bounded_value(alias, what, task).await {
        Some(()) => Outcome::Handled,
        None => Outcome::Retry,
    }
}

async fn bounded_value<T, F>(alias: &str, what: &str, task: F) -> Option<T>
where
    T: Send + 'static,
    F: Future<Output = Result<T, String>> + Send + 'static,
{
    bounded_value_within(HANDLER_TIMEOUT, alias, what, task).await
}

pub(crate) async fn bounded_value_within<T, F>(
    limit: Duration,
    alias: &str,
    what: &str,
    task: F,
) -> Option<T>
where
    T: Send + 'static,
    F: Future<Output = Result<T, String>> + Send + 'static,
{
    let mut handle = tokio::spawn(task);
    match tokio::time::timeout(limit, &mut handle).await {
        Ok(Ok(Ok(value))) => Some(value),
        Ok(Ok(Err(e))) => {
            error!("[profile = {alias}] handling {what} failed: {e}");
            None
        }
        Ok(Err(join_error)) => {
            error!("[profile = {alias}] handler for {what} panicked: {join_error}");
            None
        }
        Err(_) => {
            handle.abort();
            error!(
                "[profile = {alias}] handling {what} did not finish within {limit:?}; abandoned"
            );
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_private_registry_fails_closed_when_its_mode_is_not_applied() {
        let outcome = acl_failure_outcome(&AccessListModeType::ExplicitAllow, "proof_required");
        assert!(
            matches!(&outcome, Err(DIDCommError::PrivateAclNotApplied(e)) if e == "proof_required"),
            "{outcome:?}"
        );
    }

    #[test]
    fn a_public_registry_only_warns_when_its_mode_is_not_applied() {
        assert!(acl_failure_outcome(&AccessListModeType::ExplicitDeny, "proof_required").is_ok());
    }

    #[tokio::test]
    async fn a_handler_that_fails_panics_or_hangs_is_not_handled() {
        let limit = Duration::from_millis(50);
        assert_eq!(
            bounded_value_within(limit, "t", "ok", async { Ok::<_, String>(1) }).await,
            Some(1)
        );
        assert_eq!(
            bounded_value_within(limit, "t", "err", async {
                Err::<(), _>("boom".to_string())
            })
            .await,
            None
        );
        assert_eq!(
            bounded_value_within(limit, "t", "panic", async {
                panic!("handler panicked");
                #[allow(unreachable_code)]
                Ok::<(), String>(())
            })
            .await,
            None
        );
        assert_eq!(
            bounded_value_within(limit, "t", "hang", async {
                tokio::time::sleep(Duration::from_secs(60)).await;
                Ok::<(), String>(())
            })
            .await,
            None
        );
    }
}
