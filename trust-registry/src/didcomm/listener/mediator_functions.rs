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
/// Why a TSP frame on the pickup socket is acked without being handled.
const TSP_UNSERVABLE: &str = "a TSP frame, and this listener does not serve TSP (a \
    TSP-enabled registry receives on the delivery-layer path)";
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
    /// A frame this listener can never handle: a TSP frame (a TSP-enabled
    /// registry receives on the delivery-layer path, not here), or a frame
    /// kind this SDK version added. Acked like poison — see
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
                ack(&self.atm, &self.profile, &self.acks, &id).await;
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
        let health = self.health.clone();
        let acks = self.acks.clone();
        // Boxed: with every feature on, the handler futures nest deeply enough
        // to overflow the compiler's layout depth limit.
        let attempt = Box::pin(self.attempt(work));
        tokio::spawn(async move {
            // Held until the ack is sent, so a shutdown drain waits for it.
            let _permit = permit;
            let outcome = attempt.await;
            let decision = lock_ledger(&ledger).finish(&id, outcome, Instant::now());
            match decision {
                Ack::Now => ack(&atm, &profile, &acks, &id).await,
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
                    if let Some(health) = &health {
                        health.record_given_up();
                    }
                    ack(&atm, &profile, &acks, &id).await;
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
                Work::Unservable(why) => {
                    // R1.6, deliberate ack without handling: nothing in this
                    // listener will ever be able to handle it, so leaving it
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
        // pickup socket (the mediator allows one websocket per DID). This
        // listener runs only with TSP disabled, so a TSP frame is unservable.
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
                self.dispatch(id, Work::Unservable(TSP_UNSERVABLE)).await;
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
    ///
    /// With the `tsp` feature the drain asks for classified frames whatever
    /// `ENABLE_TSP` says: that call keeps each message's own `id` (which a
    /// reply to a request without a `thid` is threaded on), where the
    /// DIDComm-only call replaces it with the mediator's id.
    #[cfg(feature = "tsp")]
    pub(crate) async fn sync_and_process_offline_messages(&self) -> Result<(), ATMError> {
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
                Some(InboundFrame::Tsp(_)) => {
                    self.dispatch(id, Work::Unservable(TSP_UNSERVABLE)).await
                }
                Some(_) => {
                    self.dispatch(id, Work::Unservable("an inbound frame of an unknown kind"))
                        .await
                }
                None => {
                    self.undeliverable_at(&id, Instant::now()).await;
                }
            }
        }
        Ok(())
    }

    /// The DIDComm-only drain, for a build without the `tsp` feature (the
    /// SDK's frame call needs it).
    ///
    /// The SDK unpacks each queued message and classifies a failure itself:
    /// poison (bad encoding, a bad signature, a policy rejection) is deleted,
    /// a transient failure (a resolver hiccup) is left queued for the next
    /// sync. A TSP frame cannot be served here and is purged by the SDK.
    ///
    /// The SDK replaces each message's `id` with the mediator's id for it,
    /// which is the id to ack it by. A request without a `thid` fetched here
    /// therefore gets its reply threaded on the mediator's id rather than on
    /// its own; clients should set `thid`.
    #[cfg(not(feature = "tsp"))]
    pub(crate) async fn sync_and_process_offline_messages(&self) -> Result<(), ATMError> {
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

    /// A queued message the SDK could not decode or unpack (`(None, id)`),
    /// seen at `now`. Returns what was done about it at the mediator (`None`
    /// when another copy is being handled).
    ///
    /// The SDK does not say why, so a transient failure (the sender's DID
    /// briefly unresolvable) cannot be told from poison here. Acking it at
    /// once would turn a resolver hiccup into a lost signed write (R1.6), so
    /// it is treated as transient: left queued, offered again by the next
    /// sync, and given up on — acked, logged at `error` — only after it has
    /// failed [`delivery::GIVE_UP_ATTEMPTS`] times over
    /// [`delivery::GIVE_UP_MIN_AGE`].
    #[cfg(feature = "tsp")]
    pub(crate) async fn undeliverable_at(&self, id: &str, now: Instant) -> Option<Ack> {
        let decision = {
            let mut ledger = self.ledger();
            match ledger.claim(id, now) {
                Claim::InFlight => return None,
                Claim::AlreadyHandled => Ack::Now,
                Claim::Dispatch => ledger.finish(id, Outcome::Retry, now),
            }
        };
        match decision {
            Ack::Retain => warn!(
                "[profile = {}] queued message {id} could not be unpacked; left queued to \
                 retry on the next sync",
                self.profile.inner.alias
            ),
            Ack::Now => ack(&self.atm, &self.profile, &self.acks, &id).await,
            Ack::GiveUp => {
                error!(
                    "[profile = {}] queued message {id} still cannot be unpacked after {} \
                     attempts over at least {:?}; deleting it from the mediator as undeliverable",
                    self.profile.inner.alias,
                    delivery::GIVE_UP_ATTEMPTS,
                    delivery::GIVE_UP_MIN_AGE
                );
                if let Some(health) = &self.health {
                    health.record_given_up();
                }
                ack(&self.atm, &self.profile, &self.acks, &id).await;
            }
        }
        Some(decision)
    }

    /// Drain the mediator's queued backlog once at start, then every
    /// [`OFFLINE_SYNC_INTERVAL_SECS`] until shutdown.
    ///
    /// The periodic drain is also the redelivery path. The live stream offers
    /// queued messages again only when live delivery is switched on — on each
    /// websocket (re)connect the mediator pushes the stored inbox again — so
    /// on a steady connection a message left queued after a failed attempt is
    /// offered again by this sync.
    pub(crate) async fn run_offline_sync(self: Arc<Self>) {
        let interval = Duration::from_secs(OFFLINE_SYNC_INTERVAL_SECS);
        loop {
            tokio::select! {
                _ = self.shutdown.cancelled() => break,
                result = self.sync_and_process_offline_messages() => {
                    // Each sync is a round trip with the mediator, which makes
                    // it the listener's health probe.
                    match result {
                        Ok(()) => {
                            if let Some(health) = &self.health {
                                health.record_mediator_ok();
                            }
                        }
                        Err(e) => {
                            error!(
                                "[profile = {}] Offline sync failed: {}",
                                self.profile.inner.alias, e
                            );
                            if let Some(health) = &self.health {
                                health.record_mediator_failure();
                            }
                        }
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

/// How long an id queued for background deletion is remembered, so a
/// shutdown can send its deletion again directly. Comfortably longer than the
/// SDK's deletion handler takes to send a batch, retries included.
pub(crate) const RECENT_ACK_WINDOW: Duration = Duration::from_secs(60);
/// Most ids remembered for [`RECENT_ACK_WINDOW`].
const RECENT_ACK_CAPACITY: usize = 4_096;
/// Most ids one direct `DELETE` may carry (the mediator's limit).
const DIRECT_DELETE_BATCH: usize = 100;

/// Ids recently queued on the SDK's background deletion handler.
///
/// The handler sends deletions asynchronously, and shutting the ATM down
/// cancels it without draining its queue. A message handled just before a
/// stop would then stay on the mediator and be redelivered — and, with an
/// in-memory ledger and dedup store, applied again — after a restart (R1.6).
/// So on shutdown the listener deletes every recently acked id again,
/// directly, before the connection closes ([`Listener::flush_acks`]). Deleting
/// an id the handler already deleted is answered "not found", which is
/// harmless.
#[derive(Default)]
pub(crate) struct RecentAcks {
    ids: std::sync::Mutex<std::collections::VecDeque<(Instant, String)>>,
}

impl RecentAcks {
    pub(crate) fn record(&self, id: &str, now: Instant) {
        let mut ids = self
            .ids
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        while ids
            .front()
            .is_some_and(|(at, _)| now.saturating_duration_since(*at) > RECENT_ACK_WINDOW)
            || ids.len() >= RECENT_ACK_CAPACITY
        {
            ids.pop_front();
        }
        ids.push_back((now, id.to_string()));
    }

    /// Take every id acked within [`RECENT_ACK_WINDOW`] of `now`.
    pub(crate) fn take_recent(&self, now: Instant) -> Vec<String> {
        let mut ids = self
            .ids
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        ids.drain(..)
            .filter(|(at, _)| now.saturating_duration_since(*at) <= RECENT_ACK_WINDOW)
            .map(|(_, id)| id)
            .collect()
    }
}

impl<H: MessageHandler> Listener<H> {
    /// Send the deletion of every recently acked message directly, so none is
    /// left in the background handler's queue when the connection closes. Run
    /// once the handlers have drained; each request is bounded by
    /// [`ACK_TIMEOUT`].
    pub(crate) async fn flush_acks(&self) {
        let ids = self.acks.take_recent(Instant::now());
        if ids.is_empty() {
            return;
        }
        let alias = &self.profile.inner.alias;
        for batch in ids.chunks(DIRECT_DELETE_BATCH) {
            let request = affinidi_tdk::messaging::messages::DeleteMessageRequest {
                message_ids: batch.to_vec(),
            };
            match tokio::time::timeout(
                ACK_TIMEOUT,
                self.atm.delete_messages_direct(&self.profile, &request),
            )
            .await
            {
                Ok(Ok(_)) => debug!(
                    "[profile = {alias}] sent the deletion of {} recently acked messages",
                    batch.len()
                ),
                Ok(Err(e)) => warn!(
                    "[profile = {alias}] could not send the deletion of {} recently acked \
                     messages before stopping (they may be redelivered): {e}",
                    batch.len()
                ),
                Err(_) => warn!(
                    "[profile = {alias}] sending the deletion of {} recently acked messages \
                     timed out before stopping (they may be redelivered)",
                    batch.len()
                ),
            }
        }
    }
}

/// Delete `id` at the mediator. A failure is not lost: the message is still
/// queued, the next sync offers it again, and the ledger acks it again
/// without handling it again.
async fn ack(atm: &Arc<ATM>, profile: &Arc<ATMProfile>, acks: &RecentAcks, id: &str) {
    acks.record(id, Instant::now());
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
