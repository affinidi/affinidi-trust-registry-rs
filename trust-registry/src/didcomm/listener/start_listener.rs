use tracing::{error, info, warn};

use crate::didcomm::{
    error::DIDCommError,
    listener::{
        delivery::{
            ACK_TIMEOUT, Backoff, HANDLER_TIMEOUT, RECEIVE_BACKOFF_INITIAL, RECEIVE_BACKOFF_MAX,
            is_terminal_receive_error,
        },
        mediator_functions::{acl_failure_outcome, set_mediator_acl_mode},
        *,
    },
};

impl<H: MessageHandler> Listener<H> {
    /// Apply the configured access-list mode, then receive until the shutdown
    /// token is cancelled (returns `Ok(())`) or the profile's websocket is gone
    /// for good (returns the error, so `/health` reports writes unavailable).
    ///
    /// On shutdown, handlers already running are given up to their own time
    /// limit to finish and ack before this returns; a message whose handler is
    /// cut short stays queued at the mediator.
    pub async fn start_listening(
        self: Arc<Self>,
        config: Arc<DidcommConfig>,
    ) -> Result<(), DIDCommError> {
        // A private registry whose mode was not applied does not start
        // serving; a public one only warns. See `acl_failure_outcome`.
        if let Err(e) =
            set_mediator_acl_mode(&self.atm, &self.profile, config.acl_mode.clone()).await
        {
            acl_failure_outcome(&config.acl_mode, &e.to_string())?;
        }

        let sync = tokio::spawn(self.clone().run_offline_sync());
        let result = self.receive_until_shutdown().await;
        // On shutdown the sync task ends by itself; after a terminal error it
        // would only poll a dead profile.
        sync.abort();
        self.drain_handlers().await;
        // Deletions the handlers queued may still sit in the SDK's background
        // handler, which a closing connection does not drain: send them now.
        self.flush_acks().await;
        result
    }

    pub(crate) async fn receive_until_shutdown(&self) -> Result<(), DIDCommError> {
        let alias = &self.profile.inner.alias;
        let mut backoff = Backoff::new(RECEIVE_BACKOFF_INITIAL, RECEIVE_BACKOFF_MAX);
        loop {
            let received = tokio::select! {
                biased;
                _ = self.shutdown.cancelled() => break,
                received = self.process_next_message() => received,
            };
            match received {
                Ok(()) => backoff.reset(),
                Err(e) if is_terminal_receive_error(&e) => {
                    error!(
                        "[profile = {alias}] DIDComm listener stopping: the profile has no live \
                         websocket transport: {e}"
                    );
                    return Err(e.into());
                }
                Err(e) => {
                    let delay = backoff.next_delay();
                    warn!("[profile = {alias}] receiving failed; retrying in {delay:?}: {e}");
                    tokio::select! {
                        biased;
                        _ = self.shutdown.cancelled() => break,
                        _ = tokio::time::sleep(delay) => {}
                    }
                }
            }
        }
        info!("[profile = {alias}] DIDComm listener stopped (shutdown signalled)");
        Ok(())
    }

    /// Wait for running handlers to finish (each is bounded by
    /// [`HANDLER_TIMEOUT`]), so their acks are sent before the listener
    /// reports that it has stopped.
    async fn drain_handlers(&self) {
        let all = u32::try_from(self.max_inflight).unwrap_or(u32::MAX);
        let limit = HANDLER_TIMEOUT + ACK_TIMEOUT;
        if tokio::time::timeout(limit, self.permits.acquire_many(all))
            .await
            .is_err()
        {
            warn!(
                "[profile = {}] handlers still running {limit:?} after the listener stopped; \
                 their messages stay queued at the mediator",
                self.profile.inner.alias
            );
        }
    }
}
