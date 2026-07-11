// The `Protocols` API is deprecated in affinidi-messaging-sdk 0.18 in favour of
// ATM accessor methods (`atm.mediator()`, `atm.message_pickup()`, ...). Migrating
// those call sites is a separate cleanup; this upgrade keeps the working code path
// unchanged, so we suppress the deprecation warning here only.
#![allow(deprecated)]

use std::time::Duration;

use affinidi_tdk::didcomm::Message;
use affinidi_tdk::messaging::messages::compat::UnpackMetadata;
use affinidi_tdk::messaging::protocols::Protocols;
use affinidi_tdk::messaging::protocols::mediator::acls::{AccessListModeType, MediatorACLSet};
use affinidi_tdk::messaging::protocols::message_pickup::InboundFrame;
use sha256::digest;
use tracing::{debug, error, info, warn};

use crate::didcomm::listener::*;

pub const OFFLINE_SYNC_INTERVAL_SECS: u64 = 30;
pub const MESSAGE_WAIT_DURATION_SECS: u64 = 5;

impl<H: MessageHandler> Listener<H> {
    /// Sets ACL mode of Trust Registry DID to public mode
    /// Anyone can send messages to TR DID
    pub(crate) async fn set_public_acl_mode(
        &self,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        return self.set_acls_mode(AccessListModeType::ExplicitDeny).await;
    }

    /// Sets ACL mode of Trust Registry DID to private mode
    /// Only DIDs in the allow list can send messages to TR DID
    pub(crate) async fn set_private_acl_mode(
        &self,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        return self.set_acls_mode(AccessListModeType::ExplicitAllow).await;
    }

    /// Sets ACLs mode for the mediator associated with this listener's profile (TR DID)
    /// to either public or private.
    /// AccessListModeType::ExplicitDeny - public mode - anyone can send messages to TR DID
    /// AccessListModeType::ExplicitAllow - private mode - only DIDs in the allow list can send messages to TR DID
    pub(crate) async fn set_acls_mode(
        &self,
        acl_mode: AccessListModeType,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let protocols = Protocols::new();

        let account_get_result = protocols
            .mediator
            .account_get(&self.atm, &self.profile, None)
            .await;

        let account_info = account_get_result?.ok_or(format!(
            "[profile = {}] Failed to get account info",
            &self.profile.inner.alias
        ))?;

        let mut acls = MediatorACLSet::from_u64(account_info.acls);

        info!("ACL_MODE: Configured to {:?}", acl_mode);

        acls.set_access_list_mode(acl_mode, true, false)?;

        protocols
            .mediator
            .acls_set(
                &self.atm,
                &self.profile,
                &digest(&self.profile.inner.did),
                &acls,
            )
            .await?;
        Ok(())
    }
    /// Spawns a new asynchronous task with tokio
    /// to handle message with handler asyncroniously
    fn spawn_handler(&self, message: Message, meta: UnpackMetadata) {
        let handler = self.handler.clone();
        let profile = self.profile.clone();
        let atm = self.atm.clone();
        tokio::spawn(async move {
            let handling_result = handler.handle(&atm, &profile, message, meta).await;
            if let Err(error) = handling_result {
                error!(
                    "[profile = {}]. Error processing message. Error = {}",
                    &profile.inner.alias, error
                );
            }
        });
        // .await - ignore await to be ready receiving the next message almost immediately.
    }

    pub(crate) async fn process_next_message(
        &self,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let auto_delete = true;
        let wait_duration = Duration::from_secs(MESSAGE_WAIT_DURATION_SECS);
        let protocols = Protocols::new();
        // `live_stream_next_frame` pulls DIDComm *and* TSP frames off the single
        // pickup socket (the mediator allows one websocket per DID), so both
        // transports are multiplexed here instead of on a second TSP socket.
        let frame = protocols
            .message_pickup
            .live_stream_next_frame(&self.atm, &self.profile, Some(wait_duration), auto_delete)
            .await?;

        match frame {
            Some(InboundFrame::DidComm(message, meta)) => self.spawn_handler(*message, *meta),
            #[cfg(feature = "tsp")]
            Some(InboundFrame::Tsp(packed)) => self.spawn_tsp_handler(*packed),
            // Non-exhaustive frame kinds — and, without `--features tsp`, TSP
            // frames — are ignored.
            Some(_) => {}
            None => {}
        }
        Ok(())
    }

    /// Route a multiplexed TSP frame through the shared registry dispatcher on a
    /// spawned task, so TSP crypto/dispatch never blocks the DIDComm receive loop.
    #[cfg(feature = "tsp")]
    fn spawn_tsp_handler(&self, packed: String) {
        let Some(tsp) = &self.tsp else {
            warn!(
                "[profile = {}] TSP frame received but no TSP dispatcher is configured",
                &self.profile.inner.alias
            );
            return;
        };
        let atm = self.atm.clone();
        let profile = self.profile.clone();
        let dispatcher = tsp.dispatcher.clone();
        let admin_dids = tsp.admin_dids.clone();
        let verifier = tsp.verifier.clone();
        tokio::spawn(async move {
            crate::tsp::process_tsp_frame(
                &atm,
                &profile,
                &dispatcher,
                &admin_dids,
                &verifier,
                &packed,
            )
            .await;
        });
    }

    pub(crate) async fn sync_and_process_offline_messages(
        &self,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        // FIXME: too long, split that...
        let wait_for_response = true;
        let wait_duration = None;
        let messages_limit = 100;
        let protocols = Protocols::new();
        // get count of messages in mediator
        let status_reply = protocols
            .message_pickup
            .send_status_request(&self.atm, &self.profile, wait_for_response, wait_duration)
            .await?;

        debug!(
            "[profile = {}] status_reply = {:?}",
            &self.profile.inner.alias, status_reply
        );
        let messages_count = status_reply.map(|m| m.message_count).unwrap_or(0);
        info!(
            "[profile = {}] Messages received offline. messages_count = {}",
            &self.profile.inner.alias, messages_count
        );

        if messages_count == 0 {
            return Ok(());
        }

        // Retrieve + dispatch the queued backlog. With `--features tsp` we fetch
        // it as classified frames so a queued TSP message is routed to the TSP
        // handler instead of being DIDComm-unpacked and dropped (mirrors the SDK's
        // own TSP-aware offline sync). Every retrieved id is acked so the mediator
        // stops redelivering it.
        #[cfg(feature = "tsp")]
        let messages_to_delete: Vec<String> = {
            let frames = protocols
                .message_pickup
                .send_delivery_request_frames(
                    &self.atm,
                    &self.profile,
                    Some(messages_limit),
                    wait_for_response,
                )
                .await?;

            let ack_ids: Vec<String> = frames.iter().map(|(_, id)| id.clone()).collect();
            for (frame, _id) in frames {
                match frame {
                    Some(InboundFrame::DidComm(message, meta)) => {
                        self.spawn_handler(*message, *meta)
                    }
                    Some(InboundFrame::Tsp(packed)) => self.spawn_tsp_handler(*packed),
                    Some(_) => {}
                    None => {}
                }
            }
            ack_ids
        };

        #[cfg(not(feature = "tsp"))]
        let messages_to_delete: Vec<String> = {
            let offline_arrived_messages = protocols
                .message_pickup
                .send_delivery_request(
                    &self.atm,
                    &self.profile,
                    Some(messages_limit),
                    wait_for_response,
                )
                .await?;

            debug!(
                "[profile = {}] delivery_reply = {:?}",
                &self.profile.inner.alias, offline_arrived_messages
            );

            let ids: Vec<String> = offline_arrived_messages
                .iter()
                .map(|(m, _)| m.id.clone())
                .collect();

            offline_arrived_messages
                .into_iter()
                .for_each(|(message, meta)| self.spawn_handler(message, meta));

            ids
        };

        // delete these from mediator queue
        let delete_messages_reply = protocols
            .message_pickup
            .send_messages_received(
                &self.atm,
                &self.profile,
                &messages_to_delete,
                wait_for_response,
            )
            .await?;

        debug!(
            "[profile = {}] delete_messages_reply = {:?}",
            &self.profile.inner.alias, delete_messages_reply
        );

        if delete_messages_reply.is_some() {
            info!(
                "[profile = {}] messages deleted.",
                &self.profile.inner.alias
            );
        } else {
            warn!(
                "[profile = {}] no status reply for messages received ack. Messages might be deleted or not",
                &self.profile.inner.alias
            );
        }

        Ok(())
    }

    pub(crate) async fn spawn_periodic_offline_sync(self: Arc<Self>) {
        let shutdown = self.shutdown.clone();
        let profile_alias = self.profile.inner.alias.clone();
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = shutdown.cancelled() => {
                        info!("[profile = {}] Offline sync task shutting down", profile_alias);
                        break;
                    }
                    _ = tokio::time::sleep(std::time::Duration::from_secs(OFFLINE_SYNC_INTERVAL_SECS)) => {
                        let offline_messages_result = self.sync_and_process_offline_messages().await;

                        if let Err(e) = offline_messages_result {
                            error!(
                                "[profile = {}] Error returned from offline_messages_result function. {}",
                                &self.profile.inner.alias, e
                            );
                        }
                    }
                }
            }
        });
    }
}
