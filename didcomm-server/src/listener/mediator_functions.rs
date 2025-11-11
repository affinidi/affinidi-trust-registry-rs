use std::time::Duration;

use affinidi_tdk::didcomm::{Message, UnpackMetadata};
use affinidi_tdk::messaging::protocols::Protocols;
use affinidi_tdk::messaging::protocols::mediator::acls::{AccessListModeType, MediatorACLSet};
use sha256::digest;
use tracing::{debug, error, info, warn};

use crate::listener::*;

pub const OFFLINE_SYNC_INTERVAL_SECS: u64 = 30;
pub const MESSAGE_WAIT_DURATION_SECS: u64 = 5;

impl<H: MessageHandler> Listener<H> {
    pub(crate) async fn set_public_acls_mode(
        self: Arc<Self>,
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
        acls.set_access_list_mode(AccessListModeType::ExplicitDeny, true, false)?;

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
        let next_message_packet = protocols
            .message_pickup
            .live_stream_next(&self.atm, &self.profile, Some(wait_duration), auto_delete)
            .await?;

        if let Some((message, meta)) = next_message_packet {
            self.spawn_handler(message, *meta);
        }
        Ok(())
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

        // retrieve messages from mediator queue
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

        let messages_to_delete: Vec<_> = offline_arrived_messages
            .iter()
            .map(|(m, _)| m.id.clone())
            .collect();

        offline_arrived_messages
            .into_iter()
            .for_each(|(message, meta)| self.spawn_handler(message, meta));

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
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(std::time::Duration::from_secs(OFFLINE_SYNC_INTERVAL_SECS))
                    .await;
                let offline_messages_result = self.sync_and_process_offline_messages().await;

                if let Err(e) = offline_messages_result {
                    error!(
                        "[profile = {}] Error returned from offline_messages_result function. {}",
                        &self.profile.inner.alias, e
                    );
                }
            }
        });
    }
}
