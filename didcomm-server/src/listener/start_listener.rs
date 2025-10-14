
use affinidi_messaging_didcomm::{Message, UnpackMetadata};
use affinidi_messaging_sdk::protocols::Protocols;
use tracing::{debug, error, info, warn};

use crate::listener::listener::*;

impl<H: MessageHandler> Listener<H> {
    /// Spawns a new asynchronous task with tokio
    /// to handle message with handler asyncroniously
    fn spawn_handler(&self, message: Message, meta: UnpackMetadata) {
        let handler = self.handler.clone();
        let profile = self.profile.clone();
        tokio::spawn(async move {
            let handling_result = handler.handle(message, meta).await;
            if let Err(error) = handling_result {
                error!(
                    "[profile = {}]. Error processing message. Error = {}",
                    &profile.inner.alias, error
                );
            }
        });
        // .await - ignore await to be ready receiving the next message almost immediately.
    }

    async fn process_next_message(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let auto_delete = true;
        let wait_duration = None;
        let protocols = Protocols::new();
        let next_message_packet = protocols
            .message_pickup
            .live_stream_next(&self.atm, &self.profile, wait_duration, auto_delete)
            .await?;

        if let Some((message, meta)) = next_message_packet {
            self.spawn_handler(message, *meta);
        }
        Ok(())
    }

    async fn sync_and_process_offline_messages(
        &self,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        // FIXME: too long, split that...
        let wait_for_response = true;
        let wait_duration = None;
        let messages_limit = 100;
        let protocols = Protocols::new();
        let status_reply = protocols
            .message_pickup
            .send_status_request(&self.atm, &self.profile, wait_for_response, wait_duration)
            .await?;

        debug!(
            "[profile = {}] status_reply = {:?}",
            &self.profile.inner.alias, status_reply
        );
        let messages_count = status_reply.map(|m| m.message_count)
            .unwrap_or(0);
        info!(
            "[profile = {}] Messages received offline. messages_count = {}",
            &self.profile.inner.alias, messages_count
        );

        if messages_count == 0 {
            return Ok(());
        }
        let delivery_reply = protocols
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
            &self.profile.inner.alias, delivery_reply
        );

        let messages_to_delete: Vec<_> = delivery_reply.iter().map(|(m, _)| m.id.clone()).collect();

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

    pub async fn start_listening(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        loop {
            let offline_messages_result = self.sync_and_process_offline_messages().await;
            if let Err(e) = offline_messages_result {
                error!(
                    "[profile = {}] Error returned from offline_messages_result function. {}",
                    &self.profile.inner.alias, e
                );
            }

            let next_message_result = self.process_next_message().await;

            if let Err(e) = next_message_result {
                error!(
                    "[profile = {}] Error returned from next_message_result function. {}",
                    &self.profile.inner.alias, e
                );
            }

            debug!(
                "[profile = {}] iteration is done.",
                &self.profile.inner.alias
            );
        }
        // Ok(())
    }
}
