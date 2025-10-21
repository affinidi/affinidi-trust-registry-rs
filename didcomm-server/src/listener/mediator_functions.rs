use affinidi_tdk::didcomm::{Message, UnpackMetadata};
use affinidi_tdk::messaging::protocols::Protocols;
use tracing::{debug, error, info, warn};

use crate::listener::*;

impl<H: MessageHandler> Listener<H> {
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

    pub(crate) async fn process_next_message(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
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

        let messages_to_delete: Vec<_> = offline_arrived_messages.iter().map(|(m, _)| m.id.clone()).collect();

        offline_arrived_messages.into_iter().for_each(|(message, meta)| {
            self.spawn_handler(message, meta)
        });

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
}
