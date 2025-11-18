use std::sync::Arc;

use affinidi_tdk::didcomm::{Message, UnpackMetadata};
use app::storage::repository::{TrustRecordQuery, TrustRecordRepository};
use async_trait::async_trait;
use serde_json::json;
use tracing::{debug, error, info};
use uuid::Uuid;

use crate::handlers::{HandlerContext, ProtocolHandler};

pub const QUERY_AUTHORIZATION_MESSAGE_TYPE: &str =
    "https://affinidi.com/didcomm/protocols/trqp/1.0/query-authorization";
pub const QUERY_RECOGNITION_MESSAGE_TYPE: &str =
    "https://affinidi.com/didcomm/protocols/trqp/1.0/query-recognition";
pub const QUERY_AUTHORIZATION_RESPONSE_MESSAGE_TYPE: &str =
    "https://affinidi.com/didcomm/protocols/trqp/1.0/query-authorization/response";
pub const QUERY_RECOGNITION_RESPONSE_MESSAGE_TYPE: &str =
    "https://affinidi.com/didcomm/protocols/trqp/1.0/query-recognition/response";

pub struct TRQPMessagesHandler<R: ?Sized + TrustRecordRepository> {
    pub repository: Arc<R>,
}

#[async_trait]
impl<R: ?Sized + TrustRecordRepository + 'static> ProtocolHandler for TRQPMessagesHandler<R> {
    fn get_supported_inbound_message_types(&self) -> Vec<String> {
        vec![
            QUERY_AUTHORIZATION_MESSAGE_TYPE.to_string(),
            QUERY_RECOGNITION_MESSAGE_TYPE.to_string(),
        ]
    }

    async fn handle(
        &self,
        ctx: &Arc<HandlerContext>,
        message: Message,
        _meta: UnpackMetadata,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let output_message_type: String = format!("{}/response", message.type_);
        let query: TrustRecordQuery = serde_json::from_value(message.body)?;
        let record = self.repository.find_by_query(query).await?;
        let mut output_body = json!({});
        if let Some(tr) = record {
            output_body = serde_json::to_value(tr)?;
        }

        let message_id = Uuid::new_v4().to_string();
        let output_message = Message::build(message_id.clone(), output_message_type, output_body)
            .from(ctx.profile.inner.did.clone())
            .to(ctx.sender_did.clone())
            .finalize();

        let packed_msg = ctx
            .atm
            .pack_encrypted(
                &output_message,
                &ctx.sender_did,
                Some(&ctx.profile.inner.did),
                Some(&ctx.profile.inner.did),
                None,
            )
            .await?;

        let sending_result = ctx
            .atm
            .forward_and_send_message(
                &ctx.profile,
                false,
                &packed_msg.0,
                Some(&message_id),
                &ctx.profile.to_tdk_profile().mediator.unwrap(),
                &ctx.sender_did,
                None,
                None,
                false,
            )
            .await;

        debug!("sending result {:?}", sending_result);
        if let Err(sending_error) = sending_result {
            error!(
                "[profile = {}] Failed to forward message. Error: {:?}",
                &ctx.profile.inner.alias, sending_error
            );
        } else {
            info!(
                "[profile = {}] Response sent successfully",
                &ctx.profile.inner.alias
            );
        }
        Ok(())
    }
}
