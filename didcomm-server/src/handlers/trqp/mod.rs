use std::sync::Arc;


use tracing::{debug, error, info};
use uuid::Uuid;
use affinidi_tdk::{didcomm::{Message, UnpackMetadata}, messaging::{profiles::ATMProfile, protocols::Protocols, ATM}};
use app::{domain::{EntityId, TrustRecordIds}, storage::repository::TrustRecordRepository};
use async_trait::async_trait;
use serde_json::{json, Value};

use crate::{handlers::ProtocolHandler, listener::MessageHandler};

pub const QUERY_AUTHORIZATION_MESSAGE_TYPE: &str = "https://affinidi.com/didcomm/protocols/trqp/1.0/query-authorization";
pub const QUERY_RECOGNITION_MESSAGE_TYPE: &str = "https://affinidi.com/didcomm/protocols/trqp/1.0/query-recognition";
pub const QUERY_AUTHORIZATION_RESPONSE_MESSAGE_TYPE: &str = "https://affinidi.com/didcomm/protocols/trqp/1.0/query-authorization/response";
pub const QUERY_RECOGNITION_RESPONSE_MESSAGE_TYPE: &str = "https://affinidi.com/didcomm/protocols/trqp/1.0/query-recognition/response";


// #[async_trait]
// impl<R: TrustRecordRepository + 'static> MessageHandler for BaseHandler<R> {

pub struct TRQPMessagesHandler<R: TrustRecordRepository> {
    pub repository: Arc<R>,
}

#[async_trait]
impl<R: TrustRecordRepository + 'static> MessageHandler for TRQPMessagesHandler<R> {
    async fn handle(
        &self,
        atm: &Arc<ATM>,
        profile: &Arc<ATMProfile>,
        message: Message,
        _meta: UnpackMetadata,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let output_message_type: String = format!("{}/response", message.type_);
        let message_sender = message
            .from
            .unwrap();
            // .ok_or_else(|| Err("Ignore message, no from field".into()))?;
        let ids: TrustRecordIds = serde_json::from_value(message.body)?;
        let mut output_body = serde_json::to_value(ids)?;
        if let Value::Object(map) = &mut output_body {
            map.insert("hello".to_string(), Value::String("world".to_string()));
        }

        let message_id = Uuid::new_v4().to_string();
        let output_message = Message::build(message_id.clone(), output_message_type, output_body)
            .from(profile.inner.did.clone())
            .to(message_sender.clone())
            .finalize();
        
        let packed_msg = atm
            .pack_encrypted(
                &output_message,
                &message_sender,
                Some(&profile.inner.did),
                Some(&profile.inner.did),
                None,
            )
            .await?;

        let sending_result = atm
            .forward_and_send_message(
                &profile,
                false,
                &packed_msg.0,
                Some(&message_id),
                &profile.to_tdk_profile().mediator.unwrap(),
                &message_sender,
                None, 
                None,
                false
            ).await;

        debug!("sending result {:?}", sending_result);
        if let Err(sending_error) = sending_result {
            error!("[profile = {}] Failed to forward message. Error: {:?}", &profile.inner.alias, sending_error);
        } else  {
            info!("[profile = {}] Response sent successfully", &profile.inner.alias);
        }
        Ok(())
    }
}

#[async_trait]
impl<R: TrustRecordRepository + 'static> ProtocolHandler for TRQPMessagesHandler<R> {
    fn get_supported_inboud_message_types(&self) -> Vec<String> {
        vec![
            QUERY_AUTHORIZATION_MESSAGE_TYPE.to_string(),
            QUERY_RECOGNITION_MESSAGE_TYPE.to_string(),
        ]
    }
}


