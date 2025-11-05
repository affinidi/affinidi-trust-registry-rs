use std::sync::Arc;

use affinidi_tdk::{
    didcomm::{Message, UnpackMetadata},
    messaging::{ATM, profiles::ATMProfile},
};
use app::storage::repository::TrustRecordAdminRepository;
use async_trait::async_trait;
use tracing::{error, info, warn};

use crate::{
    configs::AdminApiConfig,
    didcomm::{get_parent_thread_id, get_thread_id, problem_report},
    handlers::ProtocolHandler,
    listener::MessageHandler,
};

pub mod messages;

// Message type constants
pub const CREATE_RECORD_MESSAGE_TYPE: &str =
    "https://affinidi.com/didcomm/protocols/tr-admin/1.0/create-record";
pub const UPDATE_RECORD_MESSAGE_TYPE: &str =
    "https://affinidi.com/didcomm/protocols/tr-admin/1.0/update-record";
pub const DELETE_RECORD_MESSAGE_TYPE: &str =
    "https://affinidi.com/didcomm/protocols/tr-admin/1.0/delete-record";
pub const READ_RECORD_MESSAGE_TYPE: &str =
    "https://affinidi.com/didcomm/protocols/tr-admin/1.0/read-record";
pub const LIST_RECORDS_MESSAGE_TYPE: &str =
    "https://affinidi.com/didcomm/protocols/tr-admin/1.0/list-records";

// Response message types
pub const CREATE_RECORD_RESPONSE_MESSAGE_TYPE: &str =
    "https://affinidi.com/didcomm/protocols/tr-admin/1.0/create-record/response";
pub const UPDATE_RECORD_RESPONSE_MESSAGE_TYPE: &str =
    "https://affinidi.com/didcomm/protocols/tr-admin/1.0/update-record/response";
pub const DELETE_RECORD_RESPONSE_MESSAGE_TYPE: &str =
    "https://affinidi.com/didcomm/protocols/tr-admin/1.0/delete-record/response";
pub const READ_RECORD_RESPONSE_MESSAGE_TYPE: &str =
    "https://affinidi.com/didcomm/protocols/tr-admin/1.0/read-record/response";
pub const LIST_RECORDS_RESPONSE_MESSAGE_TYPE: &str =
    "https://affinidi.com/didcomm/protocols/tr-admin/1.0/list-records/response";

pub struct AdminMessagesHandler<R: ?Sized + TrustRecordAdminRepository> {
    pub repository: Arc<R>,
    pub admin_config: AdminApiConfig,
}

impl<R: ?Sized + TrustRecordAdminRepository> AdminMessagesHandler<R> {
    pub fn new(repository: Arc<R>, admin_config: AdminApiConfig) -> Self {
        Self {
            repository,
            admin_config,
        }
    }

    /// Validate that the sender DID is authorized as an admin
    fn validate_admin_did(&self, sender_did: &str) -> Result<(), String> {
        if self
            .admin_config
            .admin_dids
            .contains(&sender_did.to_string())
        {
            Ok(())
        } else {
            Err(format!(
                "Unauthorized: DID {} is not in admin list",
                sender_did
            ))
        }
    }
}

#[async_trait]
impl<R: ?Sized + TrustRecordAdminRepository + 'static> MessageHandler for AdminMessagesHandler<R> {
    async fn handle(
        &self,
        atm: &Arc<ATM>,
        profile: &Arc<ATMProfile>,
        message: Message,
        _meta: UnpackMetadata,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let message_type = message.type_.clone();
        let sender_did = message.from.clone().ok_or("Missing sender DID")?;

        let thid = get_thread_id(&message).or_else(|| Some(message.id.clone()));
        let pthid = get_parent_thread_id(&message);

        if let Err(auth_error) = self.validate_admin_did(&sender_did) {
            warn!(
                "[profile = {}] Unauthorized admin access attempt from {}: {}",
                &profile.inner.alias, sender_did, auth_error
            );
            let report = problem_report::ProblemReport::unauthorized(auth_error);
            if let Err(e) = problem_report::send_problem_report(
                atm,
                profile,
                report,
                &sender_did,
                thid.clone(),
                pthid.clone(),
            )
            .await
            {
                error!("Failed to send problem report: {}", e);
            }
            return Ok(());
        }

        info!(
            "[profile = {}] Admin operation: {} from {}",
            &profile.inner.alias, message_type, sender_did
        );

        // TODO: refactor to avoid code duplication
        let result = match message_type.as_str() {
            CREATE_RECORD_MESSAGE_TYPE => messages::handle_create_record(
                self,
                atm,
                profile,
                message,
                &sender_did,
                thid.clone(),
                pthid.clone(),
            )
            .await
            .map_err(|e| e.to_string()),
            UPDATE_RECORD_MESSAGE_TYPE => messages::handle_update_record(
                self,
                atm,
                profile,
                message,
                &sender_did,
                thid.clone(),
                pthid.clone(),
            )
            .await
            .map_err(|e| e.to_string()),
            DELETE_RECORD_MESSAGE_TYPE => messages::handle_delete_record(
                self,
                atm,
                profile,
                message,
                &sender_did,
                thid.clone(),
                pthid.clone(),
            )
            .await
            .map_err(|e| e.to_string()),
            READ_RECORD_MESSAGE_TYPE => messages::handle_read_record(
                self,
                atm,
                profile,
                message,
                &sender_did,
                thid.clone(),
                pthid.clone(),
            )
            .await
            .map_err(|e| e.to_string()),
            LIST_RECORDS_MESSAGE_TYPE => messages::handle_list_records(
                self,
                atm,
                profile,
                message,
                &sender_did,
                thid.clone(),
                pthid.clone(),
            )
            .await
            .map_err(|e| e.to_string()),
            _ => {
                warn!("Unknown admin message type: {}", message_type);
                let report = problem_report::ProblemReport::bad_request(format!(
                    "Unknown message type: {}",
                    message_type
                ));
                if let Err(e) = problem_report::send_problem_report(
                    atm,
                    profile,
                    report,
                    &sender_did,
                    thid.clone(),
                    pthid.clone(),
                )
                .await
                {
                    error!("Failed to send problem report: {}", e);
                }
                return Ok(());
            }
        };

        if let Err(error_msg) = result {
            error!(
                "[profile = {}] Admin operation failed: {}",
                &profile.inner.alias, error_msg
            );
            let report = problem_report::ProblemReport::internal_error(error_msg);
            if let Err(send_err) = problem_report::send_problem_report(
                atm,
                profile,
                report,
                &sender_did,
                thid.clone(),
                pthid.clone(),
            )
            .await
            {
                error!("Failed to send problem report: {}", send_err);
            }
        }

        Ok(())
    }
}

#[async_trait]
impl<R: ?Sized + TrustRecordAdminRepository + 'static> ProtocolHandler for AdminMessagesHandler<R> {
    fn get_supported_inbound_message_types(&self) -> Vec<String> {
        vec![
            CREATE_RECORD_MESSAGE_TYPE.to_string(),
            UPDATE_RECORD_MESSAGE_TYPE.to_string(),
            DELETE_RECORD_MESSAGE_TYPE.to_string(),
            READ_RECORD_MESSAGE_TYPE.to_string(),
            LIST_RECORDS_MESSAGE_TYPE.to_string(),
        ]
    }
}
