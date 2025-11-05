use std::sync::Arc;

use affinidi_tdk::{
    didcomm::{Message, UnpackMetadata},
    messaging::{ATM, profiles::ATMProfile},
};
use async_trait::async_trait;
use tracing::info;

use crate::listener::MessageHandler;

use super::ProtocolHandler;

const PROBLEM_REPORT_TYPE: &str = "https://didcomm.org/report-problem/2.0/problem-report";

pub struct ProblemReportHandler;

impl ProblemReportHandler {
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl MessageHandler for ProblemReportHandler {
    async fn handle(
        &self,
        _atm: &Arc<ATM>,
        profile: &Arc<ATMProfile>,
        message: Message,
        _meta: UnpackMetadata,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let unknown = "unknown".to_string();
        let from = message.from.as_ref().unwrap_or(&unknown);
        let message_id = &message.id;

        let code = message
            .body
            .get("code")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown");
        let comment = message
            .body
            .get("comment")
            .and_then(|v| v.as_str())
            .unwrap_or("no comment");
        let args = message
            .body
            .get("args")
            .map(|v| serde_json::to_string(v).unwrap_or_default());
        let escalate_to = message.body.get("escalate_to").and_then(|v| v.as_str());
        let thid = message.thid.as_deref();
        let pthid = message.pthid.as_deref();

        info!(
            profile = %profile.inner.alias,
            from = %from,
            message_id = %message_id,
            code = %code,
            comment = %comment,
            ?args,
            ?escalate_to,
            ?thid,
            ?pthid,
            "[profile = {}] Problem Report received",
            profile.inner.alias
        );

        Ok(())
    }
}

impl ProtocolHandler for ProblemReportHandler {
    fn get_supported_inbound_message_types(&self) -> Vec<String> {
        vec![PROBLEM_REPORT_TYPE.to_string()]
    }
}
