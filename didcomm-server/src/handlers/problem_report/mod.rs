use std::sync::Arc;

use affinidi_tdk::didcomm::{Message, UnpackMetadata};
use async_trait::async_trait;
use tracing::info;

use super::{HandlerContext, ProtocolHandler};

const PROBLEM_REPORT_TYPE: &str = "https://didcomm.org/report-problem/2.0/problem-report";

pub struct ProblemReportHandler;

impl ProblemReportHandler {
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl ProtocolHandler for ProblemReportHandler {
    fn get_supported_inbound_message_types(&self) -> Vec<String> {
        vec![PROBLEM_REPORT_TYPE.to_string()]
    }

    async fn handle(
        &self,
        ctx: &Arc<HandlerContext>,
        message: Message,
        _meta: UnpackMetadata,
    ) -> Result<(), Box<dyn std::error::Error>> {
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

        info!(
            profile = %ctx.profile.inner.alias,
            from = %ctx.sender_did,
            message_id = %message.id,
            code = %code,
            comment = %comment,
            ?args,
            ?escalate_to,
            thid = ?ctx.thid,
            pthid = ?ctx.pthid,
            "[profile = {}] Problem Report received",
            ctx.profile.inner.alias
        );

        Ok(())
    }
}
