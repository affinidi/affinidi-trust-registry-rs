use std::sync::Arc;

use affinidi_tdk::messaging::{ATM, profiles::ATMProfile};
use serde_json::json;
use tracing::{error, info};

use super::transport;

pub mod codes {
    pub const ERROR_UNAUTHORIZED: &str = "e.p.msg.unauthorized";
    pub const ERROR_BAD_REQUEST: &str = "e.p.msg.bad-request";
    pub const ERROR_NOT_FOUND: &str = "e.p.msg.not-found";
    pub const ERROR_CONFLICT: &str = "e.p.msg.conflict";
    pub const ERROR_INTERNAL: &str = "e.p.msg.internal-error";
}

/// Problem report structure following DIDComm problem-report protocol
/// https://identity.foundation/didcomm-messaging/spec/#problem-reports
#[derive(Debug, Clone)]
pub struct ProblemReport {
    pub code: String,
    pub comment: String,
    pub args: Option<Vec<String>>,
    pub escalate_to: Option<String>,
}

impl ProblemReport {
    pub fn new(code: impl Into<String>, comment: impl Into<String>) -> Self {
        Self {
            code: code.into(),
            comment: comment.into(),
            args: None,
            escalate_to: None,
        }
    }

    pub fn unauthorized(comment: impl Into<String>) -> Self {
        Self::new(codes::ERROR_UNAUTHORIZED, comment)
    }

    pub fn bad_request(comment: impl Into<String>) -> Self {
        Self::new(codes::ERROR_BAD_REQUEST, comment)
    }

    pub fn not_found(comment: impl Into<String>) -> Self {
        Self::new(codes::ERROR_NOT_FOUND, comment)
    }

    pub fn conflict(comment: impl Into<String>) -> Self {
        Self::new(codes::ERROR_CONFLICT, comment)
    }

    pub fn internal_error(comment: impl Into<String>) -> Self {
        Self::new(codes::ERROR_INTERNAL, comment)
    }

    pub fn with_args(mut self, args: Vec<String>) -> Self {
        self.args = Some(args);
        self
    }

    pub fn with_escalate_to(mut self, escalate_to: String) -> Self {
        self.escalate_to = Some(escalate_to);
        self
    }

    pub fn to_body(&self) -> serde_json::Value {
        let mut body = json!({
            "code": self.code,
            "comment": self.comment
        });

        if let Some(args) = &self.args {
            body["args"] = json!(args);
        }

        if let Some(escalate_to) = &self.escalate_to {
            body["escalate_to"] = json!(escalate_to);
        }

        body
    }
}

/// Send a problem report message via ATM
pub async fn send_problem_report(
    atm: &Arc<ATM>,
    profile: &Arc<ATMProfile>,
    report: ProblemReport,
    recipient: &str,
    thid: Option<String>,
    pthid: Option<String>,
) -> Result<(), Box<dyn std::error::Error>> {
    let problem_message = transport::build_problem_report(
        profile.inner.did.clone(),
        recipient.to_string(),
        report,
        thid,
        pthid,
    );

    let message_id = problem_message.id.clone();

    let packed_msg = atm
        .pack_encrypted(
            &problem_message,
            recipient,
            Some(&profile.inner.did),
            Some(&profile.inner.did),
            None,
        )
        .await?;

    let sending_result = atm
        .forward_and_send_message(
            profile,
            false,
            &packed_msg.0,
            Some(&message_id),
            &profile.to_tdk_profile().mediator.unwrap(),
            recipient,
            None,
            None,
            false,
        )
        .await;

    if let Err(sending_error) = sending_result {
        error!(
            "[profile = {}] Failed to send problem report. Error: {:?}",
            &profile.inner.alias, sending_error
        );
        return Err(sending_error.into());
    }

    info!(
        "[profile = {}] Problem report sent successfully",
        &profile.inner.alias
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_problem_report_basic() {
        let report = ProblemReport::unauthorized("Invalid DID");
        let body = report.to_body();

        assert_eq!(body["code"], codes::ERROR_UNAUTHORIZED);
        assert_eq!(body["comment"], "Invalid DID");
    }

    #[test]
    fn test_problem_report_with_args() {
        let report = ProblemReport::bad_request("Missing fields")
            .with_args(vec!["entity_id".to_string(), "authority_id".to_string()]);
        let body = report.to_body();

        assert_eq!(body["code"], codes::ERROR_BAD_REQUEST);
        assert!(body["args"].is_array());
    }
}
