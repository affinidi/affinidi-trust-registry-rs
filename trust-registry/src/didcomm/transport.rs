use std::sync::Arc;

use affinidi_tdk::{
    didcomm::Message,
    messaging::{ATM, profiles::ATMProfile},
};
use serde_json::Value;
use tracing::{error, info};

use crate::didcomm::new_message_id;

use super::problem_report::ProblemReport;

const PROBLEM_REPORT_TYPE: &str = "https://didcomm.org/report-problem/2.0/problem-report";

pub fn build_response(
    type_: String,
    from: String,
    to: String,
    body: Value,
    thid: Option<String>,
    pthid: Option<String>,
) -> Message {
    let mut builder = Message::build(new_message_id(), type_, body)
        .from(from)
        .to(to)
        .thid(thid.unwrap_or_else(new_message_id));

    if let Some(parent_id) = pthid {
        builder = builder.header("pthid".into(), Value::String(parent_id));
    }

    builder.finalize()
}

pub fn build_problem_report(
    from: String,
    to: String,
    report: ProblemReport,
    thid: Option<String>,
    pthid: Option<String>,
) -> Message {
    build_response(
        PROBLEM_REPORT_TYPE.to_string(),
        from,
        to,
        report.to_body(),
        thid,
        pthid,
    )
}

pub async fn send_response(
    atm: &Arc<ATM>,
    profile: &Arc<ATMProfile>,
    message_type: String,
    body: Value,
    recipient: &str,
    thid: Option<String>,
    pthid: Option<String>,
) -> Result<(), Box<dyn std::error::Error>> {
    let response_message = build_response(
        message_type,
        profile.inner.did.clone(),
        recipient.to_string(),
        body,
        thid,
        pthid,
    );

    let message_id = response_message.id.clone();

    let packed_msg = atm
        .pack_encrypted(
            &response_message,
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
            "[profile = {}] Failed to send response. Error: {:?}",
            &profile.inner.alias, sending_error
        );
        return Err(sending_error.into());
    }

    info!(
        "[profile = {}] Response sent successfully",
        &profile.inner.alias
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_response() {
        let msg = build_response(
            "https://example.com/test".to_string(),
            "did:example:alice".to_string(),
            "did:example:bob".to_string(),
            serde_json::json!({"result": "ok"}),
            Some("thread-123".to_string()),
            Some("parent-456".to_string()),
        );

        assert_eq!(msg.type_, "https://example.com/test");
        assert_eq!(msg.from.as_ref().unwrap(), "did:example:alice");
        assert_eq!(msg.to.as_ref().unwrap()[0], "did:example:bob");
        assert_eq!(msg.thid.as_ref().unwrap(), "thread-123");
    }
    #[test]
    fn test_build_problem_report() {
        let report = ProblemReport::unauthorized("Invalid DID");
        let msg = build_problem_report(
            "did:example:alice".to_string(),
            "did:example:bob".to_string(),
            report,
            Some("thread-123".to_string()),
            Some("parent-456".to_string()),
        );
        assert_eq!(msg.type_, PROBLEM_REPORT_TYPE);
        assert_eq!(msg.from.as_ref().unwrap(), "did:example:alice");
        assert_eq!(msg.to.as_ref().unwrap()[0], "did:example:bob");
        assert_eq!(msg.thid.as_ref().unwrap(), "thread-123");
    }
}
