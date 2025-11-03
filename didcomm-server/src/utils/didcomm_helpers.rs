use std::sync::Arc;

use affinidi_tdk::{
    didcomm::Message,
    messaging::{ATM, profiles::ATMProfile},
};
use serde_json::Value;
use tracing::{error, info};
use uuid::Uuid;

use super::problem_report::ProblemReport;

const PROBLEM_REPORT_TYPE: &str = "https://didcomm.org/report-problem/2.0/problem-report";

pub fn new_message_id() -> String {
    Uuid::new_v4().to_string()
}

pub fn build_response(
    type_: String,
    from: String,
    to: String,
    body: Value,
    thid: Option<String>,
    pthid: Option<String>,
) -> Message {
    let mut builder = Message::build(
        new_message_id(),
        type_,
        body,
    )
    .from(from)
    .to(to)
    .thid(thid.unwrap_or_else(new_message_id));

    if let Some(parent_id) = pthid {
        builder = builder.header("pthid".into(), Value::String(parent_id));
    }

    builder.finalize()
}

/// Build a problem report message
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


pub fn get_thread_id(msg: &Message) -> Option<String> {
    msg.thid.clone().or_else(|| Some(msg.id.clone()))
}

/// Extract parent thread ID from incoming message
pub fn get_parent_thread_id(msg: &Message) -> Option<String> {
    msg.pthid.clone().or_else(|| get_thread_id(msg))
}

/// Send a DIDComm response message via ATM
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

    info!("[profile = {}] Response sent successfully", &profile.inner.alias);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_message_id() {
        let id1 = new_message_id();
        let id2 = new_message_id();
        assert_ne!(id1, id2);
        assert!(Uuid::parse_str(&id1).is_ok());
    }

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
    fn test_get_thread_id() {
        let msg = Message::build(
            new_message_id(),
            "test".to_string(),
            serde_json::json!({}),
        )
        .thid("thread-123".to_string())
        .finalize();

        assert_eq!(get_thread_id(&msg), Some("thread-123".to_string()));
    }
}
