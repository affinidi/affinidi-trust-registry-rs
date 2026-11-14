//! Sending a reply over DIDComm: the one pack-and-forward path every protocol
//! handler uses.
//!
//! A reply goes only to the sender the inbound unpack authenticated
//! ([`HandlerContext::authenticated_sender`]); there is deliberately no way to
//! address it to anyone else from here.

use affinidi_tdk::didcomm::Message;
use serde_json::Value;
use tracing::debug;

use crate::didcomm::{
    error::DIDCommError,
    handlers::HandlerContext,
    new_message_id,
    problem_report::{PROBLEM_REPORT_TYPE, ProblemReport},
};

/// Build a reply from `from` to `to`, threaded on `thid` (a new thread when
/// there is none).
pub fn build_reply(
    type_: impl Into<String>,
    from: impl Into<String>,
    to: impl Into<String>,
    body: Value,
    thid: Option<String>,
) -> Message {
    Message::build(new_message_id(), type_.into(), body)
        .from(from.into())
        .to(to.into())
        .thid(thid.unwrap_or_else(new_message_id))
        .finalize()
}

/// Build a problem report answering the request on thread `thid`.
///
/// The report is sent on the request's own thread, and `pthid` names the same
/// thread as the one the problem occurred in (DIDComm v2 §"Problem Reports"),
/// so a client waiting on its request's thread receives it.
pub fn build_problem_report(
    from: impl Into<String>,
    to: impl Into<String>,
    report: &ProblemReport,
    thid: Option<String>,
) -> Message {
    let mut message = build_reply(PROBLEM_REPORT_TYPE, from, to, report.to_body(), thid);
    message.pthid = message.thid.clone();
    message
}

/// Pack `message` for the authenticated sender and forward it through the
/// registry's mediator.
pub(crate) async fn send(ctx: &HandlerContext, message: &Message) -> Result<(), DIDCommError> {
    let mediator = ctx
        .profile
        .to_tdk_profile()
        .mediator
        .clone()
        .ok_or(DIDCommError::MissingMediator)?;
    let (packed, _) = ctx
        .atm
        .pack_encrypted(
            message,
            &ctx.authenticated_sender,
            Some(&ctx.profile.inner.did),
            Some(&ctx.profile.inner.did),
        )
        .await?;
    ctx.atm
        .forward_and_send_message(
            &ctx.profile,
            false,
            &packed,
            Some(&message.id),
            &mediator,
            &ctx.authenticated_sender,
            None,
            None,
            false,
        )
        .await?;
    debug!(
        message_type = %message.typ,
        to = %ctx.authenticated_sender,
        "[profile = {}] reply sent",
        ctx.profile.inner.alias
    );
    Ok(())
}

/// Send a reply of `type_` with `body` to the authenticated sender.
pub(crate) async fn send_reply(
    ctx: &HandlerContext,
    type_: &str,
    body: Value,
    thid: Option<String>,
) -> Result<(), DIDCommError> {
    let message = build_reply(
        type_,
        ctx.profile.inner.did.clone(),
        ctx.authenticated_sender.clone(),
        body,
        thid,
    );
    send(ctx, &message).await
}

/// Answer the request on `ctx.thid` with a problem report.
pub(crate) async fn send_problem_report(
    ctx: &HandlerContext,
    report: &ProblemReport,
) -> Result<(), DIDCommError> {
    let message = build_problem_report(
        ctx.profile.inner.did.clone(),
        ctx.authenticated_sender.clone(),
        report,
        ctx.thid.clone(),
    );
    send(ctx, &message).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_reply_is_threaded_on_the_request() {
        let msg = build_reply(
            "https://example.com/test",
            "did:example:alice",
            "did:example:bob",
            serde_json::json!({"result": "ok"}),
            Some("thread-123".to_string()),
        );

        assert_eq!(msg.typ, "https://example.com/test");
        assert_eq!(msg.from.as_deref(), Some("did:example:alice"));
        assert_eq!(msg.to, Some(vec!["did:example:bob".to_string()]));
        assert_eq!(msg.thid.as_deref(), Some("thread-123"));
    }

    #[test]
    fn a_problem_report_is_on_the_request_thread() {
        let report = ProblemReport::bad_request("Invalid query");
        let msg = build_problem_report(
            "did:example:alice",
            "did:example:bob",
            &report,
            Some("thread-123".to_string()),
        );
        assert_eq!(msg.typ, PROBLEM_REPORT_TYPE);
        assert_eq!(msg.to, Some(vec!["did:example:bob".to_string()]));
        assert_eq!(msg.thid.as_deref(), Some("thread-123"));
        assert_eq!(msg.pthid.as_deref(), Some("thread-123"));
        assert_eq!(msg.body["code"], "e.p.msg.bad-request");
    }
}
