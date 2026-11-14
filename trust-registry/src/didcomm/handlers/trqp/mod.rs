//! The legacy read-only `trqp/1.0` DIDComm protocol.
//!
//! Every query gets exactly one reply on the query's thread: the answer
//! (`recognized` / `authorized` explicitly `true` or `false`), or a problem
//! report when the query cannot be answered — `e.p.msg.bad-request` for a body
//! that is not a query, `e.p.msg.internal-error` when the repository fails.

use std::sync::Arc;

use crate::{
    didcomm::{problem_report::ProblemReport, transport},
    domain::{Evaluation, TrustRecord},
    storage::repository::{TrustRecordQuery, TrustRecordRepository, find_either_spelling},
};
use affinidi_tdk::didcomm::Message;
use affinidi_tdk::messaging::messages::compat::UnpackMetadata;
use async_trait::async_trait;
use chrono::{DateTime, SecondsFormat, Utc};
use serde_json::{Value, json};
use tracing::{error, warn};

use crate::didcomm::handlers::{HandlerContext, ProtocolHandler};

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
    fn handles(&self, message_type: &str) -> bool {
        message_type == QUERY_AUTHORIZATION_MESSAGE_TYPE
            || message_type == QUERY_RECOGNITION_MESSAGE_TYPE
    }

    async fn handle(
        &self,
        ctx: &Arc<HandlerContext>,
        message: Message,
        _meta: UnpackMetadata,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let is_authorization = message.typ == QUERY_AUTHORIZATION_MESSAGE_TYPE;
        let sent = match answer(
            self.repository.as_ref(),
            is_authorization,
            message.body,
            Utc::now(),
        )
        .await
        {
            Ok(body) => {
                let response_type = format!("{}/response", message.typ);
                transport::send_reply(ctx, &response_type, body, ctx.thid.clone()).await
            }
            Err(report) => {
                warn!(
                    code = %report.code,
                    from = %ctx.authenticated_sender,
                    "[profile = {}] trqp/1.0 query not answered: {}",
                    ctx.profile.inner.alias,
                    report.comment
                );
                transport::send_problem_report(ctx, &report).await
            }
        };
        // The query is answered (or could not be) either way; a reply that did
        // not go out is logged, not retried by redelivering the query.
        if let Err(e) = sent {
            error!(
                "[profile = {}] Failed to send trqp/1.0 reply to {}: {e}",
                ctx.profile.inner.alias, ctx.authenticated_sender
            );
        }
        Ok(())
    }
}

/// The reply body for a `trqp/1.0` query, or the problem report to send
/// instead.
///
/// The record is judged at the registry's clock (this protocol carries no
/// `context.time`); outside its validity window it answers `false`. An
/// unknown record also answers `false`, explicitly, with the queried
/// identifiers echoed — never an empty body.
pub(crate) async fn answer<R>(
    repository: &R,
    is_authorization: bool,
    body: Value,
    requested_at: DateTime<Utc>,
) -> Result<Value, ProblemReport>
where
    R: TrustRecordRepository + ?Sized,
{
    let query: TrustRecordQuery = serde_json::from_value(body)
        .map_err(|e| ProblemReport::bad_request(format!("Invalid trqp/1.0 query: {e}")))?;
    let ids = (
        query.entity_id.as_str().to_string(),
        query.authority_id.as_str().to_string(),
        query.action.as_str().to_string(),
        query.resource.as_str().to_string(),
    );
    let record = find_either_spelling(repository, query).await.map_err(|e| {
        error!("trqp/1.0 repository lookup failed: {e}");
        ProblemReport::internal_error("The registry could not complete the lookup")
    })?;
    let evaluated_at = Utc::now();
    let verb = if is_authorization {
        "authorized"
    } else {
        "recognized"
    };

    let (mut output, message_text) = match record {
        Some(tr) => found_body(tr, is_authorization, verb, evaluated_at)?,
        None => {
            let (entity_id, authority_id, action, resource) = ids;
            let message_text = format!("{entity_id} not {verb} by {authority_id}: no such record");
            let mut body = json!({
                "entity_id": entity_id,
                "authority_id": authority_id,
                "action": action,
                "resource": resource,
            });
            if let Some(obj) = body.as_object_mut() {
                obj.insert(verb.to_string(), json!(false));
            }
            (body, message_text)
        }
    };

    if let Some(obj) = output.as_object_mut() {
        obj.insert(
            "time_requested".to_string(),
            json!(requested_at.to_rfc3339_opts(SecondsFormat::Secs, true)),
        );
        obj.insert(
            "time_evaluated".to_string(),
            json!(evaluated_at.to_rfc3339_opts(SecondsFormat::Secs, true)),
        );
        obj.insert("message".to_string(), json!(message_text));
    }
    Ok(output)
}

fn found_body(
    tr: TrustRecord,
    is_authorization: bool,
    verb: &str,
    evaluated_at: DateTime<Utc>,
) -> Result<(Value, String), ProblemReport> {
    let evaluation = Evaluation::of(Some(&tr), None, evaluated_at);
    let out_of_window = evaluation.out_of_window_reason(&tr);
    let tr = match (&out_of_window, is_authorization) {
        (None, _) => tr,
        (Some(_), true) => tr.with_authorized(false),
        (Some(_), false) => tr.with_recognized(false),
    };
    // Only the flag asked about is returned, as on the HTTP TRQP endpoint.
    let tr = if is_authorization {
        tr.none_recognized()
    } else {
        tr.none_authorized()
    };
    let message_text = match out_of_window {
        Some(reason) => format!(
            "{} not {verb} by {}: {reason}",
            tr.entity_id(),
            tr.authority_id()
        ),
        None if is_authorization => format!(
            "{} authorized to {}+{} by {}",
            tr.entity_id(),
            tr.action(),
            tr.resource(),
            tr.authority_id()
        ),
        None => format!("{} recognized by {}", tr.entity_id(), tr.authority_id()),
    };
    let mut body = serde_json::to_value(&tr).map_err(|e| {
        error!("trqp/1.0 could not serialise a record: {e}");
        ProblemReport::internal_error("The registry could not encode the answer")
    })?;
    // A stored record always carries both flags, but say `false` rather than
    // omit the field if one ever does not: absence is not an answer (R3.4).
    if let Some(obj) = body.as_object_mut() {
        obj.entry(verb.to_string()).or_insert(json!(false));
    }
    Ok((body, message_text))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]
    use super::*;
    use crate::didcomm::problem_report::codes;
    use crate::domain::{Action, AuthorityId, EntityId, RecordType, Resource, TrustRecordBuilder};
    use crate::storage::adapters::local_storage::LocalStorage;

    fn query(entity: &str) -> Value {
        json!({
            "entity_id": entity,
            "authority_id": "did:example:authority",
            "action": "issue",
            "resource": "credential",
        })
    }

    async fn seeded() -> LocalStorage {
        let record = TrustRecordBuilder::new()
            .entity_id(EntityId::new("did:example:known"))
            .authority_id(AuthorityId::new("did:example:authority"))
            .action(Action::new("issue"))
            .resource(Resource::new("credential"))
            .recognized(true)
            .authorized(true)
            .record_type(RecordType::Authorization)
            .build()
            .unwrap();
        LocalStorage::with_records(vec![record]).unwrap()
    }

    /// A did:scid authority with or without its `?src=` locator is one
    /// identity: a record stored under the bare DID answers the located
    /// spelling, and one an earlier release stored located is still found.
    #[tokio::test]
    async fn a_did_scid_locator_is_answered_either_way() {
        const LOCATED: &str = "did:scid:vh:1:abc?src=example.com";
        for authority in [AuthorityId::new(LOCATED), AuthorityId::as_written(LOCATED)] {
            let record = TrustRecordBuilder::new()
                .entity_id(EntityId::new("did:example:known"))
                .authority_id(authority)
                .action(Action::new("issue"))
                .resource(Resource::new("credential"))
                .recognized(true)
                .authorized(true)
                .record_type(RecordType::Authorization)
                .build()
                .unwrap();
            let repo = LocalStorage::with_records(vec![record]).unwrap();
            let mut located = query("did:example:known");
            located["authority_id"] = json!(LOCATED);
            let body = answer(&repo, false, located, Utc::now()).await.unwrap();
            assert_eq!(body["recognized"], true, "{body}");
        }
    }

    #[tokio::test]
    async fn a_known_record_is_recognized() {
        let repo = seeded().await;
        let body = answer(&repo, false, query("did:example:known"), Utc::now())
            .await
            .unwrap();
        assert_eq!(body["recognized"], true);
        assert!(body.get("authorized").is_none(), "{body}");
        assert!(body["message"].is_string());
    }

    #[tokio::test]
    async fn an_unknown_record_is_explicitly_not_recognized() {
        let repo = seeded().await;
        let body = answer(&repo, false, query("did:example:unknown"), Utc::now())
            .await
            .unwrap();
        assert_eq!(body["recognized"], false, "{body}");
        assert_eq!(body["entity_id"], "did:example:unknown");
        assert!(body["message"].as_str().unwrap().contains("not recognized"));
        assert!(body["time_requested"].is_string());
        assert!(body["time_evaluated"].is_string());
    }

    #[tokio::test]
    async fn an_unknown_record_is_explicitly_not_authorized() {
        let repo = seeded().await;
        let body = answer(&repo, true, query("did:example:unknown"), Utc::now())
            .await
            .unwrap();
        assert_eq!(body["authorized"], false, "{body}");
        assert!(body.get("recognized").is_none(), "{body}");
    }

    /// Every message example in `DIDCOMM_PROTOCOLS.md` is valid JSON that
    /// parses as a DIDComm message — so it names its type with `type`, the
    /// wire member — and the documented problem codes are the ones defined.
    #[test]
    fn the_protocol_document_examples_are_real_messages() {
        let doc = include_str!("../../../../../DIDCOMM_PROTOCOLS.md");
        let blocks: Vec<&str> = doc
            .split("```json")
            .skip(1)
            .filter_map(|rest| rest.split("```").next())
            .collect();
        assert!(blocks.len() >= 5, "found {} examples", blocks.len());
        for block in blocks {
            let message: Message = serde_json::from_str(block)
                .unwrap_or_else(|e| panic!("example is not a DIDComm message ({e}):\n{block}"));
            assert!(!message.typ.is_empty());
            if message.typ.ends_with("/response")
                || message.typ == crate::didcomm::problem_report::PROBLEM_REPORT_TYPE
            {
                assert!(message.thid.is_some(), "a reply without a thid:\n{block}");
            }
            if message.typ == crate::didcomm::problem_report::PROBLEM_REPORT_TYPE {
                let code = message.body["code"].as_str().unwrap_or_default();
                assert!(
                    [
                        codes::ERROR_BAD_REQUEST,
                        codes::ERROR_INTERNAL,
                        codes::ERROR_NOT_FOUND,
                        codes::ERROR_UNAUTHORIZED,
                        codes::ERROR_CONFLICT
                    ]
                    .contains(&code),
                    "undefined problem code {code}"
                );
            }
        }
        assert!(!doc.contains("\"type_\""));
    }

    #[tokio::test]
    async fn a_body_that_is_not_a_query_is_a_bad_request() {
        let repo = seeded().await;
        let report = answer(&repo, false, json!({"entity": "x"}), Utc::now())
            .await
            .unwrap_err();
        assert_eq!(report.code, codes::ERROR_BAD_REQUEST);
    }
}
