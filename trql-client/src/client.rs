//! The typed query client: builds request documents, delegates the exchange to
//! a [`TrqlTransport`], and owns all document semantics (correlation, error
//! mapping, payload typing) so every binding behaves identically.

use std::sync::Arc;

use chrono::{DateTime, Utc};
use serde::Serialize;
use serde::de::DeserializeOwned;
use serde_json::Value;
use trust_tasks_rs::{ErrorPayload, Payload, TrustTask};

use crate::error::TrqlError;
use crate::payloads::{
    AuthorizationRequest, AuthorizationResponse, RecognitionRequest, RecognitionResponse,
};
use crate::transport::TrqlTransport;

/// Slug of the framework's reserved error document type.
const ERROR_SLUG: &str = "trust-task-error";

/// The TRQP 4-tuple members, named identically on requests and responses.
///
/// Both `registry/authorization/0.1` and `registry/recognition/0.1` require all
/// four on the response, verbatim from the request, which is what makes an echo
/// check possible without knowing which query is in flight.
const TRQP_TUPLE: [&str; 4] = ["entity_id", "authority_id", "action", "resource"];

/// The TRQP 4-tuple every registry query is keyed on, plus the optional
/// evaluation context.
#[derive(Debug, Clone)]
pub struct TrqpQuery {
    /// DID of the entity whose trust is being checked.
    pub entity_id: String,
    /// DID of the governing authority.
    pub authority_id: String,
    /// The action being checked (e.g. `issue`, `git.commit.sign`).
    pub action: String,
    /// The resource the action applies to.
    pub resource: String,
    /// Evaluate as of this instant instead of "now", when set.
    pub time: Option<DateTime<Utc>>,
    /// Authority-defined record-location hint.
    pub locator: Option<String>,
}

impl TrqpQuery {
    /// A query over the TRQP 4-tuple, evaluated at the registry's current time.
    pub fn new(
        entity_id: impl Into<String>,
        authority_id: impl Into<String>,
        action: impl Into<String>,
        resource: impl Into<String>,
    ) -> Self {
        Self {
            entity_id: entity_id.into(),
            authority_id: authority_id.into(),
            action: action.into(),
            resource: resource.into(),
            time: None,
            locator: None,
        }
    }

    /// Request evaluation as of `time` instead of the registry's current time.
    pub fn at(mut self, time: DateTime<Utc>) -> Self {
        self.time = Some(time);
        self
    }

    /// Attach an authority-defined locator hint.
    pub fn locator(mut self, locator: impl Into<String>) -> Self {
        self.locator = Some(locator.into());
        self
    }

    fn has_context(&self) -> bool {
        self.time.is_some() || self.locator.is_some()
    }
}

/// Transport-agnostic Trust Registry query client.
///
/// Holds one [`TrqlTransport`] and the registry's DID (the `recipient` stamped
/// on every request — the registry rejects documents addressed to anyone
/// else). Swapping HTTPS for DIDComm or TSP changes only the transport handed
/// to [`TrqlClient::new`].
pub struct TrqlClient {
    transport: Arc<dyn TrqlTransport>,
    registry_did: String,
    client_did: Option<String>,
    referred_by: Option<String>,
}

impl TrqlClient {
    /// A client that queries the registry identified by `registry_did` over
    /// `transport`.
    pub fn new(transport: Arc<dyn TrqlTransport>, registry_did: impl Into<String>) -> Self {
        Self {
            transport,
            registry_did: registry_did.into(),
            client_did: None,
            referred_by: None,
        }
    }

    /// Set the in-band `issuer` on outbound documents. Optional over HTTPS
    /// (the registry treats queries as anonymous reads); DIDComm and TSP
    /// authenticate the sender at the transport layer regardless.
    pub fn with_client_did(mut self, did: impl Into<String>) -> Self {
        self.client_did = Some(did.into());
        self
    }

    /// Record that this client reached the registry by following a
    /// [`crate::registry_referral`] in `origin_did`'s document, and hold every
    /// answer to that provenance.
    ///
    /// This is step 5 of `DID_SERVICE_DISCOVERY.md` §4 — *closing the loop* —
    /// made structural instead of advisory. With it set, an answer whose
    /// `authority_id` is anything other than `origin_did` is rejected as
    /// [`TrqlError::ReferralNotClosed`] rather than returned.
    ///
    /// A referral is a self-assertion: anyone can publish a DID document
    /// naming any registry, so a followed referral establishes *where to ask*
    /// and nothing about the answer. Authority flows registry → subject, and
    /// only the registry answering for `origin_did` completes that direction.
    ///
    /// ```rust,ignore
    /// let mut doc = resolve(vtc_did).await?;
    /// let client = match registry_referral(&doc) {
    ///     Some(registry) => {
    ///         doc = resolve(&registry).await?;              // one hop
    ///         TrqlClient::new(transport, registry).referred_by(vtc_did)
    ///     }
    ///     None => TrqlClient::new(transport, registry_did),
    /// };
    /// ```
    pub fn referred_by(mut self, origin_did: impl Into<String>) -> Self {
        self.referred_by = Some(origin_did.into());
        self
    }

    /// Ask whether `entity` is authorized by `authority` for `action` on
    /// `resource` (`registry/authorization/0.1`).
    ///
    /// A registry with no matching record answers `authorized: false` — absence
    /// is a denial, not an error.
    pub async fn authorization(
        &self,
        query: TrqpQuery,
    ) -> Result<AuthorizationResponse, TrqlError> {
        // The generated payload types are `#[non_exhaustive]` from
        // trust-tasks 0.17 on, so they are built through their builders.
        let context: Option<crate::payloads::AuthorizationQueryContext> = query
            .has_context()
            .then(|| {
                crate::payloads::AuthorizationQueryContext::builder()
                    .time(query.time)
                    .locator(query.locator.clone())
                    .extra(std::collections::HashMap::new())
                    .try_into()
            })
            .transpose()
            .map_err(|e| TrqlError::Contract(format!("query context did not build: {e}")))?;
        let payload: AuthorizationRequest = AuthorizationRequest::builder()
            .entity_id(query.entity_id.clone())
            .authority_id(query.authority_id.clone())
            .action(query.action.clone())
            .resource(query.resource.clone())
            .context(context)
            .try_into()
            .map_err(|e| TrqlError::Contract(format!("request payload did not build: {e}")))?;
        self.send_query(payload).await
    }

    /// Ask whether `entity` is recognized by `authority` for `action` on
    /// `resource` (`registry/recognition/0.1`).
    pub async fn recognition(&self, query: TrqpQuery) -> Result<RecognitionResponse, TrqlError> {
        // The generated payload types are `#[non_exhaustive]` from
        // trust-tasks 0.17 on, so they are built through their builders.
        let context: Option<crate::payloads::RecognitionQueryContext> = query
            .has_context()
            .then(|| {
                crate::payloads::RecognitionQueryContext::builder()
                    .time(query.time)
                    .locator(query.locator.clone())
                    .extra(std::collections::HashMap::new())
                    .try_into()
            })
            .transpose()
            .map_err(|e| TrqlError::Contract(format!("query context did not build: {e}")))?;
        let payload: RecognitionRequest = RecognitionRequest::builder()
            .entity_id(query.entity_id.clone())
            .authority_id(query.authority_id.clone())
            .action(query.action.clone())
            .resource(query.resource.clone())
            .context(context)
            .try_into()
            .map_err(|e| TrqlError::Contract(format!("request payload did not build: {e}")))?;
        self.send_query(payload).await
    }

    /// Build the request document for `payload`, run one exchange, and
    /// validate the reply: correlated (`threadId` == request `id`), then
    /// either the matching `#response` document or a `trust-task-error`
    /// mapped to [`TrqlError::Rejected`]. A `#response` must additionally
    /// answer the tuple that was asked, and close any referral this client was
    /// built with.
    async fn send_query<Req, Resp>(&self, payload: Req) -> Result<Resp, TrqlError>
    where
        Req: Payload + Serialize,
        Resp: DeserializeOwned,
    {
        let body = serde_json::to_value(&payload)
            .map_err(|e| TrqlError::Contract(format!("request payload did not serialize: {e}")))?;
        // Capture the tuple before `body` is moved into the request document;
        // the reply is checked against what we actually put on the wire.
        let asked = TRQP_TUPLE.map(|field| body.get(field).cloned().unwrap_or(Value::Null));
        let id = new_task_id();
        let mut request = TrustTask::new(id.clone(), Req::type_uri(), body);
        request.recipient = Some(self.registry_did.clone());
        request.issuer = self.client_did.clone();
        request.issued_at = Some(Utc::now());
        let request_slug = request.type_uri.slug().to_string();

        let reply = self.transport.exchange(request).await?;

        // Correlation is checked, never assumed: an uncorrelated document is
        // someone else's reply and must not be interpreted as ours.
        if reply.thread_id.as_deref() != Some(id.as_str()) {
            return Err(TrqlError::Contract(format!(
                "uncorrelated reply: threadId {:?} does not match request id {id}",
                reply.thread_id
            )));
        }

        if reply.type_uri.slug() == ERROR_SLUG {
            let error: ErrorPayload = serde_json::from_value(reply.payload).map_err(|e| {
                TrqlError::Contract(format!("trust-task-error payload did not parse: {e}"))
            })?;
            return Err(TrqlError::Rejected {
                code: error.code,
                retryable: error.retryable,
                retry_after: error.retry_after,
                message: error.message,
            });
        }

        if !(reply.type_uri.is_response() && reply.type_uri.slug() == request_slug) {
            return Err(TrqlError::Contract(format!(
                "unexpected reply type `{}` to a `{request_slug}` request",
                reply.type_uri
            )));
        }

        self.check_answers_our_question(&asked, &reply.payload)?;

        serde_json::from_value(reply.payload)
            .map_err(|e| TrqlError::Contract(format!("response payload did not parse: {e}")))
    }

    /// Reject a reply that answers a different question than the one asked, or
    /// that fails to close the referral this client followed.
    ///
    /// Correlation (`threadId`) proves a reply belongs to our exchange but not
    /// what it is an answer *about*. TRQP responses echo the queried tuple
    /// precisely so the asker can tell; nothing checked that echo before, so a
    /// registry — or anything able to shape its reply — could substitute the
    /// subject of an authorization decision and be believed.
    ///
    /// A field the reply omits is *not* treated as a mismatch here: all four
    /// members are required by the response schema, so absence fails in the
    /// deserialization immediately below. That keeps a malformed payload
    /// reported as a contract violation rather than as a substituted answer,
    /// and either way the query fails closed.
    fn check_answers_our_question(
        &self,
        asked: &[Value; TRQP_TUPLE.len()],
        answered: &Value,
    ) -> Result<(), TrqlError> {
        for (&field, asked) in TRQP_TUPLE.iter().zip(asked) {
            let Some(answered) = answered.get(field) else {
                continue;
            };
            if answered != asked {
                return Err(TrqlError::AnswerMismatch {
                    field,
                    asked: render(asked),
                    answered: render(answered),
                });
            }
        }

        // Closing the loop (DID_SERVICE_DISCOVERY.md §4 step 5). The echo check
        // above proves the registry answered the authority we named; this
        // proves the authority we named is the one that referred us here. A
        // caller that follows a referral and then asks about some other
        // authority has learned nothing about the referral.
        if let Some(origin) = self.referred_by.as_deref() {
            let answered = answered.get("authority_id").and_then(Value::as_str);
            if answered != Some(origin) {
                return Err(TrqlError::ReferralNotClosed {
                    origin: origin.to_string(),
                    answered: answered.unwrap_or("<absent>").to_string(),
                });
            }
        }

        Ok(())
    }
}

/// Render a tuple member for an error message.
///
/// These are strings on the wire, so the common case prints bare; anything
/// else prints as the JSON it actually was, which is the detail an operator
/// needs when a registry answers with the wrong shape rather than the wrong
/// value.
fn render(value: &Value) -> String {
    match value.as_str() {
        Some(s) => s.to_string(),
        None => value.to_string(),
    }
}

/// A fresh `urn:uuid:` document id.
fn new_task_id() -> String {
    format!("urn:uuid:{}", uuid_v4())
}

#[cfg(any(feature = "didcomm", feature = "tsp"))]
fn uuid_v4() -> String {
    uuid::Uuid::new_v4().to_string()
}

// Without the mediator transports the crate has no uuid dependency; derive the
// id from entropy the std library already gives us. Uniqueness only needs to
// hold within this process's in-flight queries.
#[cfg(not(any(feature = "didcomm", feature = "tsp")))]
fn uuid_v4() -> String {
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{SystemTime, UNIX_EPOCH};
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    format!("{nanos:032x}-{n:016x}")
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;
    use trust_tasks_rs::RejectReason;

    /// A transport that answers every request with a canned closure.
    struct MockTransport<F>(F)
    where
        F: Fn(TrustTask<Value>) -> Result<TrustTask<Value>, TrqlError> + Send + Sync;

    #[async_trait::async_trait]
    impl<F> TrqlTransport for MockTransport<F>
    where
        F: Fn(TrustTask<Value>) -> Result<TrustTask<Value>, TrqlError> + Send + Sync,
    {
        fn kind(&self) -> crate::TransportKind {
            crate::TransportKind::Https
        }

        async fn exchange(&self, request: TrustTask<Value>) -> Result<TrustTask<Value>, TrqlError> {
            (self.0)(request)
        }
    }

    fn client_over<F>(f: F) -> TrqlClient
    where
        F: Fn(TrustTask<Value>) -> Result<TrustTask<Value>, TrqlError> + Send + Sync + 'static,
    {
        TrqlClient::new(Arc::new(MockTransport(f)), "did:example:registry")
    }

    fn authorized_response(request: &TrustTask<Value>, authorized: bool) -> TrustTask<Value> {
        let payload = serde_json::json!({
            "entity_id": request.payload["entity_id"],
            "authority_id": request.payload["authority_id"],
            "action": request.payload["action"],
            "resource": request.payload["resource"],
            "authorized": authorized,
            "time_evaluated": "2026-07-16T00:00:00Z",
        });
        request.respond_with("urn:uuid:reply".to_string(), payload)
    }

    fn query() -> TrqpQuery {
        TrqpQuery::new("did:example:e", "did:example:a", "issue", "vc")
    }

    #[tokio::test]
    async fn authorization_round_trip_stamps_recipient_and_parses_reply() {
        let client = client_over(|req| {
            assert_eq!(req.recipient.as_deref(), Some("did:example:registry"));
            assert!(req.issued_at.is_some());
            assert_eq!(req.type_uri.slug(), "registry/authorization");
            Ok(authorized_response(&req, true))
        });
        let response = client.authorization(query()).await.unwrap();
        assert!(response.authorized);
        assert_eq!(response.entity_id, "did:example:e");
    }

    #[tokio::test]
    async fn uncorrelated_reply_is_a_contract_error() {
        let client = client_over(|req| {
            let mut reply = authorized_response(&req, true);
            reply.thread_id = Some("urn:uuid:someone-else".to_string());
            Ok(reply)
        });
        let err = client.authorization(query()).await.unwrap_err();
        assert!(matches!(err, TrqlError::Contract(_)), "got: {err}");
        assert!(!err.is_retryable());
    }

    #[tokio::test]
    async fn error_document_maps_to_rejected_with_code() {
        let client = client_over(|req| {
            let error_doc = req.reject_with(
                "urn:uuid:err".to_string(),
                RejectReason::PermissionDenied {
                    reason: "not allowed".to_string(),
                },
            );
            // The seam carries untyped documents; reserialize like a wire hop.
            let as_value = serde_json::to_value(&error_doc).unwrap();
            Ok(serde_json::from_value(as_value).unwrap())
        });
        let err = client.authorization(query()).await.unwrap_err();
        match err {
            TrqlError::Rejected { retryable, .. } => assert!(!retryable),
            other => panic!("expected Rejected, got {other}"),
        }
    }

    #[tokio::test]
    async fn wrong_response_type_is_a_contract_error() {
        let client = client_over(|req| {
            let mut reply = authorized_response(&req, true);
            reply.type_uri = "https://trusttasks.org/spec/registry/recognition/0.1#response"
                .parse()
                .unwrap();
            Ok(reply)
        });
        let err = client.authorization(query()).await.unwrap_err();
        assert!(matches!(err, TrqlError::Contract(_)), "got: {err}");
    }

    #[tokio::test]
    async fn malformed_response_payload_is_a_contract_error_not_transport() {
        let client = client_over(|req| {
            // `authorized` missing: the strict payload must fail to parse.
            let payload = serde_json::json!({ "unexpected": true });
            Ok(req.respond_with("urn:uuid:reply".to_string(), payload))
        });
        let err = client.authorization(query()).await.unwrap_err();
        assert!(matches!(err, TrqlError::Contract(_)), "got: {err}");
        assert!(!err.is_retryable());
    }

    #[tokio::test]
    async fn recognition_parses_recognized_flag() {
        let client = client_over(|req| {
            let payload = serde_json::json!({
                "entity_id": req.payload["entity_id"],
                "authority_id": req.payload["authority_id"],
                "action": req.payload["action"],
                "resource": req.payload["resource"],
                "recognized": false,
                "time_evaluated": "2026-07-16T00:00:00Z",
            });
            Ok(req.respond_with("urn:uuid:reply".to_string(), payload))
        });
        let response = client.recognition(query()).await.unwrap();
        assert!(!response.recognized, "absence of trust reads as false");
    }

    #[tokio::test]
    async fn query_context_is_sent_when_time_is_set() {
        let at = "2026-01-01T00:00:00Z".parse().unwrap();
        let client = client_over(|req| {
            assert_eq!(
                req.payload["context"]["time"], "2026-01-01T00:00:00Z",
                "context.time must be carried on the wire"
            );
            Ok(authorized_response(&req, true))
        });
        client.authorization(query().at(at)).await.unwrap();
    }

    // --- answering the question that was asked ------------------------------

    /// An otherwise well-formed, correctly correlated answer with one tuple
    /// member rewritten.
    fn answer_substituting(
        request: &TrustTask<Value>,
        field: &str,
        value: &str,
    ) -> TrustTask<Value> {
        let mut reply = authorized_response(request, true);
        reply.payload[field] = Value::String(value.to_string());
        reply
    }

    #[tokio::test]
    async fn answer_for_a_different_authority_is_rejected() {
        let client = client_over(|req| {
            Ok(answer_substituting(
                &req,
                "authority_id",
                "did:example:other-authority",
            ))
        });
        let err = client.authorization(query()).await.unwrap_err();
        match err {
            TrqlError::AnswerMismatch {
                field,
                ref asked,
                ref answered,
            } => {
                assert_eq!(field, "authority_id");
                assert_eq!(asked, "did:example:a");
                assert_eq!(answered, "did:example:other-authority");
            }
            other => panic!("expected AnswerMismatch, got {other}"),
        }
        assert!(!err.is_retryable(), "a substituted answer is not transient");
    }

    #[tokio::test]
    async fn answer_for_a_different_entity_is_rejected() {
        let client = client_over(|req| {
            Ok(answer_substituting(
                &req,
                "entity_id",
                "did:example:someone-else",
            ))
        });
        let err = client.authorization(query()).await.unwrap_err();
        assert!(
            matches!(
                err,
                TrqlError::AnswerMismatch {
                    field: "entity_id",
                    ..
                }
            ),
            "got: {err}"
        );
    }

    #[tokio::test]
    async fn answer_for_a_different_action_or_resource_is_rejected() {
        for (field, value) in [("action", "revoke"), ("resource", "some-other-repo")] {
            let client = client_over(move |req| Ok(answer_substituting(&req, field, value)));
            let err = client.authorization(query()).await.unwrap_err();
            assert!(
                matches!(err, TrqlError::AnswerMismatch { field: f, .. } if f == field),
                "substituting {field} was not caught: {err}"
            );
        }
    }

    /// A denial is the answer an attacker would most like to see substituted
    /// in the other direction, so the check must not be limited to grants.
    #[tokio::test]
    async fn a_denial_must_also_answer_the_question_asked() {
        let client = client_over(|req| {
            let mut reply = authorized_response(&req, false);
            reply.payload["authority_id"] = Value::String("did:example:other".to_string());
            Ok(reply)
        });
        let err = client.authorization(query()).await.unwrap_err();
        assert!(
            matches!(err, TrqlError::AnswerMismatch { .. }),
            "got: {err}"
        );
    }

    #[tokio::test]
    async fn recognition_answers_are_checked_too() {
        let client = client_over(|req| {
            let payload = serde_json::json!({
                "entity_id": req.payload["entity_id"],
                "authority_id": "did:example:other",
                "action": req.payload["action"],
                "resource": req.payload["resource"],
                "recognized": true,
                "time_evaluated": "2026-07-16T00:00:00Z",
            });
            Ok(req.respond_with("urn:uuid:reply".to_string(), payload))
        });
        let err = client.recognition(query()).await.unwrap_err();
        assert!(
            matches!(err, TrqlError::AnswerMismatch { .. }),
            "got: {err}"
        );
    }

    /// An omitted tuple member is a malformed payload, not a substituted
    /// answer. It still fails — the response schema requires all four — but it
    /// is reported as the contract violation it is.
    #[tokio::test]
    async fn omitted_tuple_member_is_a_contract_error_not_a_mismatch() {
        let client = client_over(|req| {
            let mut reply = authorized_response(&req, true);
            reply
                .payload
                .as_object_mut()
                .expect("response payload is an object")
                .remove("authority_id");
            Ok(reply)
        });
        let err = client.authorization(query()).await.unwrap_err();
        assert!(matches!(err, TrqlError::Contract(_)), "got: {err}");
    }

    // --- closing the referral loop (DID_SERVICE_DISCOVERY.md §4 step 5) -----

    #[tokio::test]
    async fn referral_closes_when_the_registry_answers_for_the_origin() {
        let client =
            client_over(|req| Ok(authorized_response(&req, true))).referred_by("did:example:a");
        let response = client.authorization(query()).await.unwrap();
        assert!(response.authorized);
    }

    /// The registry echoes our query faithfully — so the tuple check passes —
    /// but we asked about an authority other than the one whose document
    /// referred us here. The referral is left unconfirmed, and an unconfirmed
    /// referral is an unverified redirect.
    #[tokio::test]
    async fn referral_that_the_answer_does_not_confirm_is_rejected() {
        let client = client_over(|req| Ok(authorized_response(&req, true)))
            .referred_by("did:example:referring-vtc");
        let err = client.authorization(query()).await.unwrap_err();
        match err {
            TrqlError::ReferralNotClosed {
                ref origin,
                ref answered,
            } => {
                assert_eq!(origin, "did:example:referring-vtc");
                assert_eq!(answered, "did:example:a");
            }
            other => panic!("expected ReferralNotClosed, got {other}"),
        }
        assert!(!err.is_retryable());
    }

    /// Without `referred_by` nothing changes: the endpoint path (a registry
    /// describing its own surface) never had a referral to close.
    #[tokio::test]
    async fn endpoint_path_is_unaffected_by_the_referral_check() {
        let client = client_over(|req| Ok(authorized_response(&req, true)));
        assert!(client.authorization(query()).await.unwrap().authorized);
    }
}
