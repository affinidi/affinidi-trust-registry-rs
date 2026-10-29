//! The typed query client: builds request documents, delegates the exchange to
//! a [`TrqlTransport`], and owns all document semantics (correlation, error
//! mapping, payload typing) so every binding behaves identically.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use chrono::{DateTime, Utc};
use serde::Serialize;
use serde::de::DeserializeOwned;
use serde_json::Value;
use trust_tasks_rs::{ErrorPayload, Payload, StandardCode, TrustTask};

use crate::answer::{AuthorizationAnswer, RecognitionAnswer, SpecVersion};
use crate::error::TrqlError;
use crate::payloads::{v0_1, v0_2};
use crate::transport::TrqlTransport;

/// Slug of the framework's reserved error document type.
const ERROR_SLUG: &str = "trust-task-error";

/// Map a generated-payload builder failure onto [`TrqlError::Config`].
///
/// The generated request types are `#[non_exhaustive]`, so they are assembled
/// through their builders, which validate at `try_into()`. Every field this
/// client sets is a required one it always supplies, so a failure here means
/// the client and the spec crate disagree about the payload shape — a build-
/// time contract problem, not anything the peer did.
fn payload_build_error(err: impl std::fmt::Display) -> TrqlError {
    TrqlError::Config(format!("could not build query payload: {err}"))
}

/// The four tuple members, as one version spells them on both its request and
/// its response.
///
/// Every `registry/authorization` and `registry/recognition` version requires
/// all four on the response, verbatim from the request, which is what makes an
/// echo check possible without knowing which query is in flight. The authority
/// is always the second.
type Tuple = [&'static str; 4];
const TUPLE_V0_1: Tuple = ["entity_id", "authority_id", "action", "resource"];
const TUPLE_V0_2: Tuple = ["entityId", "authorityId", "action", "resource"];

/// Whether `err` is a registry saying it does not speak this version of a task
/// it does know: the SPEC §8.3 signal to downgrade.
fn is_unsupported_version(err: &TrqlError) -> bool {
    matches!(err, TrqlError::Rejected { code, .. } if *code == StandardCode::UnsupportedVersion.into())
}

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
    /// Set once this registry has answered a 0.2 query with
    /// `unsupportedVersion`, so later queries go straight to 0.1 rather than
    /// paying the extra round trip each time. A client is for one registry;
    /// one that upgrades is still answered correctly at 0.1.
    v0_1_only: AtomicBool,
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
            v0_1_only: AtomicBool::new(false),
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
    /// `resource`.
    ///
    /// Sent as `registry/authorization/0.2`; a registry that answers
    /// `unsupportedVersion` is asked again at 0.1, and remembered. A registry
    /// with no matching record answers `authorized: false`: absence is a
    /// denial, not an error.
    pub async fn authorization(&self, query: TrqpQuery) -> Result<AuthorizationAnswer, TrqlError> {
        if !self.v0_1_only.load(Ordering::Relaxed) {
            match self.authorization_v0_2(&query).await {
                Err(e) if is_unsupported_version(&e) => {
                    self.v0_1_only.store(true, Ordering::Relaxed)
                }
                answered => return answered,
            }
        }
        self.authorization_v0_1(&query).await
    }

    /// Ask whether `entity` is recognized by `authority` for `action` on
    /// `resource`. Versions as for [`authorization`](Self::authorization).
    pub async fn recognition(&self, query: TrqpQuery) -> Result<RecognitionAnswer, TrqlError> {
        if !self.v0_1_only.load(Ordering::Relaxed) {
            match self.recognition_v0_2(&query).await {
                Err(e) if is_unsupported_version(&e) => {
                    self.v0_1_only.store(true, Ordering::Relaxed)
                }
                answered => return answered,
            }
        }
        self.recognition_v0_1(&query).await
    }

    async fn authorization_v0_2(
        &self,
        query: &TrqpQuery,
    ) -> Result<AuthorizationAnswer, TrqlError> {
        let context: Option<v0_2::AuthorizationQueryContext> = query
            .has_context()
            .then(|| {
                v0_2::AuthorizationQueryContext::builder()
                    .time(query.time)
                    .locator(query.locator.clone())
                    .extra(std::collections::HashMap::new())
                    .try_into()
            })
            .transpose()
            .map_err(payload_build_error)?;
        let payload: v0_2::AuthorizationRequest = v0_2::AuthorizationRequest::builder()
            .entity_id(query.entity_id.clone())
            .authority_id(query.authority_id.clone())
            .action(query.action.clone())
            .resource(query.resource.clone())
            .context(context)
            .try_into()
            .map_err(payload_build_error)?;
        let r: v0_2::AuthorizationResponse = self.send_query(payload, &TUPLE_V0_2).await?;
        Ok(AuthorizationAnswer {
            entity_id: r.entity_id,
            authority_id: r.authority_id,
            action: r.action,
            resource: r.resource,
            authorized: r.authorized,
            evaluated_at: r.evaluated_at,
            as_of: r.as_of,
            message: r.message.map(|m| m.to_string()),
            version: SpecVersion::V0_2,
        })
    }

    async fn authorization_v0_1(
        &self,
        query: &TrqpQuery,
    ) -> Result<AuthorizationAnswer, TrqlError> {
        let context: Option<v0_1::AuthorizationQueryContext> = query
            .has_context()
            .then(|| {
                v0_1::AuthorizationQueryContext::builder()
                    .time(query.time)
                    .locator(query.locator.clone())
                    .extra(std::collections::HashMap::new())
                    .try_into()
            })
            .transpose()
            .map_err(payload_build_error)?;
        let payload: v0_1::AuthorizationRequest = v0_1::AuthorizationRequest::builder()
            .entity_id(query.entity_id.clone())
            .authority_id(query.authority_id.clone())
            .action(query.action.clone())
            .resource(query.resource.clone())
            .context(context)
            .try_into()
            .map_err(payload_build_error)?;
        let r: v0_1::AuthorizationResponse = self.send_query(payload, &TUPLE_V0_1).await?;
        Ok(AuthorizationAnswer {
            entity_id: r.entity_id,
            authority_id: r.authority_id,
            action: r.action,
            resource: r.resource,
            authorized: r.authorized,
            evaluated_at: r.time_evaluated,
            as_of: r.time_requested,
            message: r.message.map(|m| m.to_string()),
            version: SpecVersion::V0_1,
        })
    }

    async fn recognition_v0_2(&self, query: &TrqpQuery) -> Result<RecognitionAnswer, TrqlError> {
        let context: Option<v0_2::RecognitionQueryContext> = query
            .has_context()
            .then(|| {
                v0_2::RecognitionQueryContext::builder()
                    .time(query.time)
                    .locator(query.locator.clone())
                    .extra(std::collections::HashMap::new())
                    .try_into()
            })
            .transpose()
            .map_err(payload_build_error)?;
        let payload: v0_2::RecognitionRequest = v0_2::RecognitionRequest::builder()
            .entity_id(query.entity_id.clone())
            .authority_id(query.authority_id.clone())
            .action(query.action.clone())
            .resource(query.resource.clone())
            .context(context)
            .try_into()
            .map_err(payload_build_error)?;
        let r: v0_2::RecognitionResponse = self.send_query(payload, &TUPLE_V0_2).await?;
        Ok(RecognitionAnswer {
            entity_id: r.entity_id,
            authority_id: r.authority_id,
            action: r.action,
            resource: r.resource,
            recognized: r.recognized,
            evaluated_at: r.evaluated_at,
            as_of: r.as_of,
            message: r.message.map(|m| m.to_string()),
            version: SpecVersion::V0_2,
        })
    }

    async fn recognition_v0_1(&self, query: &TrqpQuery) -> Result<RecognitionAnswer, TrqlError> {
        let context: Option<v0_1::RecognitionQueryContext> = query
            .has_context()
            .then(|| {
                v0_1::RecognitionQueryContext::builder()
                    .time(query.time)
                    .locator(query.locator.clone())
                    .extra(std::collections::HashMap::new())
                    .try_into()
            })
            .transpose()
            .map_err(payload_build_error)?;
        let payload: v0_1::RecognitionRequest = v0_1::RecognitionRequest::builder()
            .entity_id(query.entity_id.clone())
            .authority_id(query.authority_id.clone())
            .action(query.action.clone())
            .resource(query.resource.clone())
            .context(context)
            .try_into()
            .map_err(payload_build_error)?;
        let r: v0_1::RecognitionResponse = self.send_query(payload, &TUPLE_V0_1).await?;
        Ok(RecognitionAnswer {
            entity_id: r.entity_id,
            authority_id: r.authority_id,
            action: r.action,
            resource: r.resource,
            recognized: r.recognized,
            evaluated_at: r.time_evaluated,
            as_of: r.time_requested,
            message: r.message.map(|m| m.to_string()),
            version: SpecVersion::V0_1,
        })
    }

    /// Build the request document for `payload`, run one exchange, and
    /// validate the reply: correlated (`threadId` == request `id`), then
    /// either the matching `#response` document or a `trust-task-error`
    /// mapped to [`TrqlError::Rejected`]. A `#response` must additionally
    /// answer the tuple that was asked, and close any referral this client was
    /// built with.
    async fn send_query<Req, Resp>(&self, payload: Req, tuple: &Tuple) -> Result<Resp, TrqlError>
    where
        Req: Payload + Serialize,
        Resp: DeserializeOwned,
    {
        let body = serde_json::to_value(&payload)
            .map_err(|e| TrqlError::Contract(format!("request payload did not serialize: {e}")))?;
        // Capture the tuple before `body` is moved into the request document;
        // the reply is checked against what we actually put on the wire.
        let asked = tuple.map(|field| body.get(field).cloned().unwrap_or(Value::Null));
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

        self.check_answers_our_question(tuple, &asked, &reply.payload)?;

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
        tuple: &Tuple,
        asked: &[Value; 4],
        answered: &Value,
    ) -> Result<(), TrqlError> {
        for (&field, asked) in tuple.iter().zip(asked) {
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
            let answered = answered.get(tuple[1]).and_then(Value::as_str);
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
            "entityId": request.payload["entityId"],
            "authorityId": request.payload["authorityId"],
            "action": request.payload["action"],
            "resource": request.payload["resource"],
            "authorized": authorized,
            "evaluatedAt": "2026-07-16T00:00:00Z",
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
                "entityId": req.payload["entityId"],
                "authorityId": req.payload["authorityId"],
                "action": req.payload["action"],
                "resource": req.payload["resource"],
                "recognized": false,
                "evaluatedAt": "2026-07-16T00:00:00Z",
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
                "authorityId",
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
                assert_eq!(field, "authorityId");
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
                "entityId",
                "did:example:someone-else",
            ))
        });
        let err = client.authorization(query()).await.unwrap_err();
        assert!(
            matches!(
                err,
                TrqlError::AnswerMismatch {
                    field: "entityId",
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
            reply.payload["authorityId"] = Value::String("did:example:other".to_string());
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
                "entityId": req.payload["entityId"],
                "authorityId": "did:example:other",
                "action": req.payload["action"],
                "resource": req.payload["resource"],
                "recognized": true,
                "evaluatedAt": "2026-07-16T00:00:00Z",
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
                .remove("authorityId");
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

    // --- version fallback --------------------------------------------------

    /// A registry from before 0.2: rejects 0.2 with `unsupportedVersion` and
    /// answers 0.1 in snake_case. Counts the 0.2 attempts.
    fn pre_0_2_registry(
        attempts_0_2: Arc<std::sync::atomic::AtomicUsize>,
        authority_answered: &'static str,
    ) -> TrqlClient {
        client_over(move |req| {
            if req.type_uri.minor() == 2 {
                attempts_0_2.fetch_add(1, Ordering::Relaxed);
                return Err(TrqlError::Rejected {
                    code: StandardCode::UnsupportedVersion.into(),
                    retryable: false,
                    retry_after: None,
                    message: None,
                });
            }
            let payload = serde_json::json!({
                "entity_id": req.payload["entity_id"],
                "authority_id": if authority_answered.is_empty() {
                    req.payload["authority_id"].clone()
                } else {
                    Value::String(authority_answered.to_string())
                },
                "action": req.payload["action"],
                "resource": req.payload["resource"],
                "authorized": true,
                "time_evaluated": "2026-07-16T00:00:00Z",
            });
            Ok(req.respond_with("urn:uuid:reply".to_string(), payload))
        })
    }

    #[tokio::test]
    async fn a_0_2_registry_is_answered_at_0_2() {
        let client = client_over(|req| {
            assert_eq!(req.type_uri.minor(), 2, "0.2 is asked first");
            assert!(req.payload.get("entityId").is_some());
            Ok(authorized_response(&req, true))
        });
        let answer = client.authorization(query()).await.unwrap();
        assert_eq!(answer.version, SpecVersion::V0_2);
        assert!(answer.authorized);
    }

    #[tokio::test]
    async fn unsupported_version_falls_back_to_0_1_once() {
        let attempts = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let client = pre_0_2_registry(attempts.clone(), "");
        let first = client.authorization(query()).await.unwrap();
        assert_eq!(first.version, SpecVersion::V0_1);
        assert!(first.authorized);
        assert_eq!(first.entity_id, "did:example:e");
        // Remembered: the next query (of either kind) goes straight to 0.1.
        client.authorization(query()).await.unwrap();
        client.recognition(query()).await.ok();
        assert_eq!(attempts.load(Ordering::Relaxed), 1);
    }

    /// Only `unsupportedVersion` means "downgrade". Any other rejection is the
    /// registry's answer, and asking again in an older form must not route
    /// around it.
    #[tokio::test]
    async fn other_rejections_are_not_retried_at_0_1() {
        for code in [
            StandardCode::UnsupportedType,
            StandardCode::PermissionDenied,
        ] {
            let asked_0_1 = Arc::new(AtomicBool::new(false));
            let seen = asked_0_1.clone();
            let client = client_over(move |req| {
                if req.type_uri.minor() == 1 {
                    seen.store(true, Ordering::Relaxed);
                }
                Err(TrqlError::Rejected {
                    code: code.into(),
                    retryable: false,
                    retry_after: None,
                    message: None,
                })
            });
            let err = client.authorization(query()).await.unwrap_err();
            assert!(matches!(err, TrqlError::Rejected { .. }), "{err}");
            assert!(
                !asked_0_1.load(Ordering::Relaxed),
                "{code:?} must not fall back"
            );
        }
    }

    /// The fallback path holds answers to the same checks: here the 0.1
    /// registry answers for another authority.
    #[tokio::test]
    async fn the_0_1_path_still_checks_the_answer() {
        let client = pre_0_2_registry(Arc::default(), "did:example:other");
        match client.authorization(query()).await {
            Err(TrqlError::AnswerMismatch { field, .. }) => assert_eq!(field, "authority_id"),
            other => panic!("expected AnswerMismatch, got {other:?}"),
        }
        let client = pre_0_2_registry(Arc::default(), "").referred_by("did:example:vtc");
        assert!(matches!(
            client.authorization(query()).await,
            Err(TrqlError::ReferralNotClosed { .. })
        ));
    }

    /// Every version this client sends, and the response it reads back,
    /// resolves to a schema generated from `trust-tasks.lock`.
    ///
    /// trust-tasks-rs is built without its prebuilt spec families, so
    /// `trust_tasks_rs::schema_index` does not know these URIs; the client
    /// must not depend on it. This fails if the lock and the versions the
    /// client speaks drift apart, or if a generated type loses its schema.
    #[test]
    fn every_sent_type_uri_resolves_to_a_generated_schema() {
        use crate::payloads::{v0_1, v0_2};

        fn check<Req: Payload, Resp: Payload + DeserializeOwned>() -> String {
            let uri = Req::type_uri().to_string();
            for schema in [Req::PAYLOAD_SCHEMA, Resp::PAYLOAD_SCHEMA] {
                let schema = schema.unwrap_or_else(|| panic!("{uri}: no generated schema"));
                let schema: serde_json::Value =
                    serde_json::from_str(schema).expect("schema is JSON");
                assert!(schema.is_object(), "{uri}: schema is not an object");
            }
            assert!(
                serde_json::from_value::<Resp>(serde_json::json!("not a payload")).is_err(),
                "{uri}: response type accepted a non-object"
            );
            uri
        }

        let mut sent = vec![
            check::<v0_1::AuthorizationRequest, v0_1::AuthorizationResponse>(),
            check::<v0_2::AuthorizationRequest, v0_2::AuthorizationResponse>(),
            check::<v0_1::RecognitionRequest, v0_1::RecognitionResponse>(),
            check::<v0_2::RecognitionRequest, v0_2::RecognitionResponse>(),
        ];
        sent.sort();
        let mut pinned: Vec<String> = include_str!("../trust-tasks.lock")
            .lines()
            .filter_map(|l| l.strip_prefix("type_uri = \""))
            .map(|l| l.trim_end_matches('"').to_string())
            .collect();
        pinned.sort();
        assert_eq!(sent, pinned, "the client sends exactly the locked versions");
    }
}
