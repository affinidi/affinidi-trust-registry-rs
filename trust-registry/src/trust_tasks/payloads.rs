//! Trust Task payload types for the Trust Registry (`registry/*` family).
//!
//! Each type implements [`trust_tasks_rs::Payload`], binding a Rust struct to a
//! versioned Trust Task specification (`https://trusttasks.org/spec/registry/<op>/0.1`).
//!
//! The TRQP query payloads ([`RecognitionRequest`]/[`RecognitionResponse`] and
//! [`AuthorizationRequest`]/[`AuthorizationResponse`]) reuse the **verbatim
//! field names** from the ToIP TRQP v2.0 JSON schemas
//! (`trqp_{recognition,authorization}_{request,response}.schema.json`) so a
//! single Rust type serialises for both the plain HTTP TRQP binding and the
//! Trust Task payload.
//!
//! Payloads are hand-written here; a later change formalises identical
//! slugs/field names as published specs in `dtgwg-trust-tasks-tf`. The
//! `Payload` trait only requires a valid `TYPE_URI` constant, so the two
//! representations stay in lock-step by construction.

use serde::{Deserialize, Serialize};
use trust_tasks_rs::Payload;

use crate::domain::{Action, AuthorityId, EntityId, Resource, TrustRecord};
use crate::storage::repository::TrustRecordQuery;

/// Canonical Type URIs for the `registry/*` Trust Task family.
///
/// Kept as public constants so transport bindings (DIDComm/HTTP/TSP) and the
/// future published specs can reference the exact same strings.
pub mod type_uris {
    /// `registry/recognition/0.1` request.
    pub const RECOGNITION: &str = "https://trusttasks.org/spec/registry/recognition/0.1";
    /// `registry/authorization/0.1` request.
    pub const AUTHORIZATION: &str = "https://trusttasks.org/spec/registry/authorization/0.1";
    /// `registry/record/create/0.1` request.
    pub const RECORD_CREATE: &str = "https://trusttasks.org/spec/registry/record/create/0.1";
    /// `registry/record/update/0.1` request.
    pub const RECORD_UPDATE: &str = "https://trusttasks.org/spec/registry/record/update/0.1";
    /// `registry/record/delete/0.1` request.
    pub const RECORD_DELETE: &str = "https://trusttasks.org/spec/registry/record/delete/0.1";
    /// `registry/record/read/0.1` request.
    pub const RECORD_READ: &str = "https://trusttasks.org/spec/registry/record/read/0.1";
    /// `registry/record/list/0.1` request.
    pub const RECORD_LIST: &str = "https://trusttasks.org/spec/registry/record/list/0.1";
}

/// TRQP query `context` object (SPEC v2.0). All members optional.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct QueryContext {
    /// Server time to evaluate the query at (RFC3339, `Z` offset). Blank = now.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub time: Option<String>,
    /// Optional hint for systems that need extra information to locate records
    /// (authorization queries only, per the TRQP schema).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub locator: Option<String>,
}

/// The four TRQP identifiers shared by every query and record-key payload.
///
/// Field names are verbatim from the TRQP v2.0 request schema.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct QueryTuple {
    /// Entity being tested.
    pub entity_id: String,
    /// Authority being queried.
    pub authority_id: String,
    /// Action under test.
    pub action: String,
    /// Resource under test.
    pub resource: String,
}

impl QueryTuple {
    /// Convert into the repository's [`TrustRecordQuery`].
    pub fn to_query(&self) -> TrustRecordQuery {
        TrustRecordQuery::new(
            EntityId::new(self.entity_id.clone()),
            AuthorityId::new(self.authority_id.clone()),
            Action::new(self.action.clone()),
            Resource::new(self.resource.clone()),
        )
    }
}

// --- TRQP: recognition -------------------------------------------------------

/// `registry/recognition/0.1` request — TRQP recognition query.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecognitionRequest {
    /// The four TRQP identifiers.
    #[serde(flatten)]
    pub query: QueryTuple,
    /// Optional query context.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub context: Option<QueryContext>,
}

impl Payload for RecognitionRequest {
    const TYPE_URI: &'static str = type_uris::RECOGNITION;
}

/// `registry/recognition/0.1#response` — TRQP recognition response.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecognitionResponse {
    /// Echoed TRQP identifiers.
    #[serde(flatten)]
    pub query: QueryTuple,
    /// True if recognised.
    pub recognized: bool,
    /// Server time the query was evaluated at (required by TRQP).
    pub time_evaluated: String,
    /// Server time requested, if any.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub time_requested: Option<String>,
    /// Additional human-readable detail.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

impl Payload for RecognitionResponse {
    const TYPE_URI: &'static str = "https://trusttasks.org/spec/registry/recognition/0.1#response";
}

// --- TRQP: authorization -----------------------------------------------------

/// `registry/authorization/0.1` request — TRQP authorization query.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthorizationRequest {
    /// The four TRQP identifiers.
    #[serde(flatten)]
    pub query: QueryTuple,
    /// Optional query context (may carry `locator`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub context: Option<QueryContext>,
}

impl Payload for AuthorizationRequest {
    const TYPE_URI: &'static str = type_uris::AUTHORIZATION;
}

/// `registry/authorization/0.1#response` — TRQP authorization response.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthorizationResponse {
    /// Echoed TRQP identifiers.
    #[serde(flatten)]
    pub query: QueryTuple,
    /// True if authorised.
    pub authorized: bool,
    /// Server time the query was evaluated at (required by TRQP).
    pub time_evaluated: String,
    /// Server time requested, if any.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub time_requested: Option<String>,
    /// Additional human-readable detail.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

impl Payload for AuthorizationResponse {
    const TYPE_URI: &'static str =
        "https://trusttasks.org/spec/registry/authorization/0.1#response";
}

// --- Record CRUD -------------------------------------------------------------

/// Acknowledgement returned by mutating record operations.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecordAck {
    /// Whether the operation succeeded.
    pub ok: bool,
    /// Optional human-readable detail.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

impl RecordAck {
    /// A bare success acknowledgement.
    pub fn ok() -> Self {
        Self {
            ok: true,
            message: None,
        }
    }
}

/// `registry/record/create/0.1` request. **Proof required** (write).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RecordCreateRequest {
    /// The record to create.
    pub record: TrustRecord,
}

impl Payload for RecordCreateRequest {
    const TYPE_URI: &'static str = type_uris::RECORD_CREATE;
    const IS_PROOF_REQUIRED: bool = true;
}

/// `registry/record/update/0.1` request. **Proof required** (write).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RecordUpdateRequest {
    /// The record to update.
    pub record: TrustRecord,
}

impl Payload for RecordUpdateRequest {
    const TYPE_URI: &'static str = type_uris::RECORD_UPDATE;
    const IS_PROOF_REQUIRED: bool = true;
}

/// `registry/record/delete/0.1` request. **Proof required** (write).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecordDeleteRequest {
    /// The record key to delete.
    #[serde(flatten)]
    pub query: QueryTuple,
}

impl Payload for RecordDeleteRequest {
    const TYPE_URI: &'static str = type_uris::RECORD_DELETE;
    const IS_PROOF_REQUIRED: bool = true;
}

/// `registry/record/read/0.1` request (read).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecordReadRequest {
    /// The record key to read.
    #[serde(flatten)]
    pub query: QueryTuple,
}

impl Payload for RecordReadRequest {
    const TYPE_URI: &'static str = type_uris::RECORD_READ;
}

/// `registry/record/list/0.1` request (read). No parameters.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecordListRequest {}

impl Payload for RecordListRequest {
    const TYPE_URI: &'static str = type_uris::RECORD_LIST;
}

#[cfg(test)]
mod tests {
    use super::*;
    use trust_tasks_rs::Payload;

    #[test]
    fn type_uris_parse_as_valid_type_uris() {
        // `Payload::type_uri()` panics on a malformed TYPE_URI constant, so
        // exercising each one guards against slug typos.
        let _ = RecognitionRequest::type_uri();
        let _ = RecognitionResponse::type_uri();
        let _ = AuthorizationRequest::type_uri();
        let _ = AuthorizationResponse::type_uri();
        let _ = RecordCreateRequest::type_uri();
        let _ = RecordUpdateRequest::type_uri();
        let _ = RecordDeleteRequest::type_uri();
        let _ = RecordReadRequest::type_uri();
        let _ = RecordListRequest::type_uri();
    }

    #[test]
    fn writes_require_proof_reads_do_not() {
        assert!(RecordCreateRequest::IS_PROOF_REQUIRED);
        assert!(RecordUpdateRequest::IS_PROOF_REQUIRED);
        assert!(RecordDeleteRequest::IS_PROOF_REQUIRED);
        assert!(!RecordReadRequest::IS_PROOF_REQUIRED);
        assert!(!RecordListRequest::IS_PROOF_REQUIRED);
        assert!(!RecognitionRequest::IS_PROOF_REQUIRED);
        assert!(!AuthorizationRequest::IS_PROOF_REQUIRED);
    }

    #[test]
    fn recognition_request_uses_verbatim_trqp_field_names() {
        let json = serde_json::json!({
            "entity_id": "did:example:entity",
            "authority_id": "did:example:authority",
            "action": "issue",
            "resource": "vc",
            "context": { "time": "2026-07-06T00:00:00Z" }
        });
        let req: RecognitionRequest = serde_json::from_value(json).expect("parses");
        assert_eq!(req.query.entity_id, "did:example:entity");
        assert_eq!(req.query.action, "issue");
        assert_eq!(
            req.context.and_then(|c| c.time).as_deref(),
            Some("2026-07-06T00:00:00Z")
        );
    }

    #[test]
    fn query_tuple_converts_to_repository_query() {
        let tuple = QueryTuple {
            entity_id: "e".into(),
            authority_id: "a".into(),
            action: "act".into(),
            resource: "res".into(),
        };
        let q = tuple.to_query();
        assert_eq!(q.entity_id.as_str(), "e");
        assert_eq!(q.authority_id.as_str(), "a");
        assert_eq!(q.action.as_str(), "act");
        assert_eq!(q.resource.as_str(), "res");
    }
}
