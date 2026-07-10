//! Trust Task payload types for the Trust Registry (`registry/*` family).
//!
//! These are the **published** specs: the types are re-exported from
//! [`trust_tasks_rs::specs::registry`], which is generated from the
//! `registry/*` JSON schemas in `dtgwg-trust-tasks-tf`. This crate no longer
//! hand-writes the payloads — the generated types are the single source of
//! truth for field names, the `TYPE_URI`s, and the `IS_PROOF_REQUIRED` policy,
//! so the wire format cannot drift from the spec.
//!
//! Each generated module exposes a `Payload` (request) and a `Response`. We
//! alias them to request/response names for readability at the call sites and
//! add the small glue that bridges the spec payloads to the Trust Registry's
//! own [`crate::domain`] types (query construction + record conversion).

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

use trust_tasks_rs::Payload;
use trust_tasks_rs::specs::registry;

use crate::domain::{Action, AuthorityId, EntityId, Resource};
use crate::storage::repository::TrustRecordQuery;

// --- Request / response types (from the published specs) --------------------

pub use registry::authorization::v0_1::{
    Payload as AuthorizationRequest, Response as AuthorizationResponse,
};
pub use registry::recognition::v0_1::{
    Payload as RecognitionRequest, Response as RecognitionResponse,
};
pub use registry::record::create::v0_1::{
    Payload as RecordCreateRequest, Response as RecordCreateResponse,
};
pub use registry::record::delete::v0_1::{
    Payload as RecordDeleteRequest, Response as RecordDeleteResponse,
};
pub use registry::record::list::v0_1::{
    Payload as RecordListRequest, Response as RecordListResponse,
};
pub use registry::record::read::v0_1::{
    Payload as RecordReadRequest, Response as RecordReadResponse,
};
pub use registry::record::update::v0_1::{
    Payload as RecordUpdateRequest, Response as RecordUpdateResponse,
};

/// Canonical Type URIs for the `registry/*` Trust Task family.
///
/// Derived from the generated `Payload::TYPE_URI` constants so transport
/// bindings (DIDComm/HTTP/TSP) reference exactly the same strings the specs
/// declare — there is no separate hand-maintained list to drift.
pub mod type_uris {
    use super::*;
    use trust_tasks_rs::Payload;

    /// `registry/recognition/0.1` request.
    pub const RECOGNITION: &str = RecognitionRequest::TYPE_URI;
    /// `registry/authorization/0.1` request.
    pub const AUTHORIZATION: &str = AuthorizationRequest::TYPE_URI;
    /// `registry/record/create/0.1` request.
    pub const RECORD_CREATE: &str = RecordCreateRequest::TYPE_URI;
    /// `registry/record/update/0.1` request.
    pub const RECORD_UPDATE: &str = RecordUpdateRequest::TYPE_URI;
    /// `registry/record/delete/0.1` request.
    pub const RECORD_DELETE: &str = RecordDeleteRequest::TYPE_URI;
    /// `registry/record/read/0.1` request.
    pub const RECORD_READ: &str = RecordReadRequest::TYPE_URI;
    /// `registry/record/list/0.1` request.
    pub const RECORD_LIST: &str = RecordListRequest::TYPE_URI;
    /// `registry/did/rotate/0.1` request — rotate the registry's own
    /// VTA-managed `did:webvh` keys.
    pub const DID_ROTATE: &str = "https://trusttasks.org/spec/registry/did/rotate/0.1";
}

// --- Glue between the spec payloads and the domain --------------------------

/// Build the repository's [`TrustRecordQuery`] from the four TRQP identifiers
/// carried (flat) by every query and record-key payload.
pub(crate) fn query_of(
    entity_id: &str,
    authority_id: &str,
    action: &str,
    resource: &str,
) -> TrustRecordQuery {
    TrustRecordQuery::new(
        EntityId::new(entity_id),
        AuthorityId::new(authority_id),
        Action::new(action),
        Resource::new(resource),
    )
}

/// Convert between two structurally-identical types by re-serialising through
/// JSON.
///
/// The generated `specs::registry` `TrustRecord` and the Trust Registry's
/// [`crate::domain::TrustRecord`] share a byte-for-byte wire shape (verbatim
/// TRQP field names, `record_type` lower-cased, `recognized`/`authorized`
/// omitted when absent), so a serialise→deserialise round-trip *is* the
/// conversion. Keeping it in one place means the spec↔domain bridge has a
/// single, obvious failure mode (a genuinely malformed record) rather than a
/// hand-written field-by-field mapping that could silently diverge.
pub(crate) fn reserialize<A, B>(value: &A) -> Result<B, String>
where
    A: Serialize,
    B: DeserializeOwned,
{
    let json = serde_json::to_value(value).map_err(|e| e.to_string())?;
    serde_json::from_value(json).map_err(|e| e.to_string())
}

/// `registry/did/rotate/0.1` request — rotate the registry's own VTA-managed
/// `did:webvh` keys. **Proof required** (administrative, state-changing).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct DidRotateRequest {
    /// Override the pre-rotation commitment count for the new key set.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pre_rotation_count: Option<u32>,
    /// Operator-facing audit label for the rotation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
}

impl Payload for DidRotateRequest {
    const TYPE_URI: &'static str = type_uris::DID_ROTATE;
    const IS_PROOF_REQUIRED: bool = true;
}

/// `registry/did/rotate/0.1#response` — the outcome of a key rotation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DidRotateResponse {
    /// The DID whose keys were rotated.
    pub did: String,
    /// The new SCID after rotation.
    pub new_scid: String,
    /// The new webvh log version id.
    pub new_version_id: String,
}

impl Payload for DidRotateResponse {
    const TYPE_URI: &'static str = "https://trusttasks.org/spec/registry/did/rotate/0.1#response";
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::{Action, AuthorityId, EntityId, RecordType, Resource, TrustRecordBuilder};
    use trust_tasks_rs::Payload;

    #[test]
    fn type_uris_parse_as_valid_type_uris() {
        // `Payload::type_uri()` panics on a malformed TYPE_URI constant, so
        // exercising each one guards the re-exported specs against a bad slug.
        let _ = RecognitionRequest::type_uri();
        let _ = AuthorizationRequest::type_uri();
        let _ = RecordCreateRequest::type_uri();
        let _ = RecordUpdateRequest::type_uri();
        let _ = RecordDeleteRequest::type_uri();
        let _ = RecordReadRequest::type_uri();
        let _ = RecordListRequest::type_uri();
        let _ = DidRotateRequest::type_uri();
        let _ = DidRotateResponse::type_uri();
    }

    #[test]
    fn type_uri_constants_match_the_spec_slugs() {
        assert_eq!(type_uris::RECOGNITION, RecognitionRequest::TYPE_URI);
        assert_eq!(
            RecognitionRequest::type_uri().slug(),
            "registry/recognition"
        );
        assert_eq!(
            RecordCreateRequest::type_uri().slug(),
            "registry/record/create"
        );
    }

    #[test]
    fn writes_require_proof_reads_do_not() {
        assert!(RecordCreateRequest::IS_PROOF_REQUIRED);
        assert!(RecordUpdateRequest::IS_PROOF_REQUIRED);
        assert!(RecordDeleteRequest::IS_PROOF_REQUIRED);
        assert!(DidRotateRequest::IS_PROOF_REQUIRED);
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
        assert_eq!(req.entity_id, "did:example:entity");
        assert_eq!(req.action, "issue");
        assert!(req.context.and_then(|c| c.time).is_some());
    }

    #[test]
    fn domain_record_round_trips_to_and_from_the_spec_record() {
        let domain = TrustRecordBuilder::new()
            .entity_id(EntityId::new("did:example:entity"))
            .authority_id(AuthorityId::new("did:example:authority"))
            .action(Action::new("issue"))
            .resource(Resource::new("vc"))
            .recognized(true)
            .authorized(true)
            .record_type(RecordType::Authorization)
            .build()
            .expect("valid record");

        // domain -> spec -> domain must be lossless.
        let spec: registry::record::create::v0_1::TrustRecord =
            reserialize(&domain).expect("domain -> spec");
        assert_eq!(spec.entity_id, "did:example:entity");
        assert_eq!(spec.record_type.to_string(), "authorization");

        let back: crate::domain::TrustRecord = reserialize(&spec).expect("spec -> domain");
        assert_eq!(back, domain);
    }

    #[test]
    fn query_of_builds_the_repository_query() {
        let q = query_of("e", "a", "act", "res");
        assert_eq!(q.entity_id.as_str(), "e");
        assert_eq!(q.authority_id.as_str(), "a");
        assert_eq!(q.action.as_str(), "act");
        assert_eq!(q.resource.as_str(), "res");
    }
}
