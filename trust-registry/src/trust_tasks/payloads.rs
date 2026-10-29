//! Trust Task payload types for the Trust Registry (`registry/*` family).
//!
//! These are the **published** specs: the types are re-exported from
//! [`crate::specs::registry`], which `build.rs` generates with
//! `trust-tasks-build` from the bundles pinned in `trust-tasks.lock`. Nothing
//! here is hand-written — the generated types are the single source of truth
//! for field names, the `TYPE_URI`s, and the proof/`issuedAt`/recipient policy,
//! so the wire format cannot drift from the spec.
//!
//! Each generated module exposes a `Payload` (request) and a `Response`. We
//! alias them to request/response names for readability at the call sites and
//! add the small glue that bridges the spec payloads to the Trust Registry's
//! own [`crate::domain`] types (query construction + record conversion).

// The 0.1 `registry/*` versions are superseded (the generated types are
// `#[deprecated]`), and this registry still answers them on purpose: peers that
// have not moved to the lowerCamelCase versions keep working.
#![allow(deprecated)]

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

use crate::specs::registry;

use crate::domain::{
    Action, AuthorityId, Context, EntityId, RecordType, Resource, TrustRecord, TrustRecordBuilder,
};
use crate::storage::repository::TrustRecordQuery;
use chrono::{DateTime, Utc};
use serde_json::{Map, Value};

// --- Request / response types (from the published specs) --------------------

pub use registry::authorization::v0_1::{
    Payload as AuthorizationRequest, Response as AuthorizationResponse,
    ResponseMessage as AuthorizationResponseMessage,
};
pub use registry::did::rotate::v0_1::{Payload as DidRotateRequest, Response as DidRotateResponse};
pub use registry::recognition::v0_1::{
    Payload as RecognitionRequest, Response as RecognitionResponse,
    ResponseMessage as RecognitionResponseMessage,
};
pub use registry::record::delete::v0_1::{
    Payload as RecordDeleteRequest, Response as RecordDeleteResponse,
};
pub use registry::record::put::v0_1::{
    Payload as RecordPutRequest, Response as RecordPutResponse,
    ResponseMessage as RecordPutResponseMessage,
};
pub use registry::record::query::v0_1::{
    Payload as RecordQueryRequest, Response as RecordQueryResponse,
};

/// The spec-side `TrustRecord` wire shape (verbatim TRQP field names), as
/// `registry/record/put/0.1` carries it.
pub use registry::record::put::v0_1::TrustRecord as SpecTrustRecord;

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
    /// `registry/record/put/0.1` request — create-or-replace at the record key.
    pub const RECORD_PUT: &str = RecordPutRequest::TYPE_URI;
    /// `registry/record/query/0.1` request — exact fetch or paginated enumeration.
    pub const RECORD_QUERY: &str = RecordQueryRequest::TYPE_URI;
    /// `registry/record/delete/0.1` request.
    pub const RECORD_DELETE: &str = RecordDeleteRequest::TYPE_URI;
    /// `registry/did/rotate/0.1` request — rotate the registry's own
    /// VTA-managed `did:webvh` keys.
    pub const DID_ROTATE: &str = DidRotateRequest::TYPE_URI;
}

// --- The lowerCamelCase versions ---------------------------------------------
//
// `registry/authorization` and `registry/recognition` 0.2, `registry/record/put`
// and `registry/record/query` 0.3, `registry/record/delete` and
// `registry/did/rotate` 0.2: the same tasks with lowerCamelCase members and,
// on records, the optional `validFrom`/`validUntil` window. Served alongside
// the versions above, which keep their snake_case wire form.

/// Generated types for the lowerCamelCase `registry/*` versions.
pub mod v2 {
    pub use crate::specs::registry::authorization::v0_2::{
        Payload as AuthorizationRequest, Response as AuthorizationResponse,
        ResponseMessage as AuthorizationResponseMessage,
    };
    pub use crate::specs::registry::did::rotate::v0_2::{
        Payload as DidRotateRequest, Response as DidRotateResponse,
    };
    pub use crate::specs::registry::recognition::v0_2::{
        Payload as RecognitionRequest, Response as RecognitionResponse,
        ResponseMessage as RecognitionResponseMessage,
    };
    pub use crate::specs::registry::record::delete::v0_2::{
        Payload as RecordDeleteRequest, Response as RecordDeleteResponse,
    };
    pub use crate::specs::registry::record::put::v0_3::{
        Payload as RecordPutRequest, Response as RecordPutResponse,
    };
    pub use crate::specs::registry::record::query::v0_3::{
        Payload as RecordQueryRequest, Response as RecordQueryResponse,
    };
}

// --- Record wire forms ---------------------------------------------------------
//
// One explicit mapping per wire form, rather than a JSON round-trip through the
// domain type: the 0.1 form has no validity window (and its generated types
// reject unknown members, so the window must be dropped, not passed through),
// and the 0.2 form spells every member differently.

/// The 0.1 record (`registry/_shared/0.1` `TrustRecord`): snake_case, no window.
#[derive(Serialize, Deserialize)]
struct WireRecordV1 {
    entity_id: String,
    authority_id: String,
    action: String,
    resource: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    recognized: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    authorized: Option<bool>,
    #[serde(default, skip_serializing_if = "Map::is_empty")]
    context: Map<String, Value>,
    record_type: RecordType,
}

/// The 0.2 record (`registry/_shared/0.2` `TrustRecord`): lowerCamelCase, with
/// the optional validity window.
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct WireRecordV2 {
    entity_id: String,
    authority_id: String,
    action: String,
    resource: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    recognized: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    authorized: Option<bool>,
    #[serde(default, skip_serializing_if = "Map::is_empty")]
    context: Map<String, Value>,
    record_type: RecordType,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    valid_from: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    valid_until: Option<DateTime<Utc>>,
}

fn context_map(record: &TrustRecord) -> Map<String, Value> {
    record
        .context()
        .as_value()
        .as_object()
        .cloned()
        .unwrap_or_default()
}

#[allow(clippy::too_many_arguments)]
fn build_record(
    entity_id: String,
    authority_id: String,
    action: String,
    resource: String,
    recognized: Option<bool>,
    authorized: Option<bool>,
    context: Map<String, Value>,
    record_type: RecordType,
    valid_from: Option<DateTime<Utc>>,
    valid_until: Option<DateTime<Utc>>,
) -> Result<TrustRecord, String> {
    let mut builder = TrustRecordBuilder::new()
        .entity_id(EntityId::new(entity_id))
        .authority_id(AuthorityId::new(authority_id))
        .action(Action::new(action))
        .resource(Resource::new(resource))
        .context(Context::new(Value::Object(context)))
        .record_type(record_type)
        .valid_from(valid_from)
        .valid_until(valid_until);
    if let Some(recognized) = recognized {
        builder = builder.recognized(recognized);
    }
    if let Some(authorized) = authorized {
        builder = builder.authorized(authorized);
    }
    builder.build().map_err(|e| e.to_string())
}

/// A domain record in the 0.1 wire form. The validity window is dropped: a
/// 0.1 reader has no member for it.
pub(crate) fn record_to_v1<T: DeserializeOwned>(record: &TrustRecord) -> Result<T, String> {
    reserialize(&WireRecordV1 {
        entity_id: record.entity_id().to_string(),
        authority_id: record.authority_id().to_string(),
        action: record.action().to_string(),
        resource: record.resource().to_string(),
        recognized: record.recognized_value(),
        authorized: record.authorized_value(),
        context: context_map(record),
        record_type: record.record_type().clone(),
    })
}

/// A domain record in the 0.2 wire form, window included.
pub(crate) fn record_to_v2<T: DeserializeOwned>(record: &TrustRecord) -> Result<T, String> {
    reserialize(&WireRecordV2 {
        entity_id: record.entity_id().to_string(),
        authority_id: record.authority_id().to_string(),
        action: record.action().to_string(),
        resource: record.resource().to_string(),
        recognized: record.recognized_value(),
        authorized: record.authorized_value(),
        context: context_map(record),
        record_type: record.record_type().clone(),
        valid_from: record.valid_from(),
        valid_until: record.valid_until(),
    })
}

/// A 0.1 wire record as a domain record (no validity window).
pub(crate) fn record_from_v1<T: Serialize>(spec: &T) -> Result<TrustRecord, String> {
    let w: WireRecordV1 = reserialize(spec)?;
    build_record(
        w.entity_id,
        w.authority_id,
        w.action,
        w.resource,
        w.recognized,
        w.authorized,
        w.context,
        w.record_type,
        None,
        None,
    )
}

/// A 0.2 wire record as a domain record. Refuses a window whose `validFrom`
/// is not earlier than its `validUntil`.
pub(crate) fn record_from_v2<T: Serialize>(spec: &T) -> Result<TrustRecord, String> {
    let w: WireRecordV2 = reserialize(spec)?;
    build_record(
        w.entity_id,
        w.authority_id,
        w.action,
        w.resource,
        w.recognized,
        w.authorized,
        w.context,
        w.record_type,
        w.valid_from,
        w.valid_until,
    )
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
        let _ = RecordPutRequest::type_uri();
        let _ = RecordQueryRequest::type_uri();
        let _ = RecordDeleteRequest::type_uri();
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
        assert_eq!(RecordPutRequest::type_uri().slug(), "registry/record/put");
        assert_eq!(
            RecordQueryRequest::type_uri().slug(),
            "registry/record/query"
        );
    }

    #[test]
    fn writes_require_proof_reads_do_not() {
        assert!(RecordPutRequest::IS_PROOF_REQUIRED);
        assert!(RecordDeleteRequest::IS_PROOF_REQUIRED);
        assert!(DidRotateRequest::IS_PROOF_REQUIRED);
        assert!(!RecordQueryRequest::IS_PROOF_REQUIRED);
        assert!(!RecognitionRequest::IS_PROOF_REQUIRED);
        assert!(!AuthorizationRequest::IS_PROOF_REQUIRED);
    }

    #[test]
    fn put_and_query_use_the_spec_wire_field_names() {
        // `expectedExisting` / `nextCursor` are camelCase on the wire (framework
        // 0.2 convention); the TRQP key fields stay snake_case.
        let put: RecordPutRequest = serde_json::from_value(serde_json::json!({
            "record": {
                "entity_id": "did:example:entity",
                "authority_id": "did:example:authority",
                "action": "issue",
                "resource": "vc",
                "record_type": "authorization"
            },
            "expectedExisting": false
        }))
        .expect("parses");
        assert_eq!(put.expected_existing, Some(false));
        let put_json = serde_json::to_value(&put).expect("serialises");
        assert!(put_json.get("expectedExisting").is_some());

        let response: RecordQueryResponse = RecordQueryResponse::builder()
            .records(vec![])
            .next_cursor(Some("50".to_string()))
            .try_into()
            .expect("valid response");
        let json = serde_json::to_value(&response).expect("serialises");
        assert_eq!(json["nextCursor"], "50");
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
        let spec: SpecTrustRecord = reserialize(&domain).expect("domain -> spec");
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
