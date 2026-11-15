//! Trust Task payload types for the Trust Registry (`registry/*` family).
//!
//! The request and response types are the **published** specs, re-exported
//! from [`crate::specs::registry`], which `build.rs` generates with
//! `trust-tasks-build` from the bundles pinned in `trust-tasks.lock`. They are
//! the source of truth for member names and the `TYPE_URI`s, so the wire
//! format cannot drift from the spec. (The registry's own proof policy is in
//! [`super::descriptor`]: it is stricter than the specs' for
//! `registry/record/query`.)
//!
//! Each generated module exposes a `Payload` (request) and a `Response`. They
//! are aliased to request/response names here: the snake_case versions at the
//! top level, the lowerCamelCase ones in [`camel`]. The hand-written part is
//! the mapping between each generated wire record and the registry's own
//! [`crate::domain::TrustRecord`] — `From<&TrustRecord>` and
//! `TryFrom<&spec::TrustRecord>` implemented on the generated types — and the
//! repository query built from a record key (`query_of`).

// The 0.1 `registry/*` versions are superseded (the generated types are
// `#[deprecated]`), and this registry still answers them on purpose: peers that
// have not moved to the lowerCamelCase versions keep working.
#![allow(deprecated)]

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
pub use registry::record::put::v0_1::{Payload as RecordPutRequest, Response as RecordPutResponse};
pub use registry::record::query::v0_1::{
    Payload as RecordQueryRequest, Response as RecordQueryResponse,
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

/// Generated types for the lowerCamelCase `registry/*` versions: 0.2 of most
/// tasks, 0.3 of `registry/record/put` and `registry/record/query`.
pub mod camel {
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
// Each served version carries its own generated `TrustRecord` (the generator
// gives every task a copy of the `registry/_shared` record): 0.1 of
// `registry/record/put` and `registry/record/query` is snake_case with no
// validity window, 0.3 is lowerCamelCase with the optional window. The mapping
// to and from the domain record is implemented on those generated types
// (`From<&TrustRecord>` out, `TryFrom<&spec::TrustRecord>` in), explicitly and
// field by field, not as a JSON round-trip: the 0.1 types reject unknown
// members, so the window must be dropped, not passed through.

use crate::specs::registry::record::{put, query};

/// The domain record's opaque context as the JSON object every wire form
/// carries (an empty object is omitted on the wire).
fn context_map(record: &TrustRecord) -> Map<String, Value> {
    record
        .context()
        .as_value()
        .as_object()
        .cloned()
        .unwrap_or_default()
}

/// Validate and assemble a domain record from the members every wire form
/// shares, plus the window of the forms that carry one.
#[allow(clippy::too_many_arguments)]
fn build_record(
    entity_id: &str,
    authority_id: &str,
    action: &str,
    resource: &str,
    recognized: Option<bool>,
    authorized: Option<bool>,
    context: &Map<String, Value>,
    record_type: RecordType,
    valid_from: Option<DateTime<Utc>>,
    valid_until: Option<DateTime<Utc>>,
) -> Result<TrustRecord, String> {
    // A written identifier must be one every TRQP surface can query, so it is
    // validated as a client-supplied value (refused as `malformedRequest`).
    let invalid = |e: crate::domain::IdentifierError| e.to_string();
    let mut builder = TrustRecordBuilder::new()
        .entity_id(EntityId::parse(entity_id).map_err(invalid)?)
        .authority_id(AuthorityId::parse(authority_id).map_err(invalid)?)
        .action(Action::parse(action).map_err(invalid)?)
        .resource(Resource::parse(resource).map_err(invalid)?)
        .context(Context::new(Value::Object(context.clone())))
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

/// `From`/`TryFrom` between the domain record and one generated wire record,
/// plus the record-type enum that version generated for it. `window` says
/// whether the version carries `validFrom`/`validUntil`: without it the window
/// is dropped going out (that reader has no member for it) and absent coming
/// in.
macro_rules! record_wire {
    ($m:ident :: $v:ident, window = false) => {
        record_wire!(@record_type $m::$v);
        impl From<&TrustRecord> for $m::$v::TrustRecord {
            /// The 0.1 wire form: the validity window is dropped.
            fn from(record: &TrustRecord) -> Self {
                Self {
                    entity_id: record.entity_id().to_string(),
                    authority_id: record.authority_id().to_string(),
                    action: record.action().to_string(),
                    resource: record.resource().to_string(),
                    recognized: record.recognized_value(),
                    authorized: record.authorized_value(),
                    context: context_map(record),
                    record_type: record.record_type().clone().into(),
                }
            }
        }
        impl TryFrom<&$m::$v::TrustRecord> for TrustRecord {
            type Error = String;
            /// A 0.1 wire record (no validity window).
            fn try_from(w: &$m::$v::TrustRecord) -> Result<Self, String> {
                build_record(
                    &w.entity_id,
                    &w.authority_id,
                    &w.action,
                    &w.resource,
                    w.recognized,
                    w.authorized,
                    &w.context,
                    w.record_type.into(),
                    None,
                    None,
                )
            }
        }
    };
    ($m:ident :: $v:ident, window = true) => {
        record_wire!(@record_type $m::$v);
        impl From<&TrustRecord> for $m::$v::TrustRecord {
            /// The lowerCamelCase wire form, window included.
            fn from(record: &TrustRecord) -> Self {
                Self {
                    entity_id: record.entity_id().to_string(),
                    authority_id: record.authority_id().to_string(),
                    action: record.action().to_string(),
                    resource: record.resource().to_string(),
                    recognized: record.recognized_value(),
                    authorized: record.authorized_value(),
                    context: context_map(record),
                    record_type: record.record_type().clone().into(),
                    valid_from: record.valid_from(),
                    valid_until: record.valid_until(),
                }
            }
        }
        impl TryFrom<&$m::$v::TrustRecord> for TrustRecord {
            type Error = String;
            /// A lowerCamelCase wire record. Refuses a window whose
            /// `validFrom` is not earlier than its `validUntil`.
            fn try_from(w: &$m::$v::TrustRecord) -> Result<Self, String> {
                build_record(
                    &w.entity_id,
                    &w.authority_id,
                    &w.action,
                    &w.resource,
                    w.recognized,
                    w.authorized,
                    &w.context,
                    w.record_type.into(),
                    w.valid_from,
                    w.valid_until,
                )
            }
        }
    };
    (@record_type $m:ident :: $v:ident) => {
        impl From<RecordType> for $m::$v::RecordType {
            fn from(record_type: RecordType) -> Self {
                match record_type {
                    RecordType::Authorization => Self::Authorization,
                    RecordType::Recognition => Self::Recognition,
                }
            }
        }
        impl From<$m::$v::RecordType> for RecordType {
            fn from(record_type: $m::$v::RecordType) -> Self {
                match record_type {
                    $m::$v::RecordType::Authorization => Self::Authorization,
                    $m::$v::RecordType::Recognition => Self::Recognition,
                }
            }
        }
    };
}

record_wire!(put::v0_1, window = false);
record_wire!(query::v0_1, window = false);
record_wire!(put::v0_3, window = true);
record_wire!(query::v0_3, window = true);

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

/// The key as written, when it differs from [`query_of`]'s normalised one:
/// a record an earlier release stored under a did:scid with its `?src=`
/// locator is still found (and deleted) by the spelling it was stored under.
/// `None` when normalising changed nothing.
pub(crate) fn query_as_written(
    entity_id: &str,
    authority_id: &str,
    action: &str,
    resource: &str,
) -> Option<TrustRecordQuery> {
    let normalised = query_of(entity_id, authority_id, action, resource);
    (normalised.entity_id.as_str() != entity_id || normalised.authority_id.as_str() != authority_id)
        .then(|| {
            TrustRecordQuery::new(
                EntityId::as_written(entity_id),
                AuthorityId::as_written(authority_id),
                Action::new(action),
                Resource::new(resource),
            )
        })
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;
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

    /// The specs' own policy flag. The registry is stricter: it also requires
    /// a proof for `registry/record/query`, whose answers carry whole records
    /// (`descriptor::tests::the_registry_requires_a_proof_for_record_queries`).
    #[allow(clippy::assertions_on_constants)]
    #[test]
    fn the_spec_flags_writes_but_not_queries_as_needing_a_proof() {
        // Constants, so checked at compile time.
        const {
            assert!(RecordPutRequest::IS_PROOF_REQUIRED);
            assert!(RecordDeleteRequest::IS_PROOF_REQUIRED);
            assert!(DidRotateRequest::IS_PROOF_REQUIRED);
            assert!(!RecordQueryRequest::IS_PROOF_REQUIRED);
            assert!(!RecognitionRequest::IS_PROOF_REQUIRED);
            assert!(!AuthorizationRequest::IS_PROOF_REQUIRED);
        }
    }

    // Raw JSON in: the point is to pin the wire spelling the generated types
    // accept, which their own builders cannot show.
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

    // Raw JSON in, for the same reason as above.
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

    // --- Record wire forms: golden JSON -------------------------------------
    //
    // The expected strings below are the wire bytes for each served version,
    // pinned literally (R3.4/R3.6): member spelling, member order, and which
    // optional members are omitted. They are the bytes the generated record
    // types serialised to before the mapping moved onto them, so a change
    // here is a wire change for every consumer.

    const V1_RECORD: &str = r#"{"action":"issue","authority_id":"did:example:authority","context":{"tier":"gold"},"entity_id":"did:example:entity","recognized":true,"record_type":"recognition","resource":"vc"}"#;
    const V2_RECORD: &str = r#"{"action":"issue","authorityId":"did:example:authority","context":{"tier":"gold"},"entityId":"did:example:entity","recognized":true,"recordType":"recognition","resource":"vc","validFrom":"2026-01-01T00:00:00Z","validUntil":"2027-01-01T00:00:00Z"}"#;
    /// An authorization record with no context and no window: both omitted.
    const V1_BARE: &str = r#"{"action":"issue","authority_id":"did:example:authority","authorized":false,"entity_id":"did:example:entity","record_type":"authorization","resource":"vc"}"#;
    const V2_BARE: &str = r#"{"action":"issue","authorityId":"did:example:authority","authorized":false,"entityId":"did:example:entity","recordType":"authorization","resource":"vc"}"#;

    fn instant(s: &str) -> DateTime<Utc> {
        s.parse().expect("RFC 3339 instant")
    }

    /// A recognition record with a context and a validity window.
    fn windowed() -> TrustRecord {
        recognition(true)
    }

    /// The same recognition record, with or without its window.
    fn recognition(window: bool) -> TrustRecord {
        let (from, until) = if window {
            (
                Some(instant("2026-01-01T00:00:00Z")),
                Some(instant("2027-01-01T00:00:00Z")),
            )
        } else {
            (None, None)
        };
        TrustRecordBuilder::new()
            .entity_id(EntityId::new("did:example:entity"))
            .authority_id(AuthorityId::new("did:example:authority"))
            .action(Action::new("issue"))
            .resource(Resource::new("vc"))
            .recognized(true)
            .context(Context::new(serde_json::json!({ "tier": "gold" })))
            .record_type(RecordType::Recognition)
            .valid_from(from)
            .valid_until(until)
            .build()
            .expect("valid record")
    }

    fn bare() -> TrustRecord {
        TrustRecordBuilder::new()
            .entity_id(EntityId::new("did:example:entity"))
            .authority_id(AuthorityId::new("did:example:authority"))
            .action(Action::new("issue"))
            .resource(Resource::new("vc"))
            .authorized(false)
            .record_type(RecordType::Authorization)
            .build()
            .expect("valid record")
    }

    /// `domain -> spec` for one version produces exactly `expected`, and
    /// `expected` parses back (through the generated type) to `back`.
    macro_rules! golden {
        ($spec:ty, $domain:expr, $expected:expr, $back:expr) => {{
            let spec = <$spec>::from(&$domain);
            assert_eq!(serde_json::to_string(&spec).unwrap(), $expected);
            let parsed: $spec = serde_json::from_str($expected).unwrap();
            assert_eq!(serde_json::to_string(&parsed).unwrap(), $expected);
            assert_eq!(TrustRecord::try_from(&parsed).unwrap(), $back);
        }};
    }

    /// The 0.1 records (put in, query out) drop the window, and a 0.1 record
    /// read back has none.
    #[test]
    fn v0_1_records_keep_their_snake_case_wire_form_without_a_window() {
        let unwindowed = recognition(false);
        golden!(
            put::v0_1::TrustRecord,
            windowed(),
            V1_RECORD,
            unwindowed.clone()
        );
        golden!(query::v0_1::TrustRecord, windowed(), V1_RECORD, unwindowed);
        golden!(put::v0_1::TrustRecord, bare(), V1_BARE, bare());
        golden!(query::v0_1::TrustRecord, bare(), V1_BARE, bare());
    }

    /// The 0.3 records are lowerCamelCase and carry the window both ways.
    #[test]
    fn v0_3_records_keep_their_camel_case_wire_form_with_the_window() {
        golden!(put::v0_3::TrustRecord, windowed(), V2_RECORD, windowed());
        golden!(query::v0_3::TrustRecord, windowed(), V2_RECORD, windowed());
        golden!(put::v0_3::TrustRecord, bare(), V2_BARE, bare());
        golden!(query::v0_3::TrustRecord, bare(), V2_BARE, bare());
    }

    /// A whole `registry/record/query` answer, per version, around the record.
    #[test]
    fn record_query_responses_keep_their_wire_form() {
        let v1: RecordQueryResponse = RecordQueryResponse::builder()
            .records(vec![(&windowed()).into()])
            .next_cursor(Some("50".to_string()))
            .try_into()
            .unwrap();
        assert_eq!(
            serde_json::to_string(&v1).unwrap(),
            format!(r#"{{"nextCursor":"50","records":[{V1_RECORD}]}}"#)
        );
        let v3: camel::RecordQueryResponse = camel::RecordQueryResponse::builder()
            .records(vec![(&windowed()).into()])
            .try_into()
            .unwrap();
        assert_eq!(
            serde_json::to_string(&v3).unwrap(),
            format!(r#"{{"records":[{V2_RECORD}]}}"#)
        );
    }

    /// A whole `registry/record/put` request, per version, around the record.
    #[test]
    fn record_put_requests_keep_their_wire_form() {
        let v1: RecordPutRequest = RecordPutRequest::builder()
            .record(put::v0_1::TrustRecord::from(&bare()))
            .expected_existing(Some(false))
            .try_into()
            .unwrap();
        assert_eq!(
            serde_json::to_string(&v1).unwrap(),
            format!(r#"{{"expectedExisting":false,"record":{V1_BARE}}}"#)
        );
        let v3: camel::RecordPutRequest = camel::RecordPutRequest::builder()
            .record(put::v0_3::TrustRecord::from(&windowed()))
            .try_into()
            .unwrap();
        assert_eq!(
            serde_json::to_string(&v3).unwrap(),
            format!(r#"{{"record":{V2_RECORD}}}"#)
        );
    }

    /// Inbound records are validated like any client-supplied value: an
    /// inverted window and an invalid identifier are refused.
    #[test]
    fn inbound_records_are_validated() {
        let mut inverted = put::v0_3::TrustRecord::from(&windowed());
        std::mem::swap(&mut inverted.valid_from, &mut inverted.valid_until);
        assert!(TrustRecord::try_from(&inverted).is_err());

        let mut empty_entity = put::v0_1::TrustRecord::from(&bare());
        empty_entity.entity_id = String::new();
        assert!(TrustRecord::try_from(&empty_entity).is_err());
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
