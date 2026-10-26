use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::fmt;

pub mod key;

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
pub struct EntityId(String);

impl EntityId {
    pub fn new(id: impl Into<String>) -> Self {
        Self(id.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for EntityId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
pub struct AuthorityId(String);

impl AuthorityId {
    pub fn new(id: impl Into<String>) -> Self {
        Self(id.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for AuthorityId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
pub struct Action(String);

impl Action {
    pub fn new(action: impl Into<String>) -> Self {
        Self(action.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for Action {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
pub struct Resource(String);

impl Resource {
    pub fn new(resource: impl Into<String>) -> Self {
        Self(resource.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for Resource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Context(serde_json::Value);

impl Context {
    pub fn empty() -> Self {
        Self(json!({}))
    }

    pub fn new(value: serde_json::Value) -> Self {
        Self(value)
    }

    pub fn as_value(&self) -> &serde_json::Value {
        &self.0
    }

    pub fn merge(self, additional: Context) -> Self {
        Self(merge_json_values(self.0, additional.0))
    }
}

impl Default for Context {
    fn default() -> Self {
        Self::empty()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustRecordIds {
    entity_id: EntityId,
    authority_id: AuthorityId,
    action: Action,
    resource: Resource,
}

impl TrustRecordIds {
    pub fn entity_id(&self) -> &EntityId {
        &self.entity_id
    }

    pub fn authority_id(&self) -> &AuthorityId {
        &self.authority_id
    }

    pub fn resource(&self) -> &Resource {
        &self.resource
    }

    pub fn action(&self) -> &Action {
        &self.action
    }

    pub fn into_parts(self) -> (EntityId, AuthorityId, Action, Resource) {
        let Self {
            entity_id,
            authority_id,
            action,
            resource,
        } = self;

        (entity_id, authority_id, action, resource)
    }
}

#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum RecordType {
    Authorization,
    Recognition,
}

impl<'de> Deserialize<'de> for RecordType {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        s.parse::<RecordType>().map_err(serde::de::Error::custom)
    }
}

impl std::str::FromStr for RecordType {
    type Err = TrustRecordError;

    fn from_str(s: &str) -> Result<Self, TrustRecordError> {
        match s.to_lowercase().as_str() {
            "authorization" => Ok(Self::Authorization),
            "recognition" => Ok(Self::Recognition),
            _ => Err(TrustRecordError::InvalidRecordType),
        }
    }
}

impl fmt::Display for RecordType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Authorization => write!(f, "authorization"),
            Self::Recognition => write!(f, "recognition"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TrustRecord {
    entity_id: EntityId,
    authority_id: AuthorityId,
    action: Action,
    resource: Resource,
    #[serde(skip_serializing_if = "Option::is_none")]
    recognized: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    authorized: Option<bool>,
    // The published `registry/*` spec omits an empty `context` on the wire
    // (`skip_serializing_if` empty map), so accept a missing one as empty to
    // stay interop-compatible with the generated spec records.
    #[serde(default)]
    context: Context,
    record_type: RecordType,
    /// First instant the statement holds (inclusive). Absent: no lower bound.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    valid_from: Option<DateTime<Utc>>,
    /// Instant the statement stops holding (exclusive). Absent: no upper bound.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    valid_until: Option<DateTime<Utc>>,
}

/// Whether a record's validity window contains an instant.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Validity {
    /// The window contains the instant (or the record has no window).
    Valid,
    /// The instant is before `valid_from`.
    NotYetValid,
    /// The instant is at or after `valid_until`.
    Ended,
}

/// How far before its `valid_from` a record counts as started when the
/// registry evaluates at its own clock. Absorbs clock skew between the writer
/// and the registry (`registry/authorization` 0.2, *Evaluation*); never
/// applied to `valid_until`, nor to an instant the client named.
pub const VALIDITY_START_LEEWAY: chrono::Duration = chrono::Duration::seconds(60);

/// The answer to a recognition or authorization query, before it is shaped
/// into any one wire format.
#[derive(Debug, Clone)]
pub struct Evaluation {
    /// The instant the answer holds for: the client's `context.time`, or the
    /// registry's clock when it named none.
    pub instant: DateTime<Utc>,
    /// Whether the client named the instant (then echoed as `asOf` /
    /// `time_requested`).
    pub asked: bool,
    /// The record's window relative to `instant`; `None` when no record exists.
    pub validity: Option<Validity>,
}

impl Evaluation {
    /// Evaluate `record` as of `asked`, or as of `now` when the client named
    /// no instant. Only the latter gets [`VALIDITY_START_LEEWAY`].
    pub fn of(
        record: Option<&TrustRecord>,
        asked: Option<DateTime<Utc>>,
        now: DateTime<Utc>,
    ) -> Self {
        let (instant, leeway) = match asked {
            Some(t) => (t, chrono::Duration::zero()),
            None => (now, VALIDITY_START_LEEWAY),
        };
        Self {
            instant,
            asked: asked.is_some(),
            validity: record.map(|r| r.validity_at(instant, leeway)),
        }
    }

    /// Whether the record's own `recognized`/`authorized` value applies.
    pub fn in_window(&self) -> bool {
        self.validity == Some(Validity::Valid)
    }

    /// Why a record that exists does not answer `true`, for the response
    /// `message`. `None` when the record is in its window or absent.
    pub fn out_of_window_reason(&self, record: &TrustRecord) -> Option<String> {
        let fmt = |t: DateTime<Utc>| t.to_rfc3339_opts(chrono::SecondsFormat::AutoSi, true);
        match self.validity? {
            Validity::Valid => None,
            Validity::NotYetValid => Some(format!(
                "the statement is not valid until {}",
                record.valid_from.map(fmt).unwrap_or_default()
            )),
            Validity::Ended => Some(format!(
                "the statement stopped being valid at {}",
                record.valid_until.map(fmt).unwrap_or_default()
            )),
        }
    }
}

impl fmt::Display for TrustRecord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}|{}|{}|{}",
            self.entity_id, self.authority_id, self.action, self.resource
        )
    }
}

impl TrustRecord {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        entity_id: EntityId,
        authority_id: AuthorityId,
        action: Action,
        resource: Resource,
        recognized: bool,
        authorized: bool,
        context: Context,
        record_type: RecordType,
    ) -> Self {
        Self {
            entity_id,
            authority_id,
            action,
            resource,
            recognized: Some(recognized),
            authorized: Some(authorized),
            context,
            record_type,
            valid_from: None,
            valid_until: None,
        }
    }

    pub fn entity_id(&self) -> &EntityId {
        &self.entity_id
    }

    pub fn authority_id(&self) -> &AuthorityId {
        &self.authority_id
    }

    pub fn action(&self) -> &Action {
        &self.action
    }

    pub fn resource(&self) -> &Resource {
        &self.resource
    }

    /// The stored `recognized` value, `None` when the record carries none.
    pub fn recognized_value(&self) -> Option<bool> {
        self.recognized
    }

    /// The stored `authorized` value, `None` when the record carries none.
    pub fn authorized_value(&self) -> Option<bool> {
        self.authorized
    }

    pub fn is_recognized(&self) -> bool {
        self.recognized.unwrap_or_default()
    }

    pub fn context(&self) -> &Context {
        &self.context
    }

    pub fn record_type(&self) -> &RecordType {
        &self.record_type
    }

    pub fn is_authorized(&self) -> bool {
        self.authorized.unwrap_or_default()
    }

    /// Merges additional_context into the given one.
    /// additional_context will OVERRIDE the existing one
    pub fn merge_contexts(mut self, additional_context: Context) -> Self {
        let base_context = std::mem::take(&mut self.context);
        self.context = base_context.merge(additional_context);
        self
    }

    pub fn valid_from(&self) -> Option<DateTime<Utc>> {
        self.valid_from
    }

    pub fn valid_until(&self) -> Option<DateTime<Utc>> {
        self.valid_until
    }

    /// Whether the record's validity window, `[valid_from, valid_until)`,
    /// contains `instant`. An absent bound leaves that side open.
    ///
    /// `start_leeway` lets a record count as started that much before its
    /// `valid_from`, to absorb clock skew between the writer and this
    /// registry. It is never applied to `valid_until`: a statement that has
    /// ended is not honoured late. Callers pass zero when the client named the
    /// instant itself.
    pub fn validity_at(&self, instant: DateTime<Utc>, start_leeway: chrono::Duration) -> Validity {
        if let Some(from) = self.valid_from
            && instant < from - start_leeway
        {
            return Validity::NotYetValid;
        }
        if let Some(until) = self.valid_until
            && instant >= until
        {
            return Validity::Ended;
        }
        Validity::Valid
    }

    /// This record answering `authorized` as given, whatever it stores; used
    /// to answer `false` for a record outside its validity window.
    pub fn with_authorized(mut self, authorized: bool) -> Self {
        self.authorized = Some(authorized);
        self
    }

    /// As [`with_authorized`](Self::with_authorized), for `recognized`.
    pub fn with_recognized(mut self, recognized: bool) -> Self {
        self.recognized = Some(recognized);
        self
    }

    pub fn none_authorized(mut self) -> Self {
        self.authorized = None;
        self
    }

    pub fn none_recognized(mut self) -> Self {
        self.recognized = None;
        self
    }
}

fn merge_json_values(base: Value, additional: Value) -> Value {
    match (base, additional) {
        (Value::Object(mut base_map), Value::Object(additional_map)) => {
            for (key, additional_value) in additional_map {
                let merged_value = match base_map.remove(&key) {
                    Some(base_value) => merge_json_values(base_value, additional_value),
                    None => additional_value,
                };
                base_map.insert(key, merged_value);
            }
            Value::Object(base_map)
        }
        (_, additional_value) => additional_value,
    }
}

pub struct TrustRecordBuilder {
    entity_id: Option<EntityId>,
    authority_id: Option<AuthorityId>,
    action: Option<Action>,
    resource: Option<Resource>,
    recognized: Option<bool>,
    context: Context,
    authorized: Option<bool>,
    record_type: Option<RecordType>,
    valid_from: Option<DateTime<Utc>>,
    valid_until: Option<DateTime<Utc>>,
}

impl TrustRecordBuilder {
    pub fn new() -> Self {
        Self {
            entity_id: None,
            authority_id: None,
            action: None,
            resource: None,
            recognized: None,
            context: Context::empty(),
            authorized: None,
            record_type: None,
            valid_from: None,
            valid_until: None,
        }
    }

    pub fn valid_from(mut self, valid_from: Option<DateTime<Utc>>) -> Self {
        self.valid_from = valid_from;
        self
    }

    pub fn valid_until(mut self, valid_until: Option<DateTime<Utc>>) -> Self {
        self.valid_until = valid_until;
        self
    }

    pub fn entity_id(mut self, id: EntityId) -> Self {
        self.entity_id = Some(id);
        self
    }

    pub fn authority_id(mut self, id: AuthorityId) -> Self {
        self.authority_id = Some(id);
        self
    }

    pub fn action(mut self, action: Action) -> Self {
        self.action = Some(action);
        self
    }
    pub fn resource(mut self, resource: Resource) -> Self {
        self.resource = Some(resource);
        self
    }

    pub fn recognized(mut self, recognized: bool) -> Self {
        self.recognized = Some(recognized);
        self
    }

    pub fn context(mut self, context: Context) -> Self {
        self.context = context;
        self
    }

    pub fn authorized(mut self, authorized: bool) -> Self {
        self.authorized = Some(authorized);
        self
    }

    pub fn record_type(mut self, record_type: RecordType) -> Self {
        self.record_type = Some(record_type);
        self
    }

    pub fn build(self) -> Result<TrustRecord, TrustRecordError> {
        if let (Some(from), Some(until)) = (self.valid_from, self.valid_until)
            && from >= until
        {
            return Err(TrustRecordError::InvalidValidityWindow);
        }
        Ok(TrustRecord {
            entity_id: self.entity_id.ok_or(TrustRecordError::MissingEntityId)?,
            authority_id: self
                .authority_id
                .ok_or(TrustRecordError::MissingAuthorityId)?,
            action: self.action.ok_or(TrustRecordError::MissingAction)?,
            authorized: self.authorized,
            recognized: self.recognized,
            context: self.context,
            resource: self.resource.ok_or(TrustRecordError::MissingResource)?,
            record_type: self
                .record_type
                .ok_or(TrustRecordError::MissingRecordType)?,
            valid_from: self.valid_from,
            valid_until: self.valid_until,
        })
    }
}

impl Default for TrustRecordBuilder {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TrustRecordError {
    MissingEntityId,
    MissingAuthorityId,
    MissingAction,
    MissingResource,
    MissingTimeRequested,
    MissingTimeEvaluated,
    MissingRecordType,
    InvalidRecordType,
    /// `valid_from` is not earlier than `valid_until`.
    InvalidValidityWindow,
}

impl fmt::Display for TrustRecordError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingEntityId => write!(f, "Entity ID is required"),
            Self::MissingAuthorityId => write!(f, "Authority ID is required"),
            Self::MissingAction => write!(f, "Action is required"),
            Self::MissingResource => write!(f, "Resource is required"),
            Self::MissingTimeRequested => write!(f, "Time requested is required"),
            Self::MissingTimeEvaluated => write!(f, "Time evaluated is required"),
            Self::MissingRecordType => write!(f, "Record type is required"),
            Self::InvalidRecordType => write!(f, "Record type is invalid"),
            Self::InvalidValidityWindow => {
                write!(f, "valid_from must be earlier than valid_until")
            }
        }
    }
}

impl std::error::Error for TrustRecordError {}

#[cfg(test)]
mod tests {

    fn at(s: &str) -> chrono::DateTime<chrono::Utc> {
        chrono::DateTime::parse_from_rfc3339(s)
            .unwrap()
            .with_timezone(&chrono::Utc)
    }

    fn windowed(from: Option<&str>, until: Option<&str>) -> TrustRecord {
        TrustRecordBuilder::new()
            .entity_id(EntityId::new("e"))
            .authority_id(AuthorityId::new("a"))
            .action(Action::new("x"))
            .resource(Resource::new("r"))
            .authorized(true)
            .record_type(RecordType::Authorization)
            .valid_from(from.map(at))
            .valid_until(until.map(at))
            .build()
            .unwrap()
    }

    #[test]
    fn a_record_without_bounds_holds_at_every_instant() {
        let r = windowed(None, None);
        for t in ["1970-01-01T00:00:00Z", "2999-01-01T00:00:00Z"] {
            assert_eq!(
                r.validity_at(at(t), chrono::Duration::zero()),
                Validity::Valid
            );
        }
    }

    #[test]
    fn valid_from_is_inclusive_and_valid_until_exclusive() {
        let r = windowed(Some("2026-01-01T00:00:00Z"), Some("2027-01-01T00:00:00Z"));
        let z = chrono::Duration::zero();
        assert_eq!(
            r.validity_at(at("2025-12-31T23:59:59Z"), z),
            Validity::NotYetValid
        );
        assert_eq!(
            r.validity_at(at("2026-01-01T00:00:00Z"), z),
            Validity::Valid
        );
        assert_eq!(
            r.validity_at(at("2026-12-31T23:59:59Z"), z),
            Validity::Valid
        );
        assert_eq!(
            r.validity_at(at("2027-01-01T00:00:00Z"), z),
            Validity::Ended
        );
    }

    #[test]
    fn leeway_moves_the_start_only() {
        let r = windowed(Some("2026-01-01T00:00:00Z"), Some("2027-01-01T00:00:00Z"));
        let leeway = VALIDITY_START_LEEWAY;
        assert_eq!(
            r.validity_at(at("2025-12-31T23:59:30Z"), leeway),
            Validity::Valid
        );
        assert_eq!(
            r.validity_at(at("2025-12-31T23:58:59Z"), leeway),
            Validity::NotYetValid
        );
        // An ended statement is not honoured late.
        assert_eq!(
            r.validity_at(at("2027-01-01T00:00:01Z"), leeway),
            Validity::Ended
        );
    }

    #[test]
    fn evaluation_gives_leeway_only_at_the_registry_clock() {
        let r = windowed(Some("2026-01-01T00:00:00Z"), None);
        let now = at("2025-12-31T23:59:30Z");
        assert!(Evaluation::of(Some(&r), None, now).in_window());
        assert!(!Evaluation::of(Some(&r), Some(now), now).in_window());
        assert_eq!(Evaluation::of(None, None, now).validity, None);
    }

    #[test]
    fn an_inverted_or_empty_window_is_refused() {
        for (from, until) in [
            ("2027-01-01T00:00:00Z", "2026-01-01T00:00:00Z"),
            ("2026-01-01T00:00:00Z", "2026-01-01T00:00:00Z"),
        ] {
            let built = TrustRecordBuilder::new()
                .entity_id(EntityId::new("e"))
                .authority_id(AuthorityId::new("a"))
                .action(Action::new("x"))
                .resource(Resource::new("r"))
                .record_type(RecordType::Recognition)
                .valid_from(Some(at(from)))
                .valid_until(Some(at(until)))
                .build();
            assert_eq!(built, Err(TrustRecordError::InvalidValidityWindow));
        }
    }

    #[test]
    fn a_stored_record_without_a_window_still_deserializes() {
        // Records written before the window existed have no such members.
        let r: TrustRecord = serde_json::from_value(json!({
            "entity_id": "e", "authority_id": "a", "action": "x", "resource": "r",
            "authorized": true, "record_type": "authorization"
        }))
        .unwrap();
        assert_eq!((r.valid_from(), r.valid_until()), (None, None));
        let back = serde_json::to_value(&r).unwrap();
        assert!(
            back.get("valid_from").is_none(),
            "absent bounds are not written: {back}"
        );
    }
    use super::*;

    #[test]
    fn test_trust_record_creation() {
        let record = TrustRecordBuilder::new()
            .entity_id(EntityId::new("entity-123"))
            .authority_id(AuthorityId::new("authority-456"))
            .action(Action::new("action-789"))
            .resource(Resource::new("resource-112"))
            .recognized(true)
            .authorized(true)
            .record_type(RecordType::Authorization)
            .build()
            .unwrap();

        assert_eq!(record.entity_id().as_str(), "entity-123");
        assert_eq!(record.record_type().to_string(), "authorization");
    }

    #[test]
    fn test_builder_missing_fields() {
        let result = TrustRecordBuilder::new()
            .entity_id(EntityId::new("entity-123"))
            .build();

        assert!(result.is_err());
    }

    #[test]
    fn test_context_merge_overrides() {
        let base = Context::new(json!({
            "a": 1,
            "nested": {
                "b": 1
            },
            "arr_replaced": [3, 4],
        }));
        let additional = Context::new(json!({
            "nested": {
                "b": 2,
                "c": 3
            },
            "arr_replaced": [1, 2],
            "d": 4
        }));

        let merged = base.merge(additional);

        assert_eq!(
            merged.as_value(),
            &json!({
                "a": 1,
                "nested": {
                    "b": 2,
                    "c": 3
                },
                "arr_replaced": [1, 2],
                "d": 4
            })
        );
    }

    #[test]
    fn test_trust_record_merge_contexts() {
        let record = TrustRecord::new(
            EntityId::new("entity-123"),
            AuthorityId::new("authority-456"),
            Action::new("action-789"),
            Resource::new("resource-112"),
            true,
            true,
            Context::new(json!({
                "original": true,
                "nested": {
                    "keep": true,
                    "override": false
                }
            })),
            RecordType::Authorization,
        );

        let merged_record = record.merge_contexts(Context::new(json!({
            "nested": {
                "override": true
            },
            "additional": "value"
        })));

        assert_eq!(
            merged_record.context().as_value(),
            &json!({
                "original": true,
                "nested": {
                    "keep": true,
                    "override": true
                },
                "additional": "value"
            })
        );
    }

    #[test]
    fn test_merge_json_values_both_objects() {
        let base = json!({
            "a": 1,
            "nested": {
                "x": 10,
                "y": 20
            }
        });
        let additional = json!({
            "b": 2,
            "nested": {
                "y": 30,
                "z": 40
            }
        });

        let result = merge_json_values(base, additional);

        assert_eq!(
            result,
            json!({
                "a": 1,
                "b": 2,
                "nested": {
                    "x": 10,
                    "y": 30,
                    "z": 40
                }
            })
        );
    }

    #[test]
    fn test_merge_json_values_base_not_object() {
        let base = json!("string_value");
        let additional = json!({
            "key": "value"
        });

        let result = merge_json_values(base, additional);

        // When base is not an object, additional should completely replace it
        assert_eq!(result, json!({"key": "value"}));
    }

    #[test]
    fn test_merge_json_values_additional_not_object() {
        let base = json!({
            "existing": "value"
        });
        let additional = json!("replacement_string");

        let result = merge_json_values(base, additional);

        // When additional is not an object, it should completely replace base
        assert_eq!(result, json!("replacement_string"));
    }

    #[test]
    fn test_merge_json_values_empty_objects() {
        let base = json!({});
        let additional = json!({
            "new_key": "new_value"
        });

        let result = merge_json_values(base, additional);

        assert_eq!(result, json!({"new_key": "new_value"}));
    }

    #[test]
    fn test_merge_json_values_additional_empty() {
        let base = json!({
            "existing": "value"
        });
        let additional = json!({});

        let result = merge_json_values(base, additional);

        assert_eq!(result, json!({"existing": "value"}));
    }

    #[test]
    fn test_merge_json_values_nested_arrays_replaced() {
        let base = json!({
            "array_field": [1, 2, 3],
            "other": "value"
        });
        let additional = json!({
            "array_field": [4, 5]
        });

        let result = merge_json_values(base, additional);

        assert_eq!(
            result,
            json!({
                "array_field": [4, 5],
                "other": "value"
            })
        );
    }

    #[test]
    fn test_merge_json_values_deep_nesting() {
        let base = json!({
            "level1": {
                "level2": {
                    "level3": {
                        "keep": true,
                        "override": "original"
                    }
                }
            }
        });
        let additional = json!({
            "level1": {
                "level2": {
                    "level3": {
                        "override": "new_value",
                        "added": "extra"
                    }
                }
            }
        });

        let result = merge_json_values(base, additional);

        assert_eq!(
            result,
            json!({
                "level1": {
                    "level2": {
                        "level3": {
                            "keep": true,
                            "override": "new_value",
                            "added": "extra"
                        }
                    }
                }
            })
        );
    }

    #[test]
    fn test_merge_json_values_different_types_at_same_key() {
        let base = json!({
            "field": "string_value"
        });
        let additional = json!({
            "field": {
                "nested": "object"
            }
        });

        let result = merge_json_values(base, additional);

        // Different types should result in complete replacement
        assert_eq!(
            result,
            json!({
                "field": {
                    "nested": "object"
                }
            })
        );
    }

    #[test]
    fn test_merge_json_values_null_values() {
        let base = json!({
            "keep": "value",
            "replace": "old"
        });
        let additional = json!({
            "replace": null,
            "new": null
        });

        let result = merge_json_values(base, additional);

        assert_eq!(
            result,
            json!({
                "keep": "value",
                "replace": null,
                "new": null
            })
        );
    }

    #[test]
    fn test_record_type_from_str() {
        use std::str::FromStr;

        assert_eq!(
            RecordType::from_str("authorization").unwrap(),
            RecordType::Authorization
        );
        assert_eq!(
            RecordType::from_str("recognition").unwrap(),
            RecordType::Recognition
        );
        assert!(RecordType::from_str("invalid").is_err());
    }

    #[test]
    fn test_record_type_display() {
        assert_eq!(RecordType::Authorization.to_string(), "authorization");
        assert_eq!(RecordType::Recognition.to_string(), "recognition");
    }
}
