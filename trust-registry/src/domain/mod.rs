use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::fmt;

pub mod key;

/// The one form a party reference is stored, keyed and compared in: a
/// did:scid with its `?src=` locator removed (VTI-KEY-160), anything else as
/// written. The locator says where to resolve the DID, not who it is, so
/// `did:scid:…` and `did:scid:…?src=host` are one identity.
pub fn normalise_reference(reference: String) -> String {
    let stripped = affinidi_did_common::scid::strip_scid_src(&reference);
    if stripped.len() == reference.len() {
        return reference;
    }
    stripped.into_owned()
}

#[cfg(test)]
mod reference_tests {
    use super::*;

    #[test]
    fn a_did_scid_locator_is_dropped_and_anything_else_kept() {
        assert_eq!(
            AuthorityId::new("did:scid:vh:1:abc?src=example.com").as_str(),
            "did:scid:vh:1:abc"
        );
        assert_eq!(
            EntityId::new("did:scid:vh:1:abc?src=example.com#key-1").as_str(),
            "did:scid:vh:1:abc#key-1"
        );
        assert_eq!(
            AuthorityId::new("did:web:example.com?src=x").as_str(),
            "did:web:example.com?src=x"
        );
    }

    /// The validating constructor normalises exactly as `new` does, so a
    /// write through it cannot store a located spelling again.
    #[test]
    fn parse_normalises_party_references_like_new() {
        assert_eq!(
            AuthorityId::parse("did:scid:vh:1:abc?src=example.com")
                .unwrap()
                .as_str(),
            "did:scid:vh:1:abc"
        );
        assert_eq!(
            EntityId::try_from("did:scid:vh:1:abc?src=example.com#key-1")
                .unwrap()
                .as_str(),
            "did:scid:vh:1:abc#key-1"
        );
        // Action and resource are not party references and are kept as is.
        assert_eq!(
            Resource::parse("did:scid:vh:1:abc?src=example.com")
                .unwrap()
                .as_str(),
            "did:scid:vh:1:abc?src=example.com"
        );
    }
}

/// The longest identifier accepted from a client, in bytes.
///
/// Generous enough for any DID in use (long `did:peer:2` and `did:webvh`
/// values included) while bounding what a client can make the registry store
/// as a key or echo in a message.
pub const MAX_IDENTIFIER_BYTES: usize = 2048;

/// Why a client-supplied identifier was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IdentifierError {
    /// The identifier's wire name (`entity_id`, `authority_id`, `action`,
    /// `resource`).
    pub field: &'static str,
    /// What is wrong with it. Describes only the client's own input, so it is
    /// safe to return to the client.
    pub reason: String,
}

impl fmt::Display for IdentifierError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "`{}` {}", self.field, self.reason)
    }
}

impl std::error::Error for IdentifierError {}

/// TRQP v2.0 Identifiers: every identifier is a single RFC 3986 string, and
/// none of the four may be empty (`action`/`resource` by the spec's own rule,
/// `entity_id`/`authority_id` because an empty string identifies nothing).
/// [`MAX_IDENTIFIER_BYTES`] bounds the length.
fn check_identifier(field: &'static str, value: &str) -> Result<(), IdentifierError> {
    let refuse = |reason: String| Err(IdentifierError { field, reason });
    if value.is_empty() {
        return refuse("must not be empty".into());
    }
    if value.len() > MAX_IDENTIFIER_BYTES {
        return refuse(format!("is longer than {MAX_IDENTIFIER_BYTES} bytes"));
    }
    if let Err(e) = fluent_uri::UriRef::parse(value) {
        return refuse(format!("is not an RFC 3986 URI reference: {e}"));
    }
    Ok(())
}

/// The identity normalisation, for identifiers that are not party references.
fn as_is(value: String) -> String {
    value
}

/// Defines one of the four TRQP identifier newtypes.
///
/// Each has two ways in, chosen by where the value comes from:
///
/// - `parse` (and `TryFrom<String>` / `TryFrom<&str>`) for anything a client
///   sent. It enforces the TRQP identifier rules (non-empty, at most
///   [`MAX_IDENTIFIER_BYTES`], RFC 3986). Every `registry/record/put` and
///   every TRQP query, on every binding, goes through it.
/// - `new` and `Deserialize` skip those rules. They are for values the
///   registry already holds: records read back from storage, which may predate
///   the rules and must stay readable, listable and deletable by their exact
///   key; and registry-internal values.
///
/// `parse` and `new` both normalise the same way: the party references
/// (`EntityId`, `AuthorityId`) through [`normalise_reference`], which drops a
/// did:scid `?src=` locator; `Action` and `Resource` not at all. The party
/// references also have `as_written`, which keeps the spelling exactly.
/// `Deserialize` neither validates nor normalises (stored records are read
/// with it).
///
/// There is no `Default`: an empty identifier identifies nothing.
macro_rules! identifier {
    ($(#[$doc:meta])* $name:ident, $field:literal, $normalise:path) => {
        $(#[$doc])*
        #[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
        pub struct $name(String);

        impl $name {
            /// The identifier's wire name, as used in error messages.
            pub const FIELD: &'static str = $field;

            /// Take `id` without checking the TRQP identifier rules (but
            /// normalised as every stored identifier is): for values the
            /// registry already holds. A client-supplied value goes through
            /// [`Self::parse`].
            pub fn new(id: impl Into<String>) -> Self {
                Self($normalise(id.into()))
            }

            /// Validate a client-supplied identifier (non-empty, at most
            /// [`MAX_IDENTIFIER_BYTES`] bytes, an RFC 3986 URI reference),
            /// then normalise it exactly as [`Self::new`] does.
            pub fn parse(id: impl Into<String>) -> Result<Self, IdentifierError> {
                let id = id.into();
                check_identifier($field, &id)?;
                Ok(Self::new(id))
            }

            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl TryFrom<String> for $name {
            type Error = IdentifierError;
            fn try_from(id: String) -> Result<Self, IdentifierError> {
                Self::parse(id)
            }
        }

        impl TryFrom<&str> for $name {
            type Error = IdentifierError;
            fn try_from(id: &str) -> Result<Self, IdentifierError> {
                Self::parse(id)
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "{}", self.0)
            }
        }
    };
    (party $(#[$doc:meta])* $name:ident, $field:literal) => {
        identifier!($(#[$doc])* $name, $field, normalise_reference);

        impl $name {
            /// The reference exactly as written, not normalised: only for
            /// reaching a record an earlier release stored with a did:scid
            /// `?src=` locator.
            pub fn as_written(id: impl Into<String>) -> Self {
                Self(id.into())
            }
        }
    };
}

identifier!(party
    /// The entity a statement is about (`entity_id`). A did:scid reference is
    /// kept without its `?src=` locator ([`normalise_reference`]).
    EntityId,
    "entity_id"
);
identifier!(party
    /// The authority that makes a statement (`authority_id`). A did:scid
    /// reference is kept without its `?src=` locator ([`normalise_reference`]).
    AuthorityId,
    "authority_id"
);
identifier!(
    /// What the entity is authorized to do (`action`).
    Action,
    "action",
    as_is
);
identifier!(
    /// What the action applies to (`resource`).
    Resource,
    "resource",
    as_is
);

/// The four identifiers of a TRQP query, each validated (and normalised) with
/// its `parse`.
pub fn parse_ids(
    entity_id: &str,
    authority_id: &str,
    action: &str,
    resource: &str,
) -> Result<(EntityId, AuthorityId, Action, Resource), IdentifierError> {
    Ok((
        EntityId::parse(entity_id)?,
        AuthorityId::parse(authority_id)?,
        Action::parse(action)?,
        Resource::parse(resource)?,
    ))
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

    /// Why a record that exists is outside its window at this instant.
    /// `None` when the record is in its window or absent.
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

    /// The answer `record` gives to `question` as of this evaluation, which
    /// must have been made of that record.
    ///
    /// The one place a TRQP answer is decided, shared by every surface (the
    /// HTTP endpoints, the `registry/*` Trust Tasks and the legacy DIDComm
    /// `trqp/1.0` protocol), so they cannot disagree. The statement holds
    /// only when the record is inside its window **and** stores `true` for
    /// the flag asked about; a stored `false`, or no stored value at all,
    /// answers `false`. The `message` follows the answer: the positive
    /// sentence only when it holds, otherwise a negative one with the reason.
    pub fn answer(&self, record: &TrustRecord, question: Question) -> Answer {
        let stored = match question {
            Question::Recognized => record.recognized_value(),
            Question::Authorized => record.authorized_value(),
        };
        let reason = match (self.out_of_window_reason(record), stored) {
            (Some(reason), _) => Some(reason),
            (None, Some(true)) => None,
            (None, Some(false)) => Some(format!("the record states {question} false")),
            (None, None) => Some(format!("the record does not state {question}")),
        };
        let (entity, authority) = (record.entity_id(), record.authority_id());
        let statement = match question {
            Question::Authorized => format!(
                "authorized to {}+{} by {authority}",
                record.action(),
                record.resource()
            ),
            Question::Recognized => format!("recognized by {authority}"),
        };
        match reason {
            None => Answer {
                holds: true,
                message: format!("{entity} {statement}"),
            },
            Some(reason) => Answer {
                holds: false,
                message: format!("{entity} not {statement}: {reason}"),
            },
        }
    }
}

/// Which of the two TRQP questions a query asks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Question {
    /// Is the entity recognized by the authority?
    Recognized,
    /// Is the entity authorized by the authority for the action on the
    /// resource?
    Authorized,
}

impl Question {
    /// The flag's wire name: `recognized` or `authorized`.
    pub fn flag(self) -> &'static str {
        match self {
            Self::Recognized => "recognized",
            Self::Authorized => "authorized",
        }
    }
}

impl fmt::Display for Question {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.flag())
    }
}

/// A record's answer to a TRQP question (see [`Evaluation::answer`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Answer {
    /// Whether the statement holds: the value of `recognized` /
    /// `authorized` in the response.
    pub holds: bool,
    /// The advisory human-readable `message`, consistent with `holds`.
    pub message: String,
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

    /// The identifiers vtc-service sends (and other typical ones) must keep
    /// working: relative references like `issue` are RFC 3986 strings.
    #[test]
    fn typical_identifiers_parse() {
        for id in [
            "did:webvh:QmHash:example.com%3A8080:path",
            "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK",
            "did:example:entity#key-1",
            "https://example.com/schemas/vc?x=1",
            "recognise",
            "trust-graph",
            "auth-service-A",
        ] {
            assert!(EntityId::parse(id).is_ok(), "{id}");
            assert!(Resource::try_from(id).is_ok(), "{id}");
        }
        let longest = "a".repeat(MAX_IDENTIFIER_BYTES);
        assert!(Action::parse(longest).is_ok());
    }

    #[test]
    fn invalid_identifiers_are_refused_and_named() {
        let too_long = "a".repeat(MAX_IDENTIFIER_BYTES + 1);
        for (bad, says) in [
            ("", "must not be empty"),
            ("has spaces", "RFC 3986"),
            ("<angle>", "RFC 3986"),
            (too_long.as_str(), "longer than"),
        ] {
            let err = AuthorityId::parse(bad).unwrap_err();
            assert_eq!(err.field, "authority_id");
            let text = err.to_string();
            assert!(text.starts_with("`authority_id`"), "{text}");
            assert!(text.contains(says), "{text}");
        }
        assert!(parse_ids("e", "a", "x", "").is_err());
    }

    /// Records stored before the identifier rules must stay readable (and so
    /// listable and deletable): deserialising does not validate.
    #[test]
    fn a_stored_record_with_a_non_conforming_identifier_still_deserializes() {
        let r: TrustRecord = serde_json::from_value(json!({
            "entity_id": "has spaces <x>", "authority_id": "", "action": "x",
            "resource": "r", "authorized": true, "record_type": "authorization"
        }))
        .unwrap();
        assert_eq!(r.entity_id().as_str(), "has spaces <x>");
        assert_eq!(r.authority_id().as_str(), "");
    }

    fn flags(recognized: Option<bool>, authorized: Option<bool>) -> TrustRecord {
        let mut builder = TrustRecordBuilder::new()
            .entity_id(EntityId::new("did:e"))
            .authority_id(AuthorityId::new("did:a"))
            .action(Action::new("sign"))
            .resource(Resource::new("repo"))
            .record_type(RecordType::Authorization);
        if let Some(r) = recognized {
            builder = builder.recognized(r);
        }
        if let Some(a) = authorized {
            builder = builder.authorized(a);
        }
        builder.build().unwrap()
    }

    #[test]
    fn the_answer_holds_only_for_a_stored_true_in_window() {
        let now = at("2026-06-01T00:00:00Z");
        let answer = |r: &TrustRecord, q| Evaluation::of(Some(r), None, now).answer(r, q);

        let yes = flags(Some(true), Some(true));
        assert_eq!(
            answer(&yes, Question::Authorized),
            Answer {
                holds: true,
                message: "did:e authorized to sign+repo by did:a".into()
            }
        );
        assert_eq!(
            answer(&yes, Question::Recognized).message,
            "did:e recognized by did:a"
        );

        let revoked = flags(Some(false), Some(false));
        let a = answer(&revoked, Question::Authorized);
        assert!(!a.holds);
        assert_eq!(
            a.message,
            "did:e not authorized to sign+repo by did:a: the record states authorized false"
        );
        let r = answer(&revoked, Question::Recognized);
        assert!(!r.holds);
        assert!(
            r.message.starts_with("did:e not recognized by did:a"),
            "{r:?}"
        );

        let silent = flags(None, None);
        for q in [Question::Authorized, Question::Recognized] {
            let a = answer(&silent, q);
            assert!(!a.holds);
            assert!(a.message.contains(&format!("does not state {q}")), "{a:?}");
        }
    }

    #[test]
    fn out_of_window_the_answer_is_false_whatever_is_stored() {
        let r = windowed(Some("2026-01-01T00:00:00Z"), Some("2027-01-01T00:00:00Z"));
        let a = Evaluation::of(
            Some(&r),
            Some(at("2027-06-01T00:00:00Z")),
            at("2027-06-01T00:00:00Z"),
        )
        .answer(&r, Question::Authorized);
        assert!(!a.holds);
        assert!(a.message.contains("stopped being valid"), "{a:?}");
    }
}
