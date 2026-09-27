use serde::{Deserialize, Serialize};
use serde_json::json;
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
}

impl Default for Context {
    fn default() -> Self {
        Self::empty()
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
        }
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
        }
    }
}

impl std::error::Error for TrustRecordError {}

#[cfg(test)]
mod tests {
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
