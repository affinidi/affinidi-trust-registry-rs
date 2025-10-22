use std::fmt;

use serde::{Deserialize, Serialize};

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
pub struct AssertionId(String);

impl AssertionId {
    pub fn new(id: impl Into<String>) -> Self {
        Self(id.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for AssertionId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Context(serde_json::Value);

impl Context {
    pub fn empty() -> Self {
        Self(serde_json::Value::Object(serde_json::Map::new()))
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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustRecordIds {
    entity_id: EntityId,
    authority_id: AuthorityId,
    assertion_id: AssertionId,
}

impl TrustRecordIds {
    pub fn entity_id(&self) -> &EntityId {
        &self.entity_id
    }

    pub fn authority_id(&self) -> &AuthorityId {
        &self.authority_id
    }

    pub fn assertion_id(&self) -> &AssertionId {
        &self.assertion_id
    }

    pub fn into_parts(self) -> (EntityId, AuthorityId, AssertionId) {
        let Self {
            entity_id,
            authority_id,
            assertion_id,
        } = self;

        (entity_id, authority_id, assertion_id)
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TrustRecord {
    entity_id: EntityId,
    authority_id: AuthorityId,
    assertion_id: AssertionId,
    recognized: bool,
    assertion_verified: bool,
    context: Context,
}

impl TrustRecord {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        entity_id: EntityId,
        authority_id: AuthorityId,
        assertion_id: AssertionId,
        recognized: bool,
        assertion_verified: bool,
        context: Context,
    ) -> Self {
        Self {
            entity_id,
            authority_id,
            assertion_id,
            recognized,
            context,
            assertion_verified,
        }
    }

    pub fn entity_id(&self) -> &EntityId {
        &self.entity_id
    }

    pub fn authority_id(&self) -> &AuthorityId {
        &self.authority_id
    }

    pub fn assertion_id(&self) -> &AssertionId {
        &self.assertion_id
    }

    pub fn is_recognized(&self) -> bool {
        self.recognized
    }

    pub fn context(&self) -> &Context {
        &self.context
    }

    pub fn is_assertion_verified(&self) -> bool {
        self.assertion_verified
    }
}

pub struct TrustRecordBuilder {
    entity_id: Option<EntityId>,
    authority_id: Option<AuthorityId>,
    assertion_id: Option<AssertionId>,
    recognized: bool,
    context: Context,
    assertion_verified: bool,
}

impl TrustRecordBuilder {
    pub fn new() -> Self {
        Self {
            entity_id: None,
            authority_id: None,
            assertion_id: None,
            recognized: false,
            context: Context::empty(),
            assertion_verified: false,
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

    pub fn assertion_id(mut self, id: AssertionId) -> Self {
        self.assertion_id = Some(id);
        self
    }

    pub fn recognized(mut self, recognized: bool) -> Self {
        self.recognized = recognized;
        self
    }

    pub fn context(mut self, context: Context) -> Self {
        self.context = context;
        self
    }

    pub fn assertion_verified(mut self, verified: bool) -> Self {
        self.assertion_verified = verified;
        self
    }

    pub fn build(self) -> Result<TrustRecord, TrustRecordError> {
        Ok(TrustRecord {
            entity_id: self.entity_id.ok_or(TrustRecordError::MissingEntityId)?,
            authority_id: self
                .authority_id
                .ok_or(TrustRecordError::MissingAuthorityId)?,
            assertion_id: self
                .assertion_id
                .ok_or(TrustRecordError::MissingAssertionId)?,
            assertion_verified: self.assertion_verified,
            recognized: self.recognized,
            context: self.context,
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
    MissingAssertionId,
    MissingTimeRequested,
    MissingTimeEvaluated,
}

impl fmt::Display for TrustRecordError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingEntityId => write!(f, "Entity ID is required"),
            Self::MissingAuthorityId => write!(f, "Authority ID is required"),
            Self::MissingAssertionId => write!(f, "Assertion ID is required"),
            Self::MissingTimeRequested => write!(f, "Time requested is required"),
            Self::MissingTimeEvaluated => write!(f, "Time evaluated is required"),
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
            .assertion_id(AssertionId::new("assertion-789"))
            .recognized(true)
            .assertion_verified(true)
            .build()
            .unwrap();

        assert_eq!(record.entity_id().as_str(), "entity-123");
    }

    #[test]
    fn test_builder_missing_fields() {
        let result = TrustRecordBuilder::new()
            .entity_id(EntityId::new("entity-123"))
            .build();

        assert!(result.is_err());
    }
}
