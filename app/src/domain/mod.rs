use std::fmt;

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

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
    #[serde(skip_serializing_if = "Option::is_none")]
    recognized: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    assertion_verified: Option<bool>,
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
            recognized: Some(recognized),
            context,
            assertion_verified: Some(assertion_verified),
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
        if let Some(b) = self.recognized {
            b
        } else {
            false
        }
    }

    pub fn context(&self) -> &Context {
        &self.context
    }

    pub fn is_assertion_verified(&self) -> bool {
        if let Some(b) = self.assertion_verified {
            b
        } else {
            false
        }
    }

    /// Merges additional_context into the given one.
    /// additional_context will OVERRIDE the existing one
    pub fn merge_contexts(mut self, additional_context: Context) -> Self {
        let base_context = std::mem::take(&mut self.context);
        self.context = base_context.merge(additional_context);
        self
    }

    pub fn none_assertion_verified(mut self) -> Self {
        self.assertion_verified = None;
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
    assertion_id: Option<AssertionId>,
    recognized: Option<bool>,
    context: Context,
    assertion_verified: Option<bool>,
}

impl TrustRecordBuilder {
    pub fn new() -> Self {
        Self {
            entity_id: None,
            authority_id: None,
            assertion_id: None,
            recognized: None,
            context: Context::empty(),
            assertion_verified: None,
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
        self.recognized = Some(recognized);
        self
    }

    pub fn context(mut self, context: Context) -> Self {
        self.context = context;
        self
    }

    pub fn assertion_verified(mut self, verified: bool) -> Self {
        self.assertion_verified = Some(verified);
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
            AssertionId::new("assertion-789"),
            true,
            true,
            Context::new(json!({
                "original": true,
                "nested": {
                    "keep": true,
                    "override": false
                }
            })),
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
}
