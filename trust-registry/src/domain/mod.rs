use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::fmt;

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
    context: Context,
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
    ) -> Self {
        Self {
            entity_id,
            authority_id,
            action,
            resource,
            recognized: Some(recognized),
            authorized: Some(authorized),
            context,
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
        if let Some(b) = self.recognized {
            b
        } else {
            false
        }
    }

    pub fn context(&self) -> &Context {
        &self.context
    }

    pub fn is_authorized(&self) -> bool {
        if let Some(b) = self.authorized {
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
}
