use crate::{domain::*, storage::repository::TrustRecordQuery};

pub const TR_PK: &str = "TR";
pub const TR_SK_PREFIX: &str = "TR#";

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct TrustRecordKey {
    authority_id: AuthorityId,
    action: Action,
    resource: Resource,
    entity_id: EntityId,
}

impl TrustRecordKey {
    pub fn pk() -> &'static str {
        TR_PK
    }

    pub fn sk(&self) -> String {
        format!(
            "{}{}#{}#{}#{}",
            TR_SK_PREFIX, self.authority_id, self.action, self.resource, self.entity_id
        )
    }

    pub fn from_record(record: &TrustRecord) -> Self {
        Self {
            authority_id: record.authority_id().clone(),
            action: record.action().clone(),
            resource: record.resource().clone(),
            entity_id: record.entity_id().clone(),
        }
    }

    pub fn from_query(query: &TrustRecordQuery) -> Self {
        Self {
            authority_id: query.authority_id.clone(),
            action: query.action.clone(),
            resource: query.resource.clone(),
            entity_id: query.entity_id.clone(),
        }
    }
}

impl fmt::Display for TrustRecordKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.sk())
    }
}
