use crate::{domain::*, storage::repository::TrustRecordQuery};

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct TrustRecordKey {
    entity_id: EntityId,
    authority_id: AuthorityId,
    action: Action,
    resource: Resource,
}

impl fmt::Display for TrustRecordKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}|{}|{}|{}",
            self.entity_id, self.authority_id, self.action, self.resource
        )
    }
}

impl TrustRecordKey {
    pub fn from_record(record: &TrustRecord) -> Self {
        Self {
            entity_id: record.entity_id().clone(),
            authority_id: record.authority_id().clone(),
            action: record.action().clone(),
            resource: record.resource().clone(),
        }
    }

    pub fn from_query(query: &TrustRecordQuery) -> Self {
        Self {
            entity_id: query.entity_id.clone(),
            authority_id: query.authority_id.clone(),
            action: query.action.clone(),
            resource: query.resource.clone(),
        }
    }
}
