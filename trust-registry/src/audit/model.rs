use crate::domain::{Action, AuthorityId, EntityId, Resource, TrustRecord};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::fmt;

/// The rendered `role` of an entry whose actor is a proven admin.
pub const AUDIT_ROLE_ADMIN: &str = "ADMIN";
/// The rendered `role` of an entry with no proven actor: a refusal before the
/// issuer's proof verified, or a summary of such refusals.
pub const AUDIT_ROLE_UNPROVEN: &str = "UNPROVEN";

#[derive(Debug, Clone, Serialize, Deserialize)]
#[non_exhaustive]
pub struct AuditLog {
    pub operation: AuditOperation,
    /// The proven issuer, or empty. It only ever names a DID whose proof
    /// verified.
    pub actor: String,
    /// What the actor was proven to be.
    #[serde(default)]
    pub role: AuditRole,
    pub status: AuditStatus,
    pub resource: AuditResource,
    /// Why a write failed or was refused: the error document's code and
    /// message. `None` for a success, a replay or an in-flight duplicate.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<AuditReason>,
    pub thread_id: Option<String>,
    /// The Trust Task type slug the entry is about, e.g. `registry/record/put`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub task: Option<String>,
    /// The operation document's `id`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub document_id: Option<String>,
    /// Who the document claimed to come from, when it was refused before its
    /// issuer was proven. `actor` is then empty: it only ever names a DID whose
    /// proof verified.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub claimed_actor: Option<String>,
    /// The sender the transport authenticated (a DIDComm authcrypt sender, a
    /// TSP VID), when there was one. Unlike `claimed_actor` this was checked;
    /// unlike `actor` it does not mean the document's proof verified.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authenticated_sender: Option<String>,
    /// SHA-256 (hex) over the canonical JSON of the whole operation document,
    /// proof included: the key the registry's replay record uses. An archived
    /// copy of the signed document can be matched to this entry by it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub document_digest: Option<String>,
    /// The verification method of the document's proof, once the proof has
    /// verified: which of the actor's keys approved the write.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verification_method: Option<String>,
    /// The proof's `created` time, once the proof has verified.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proof_created: Option<chrono::DateTime<Utc>>,
    /// The entry's position in this process's audit sequence, starting at 1.
    /// Assigned by `BoundedAuditLogger` as it passes the entry on; `None`
    /// before then.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sequence: Option<u64>,
    pub timestamp: chrono::DateTime<Utc>,
}

/// What the entry's actor was proven to be.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
#[non_exhaustive]
pub enum AuditRole {
    /// The actor's proof verified and it is on the admin list.
    Admin,
    /// No actor was proven.
    #[default]
    Unproven,
}

impl fmt::Display for AuditRole {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Admin => f.write_str(AUDIT_ROLE_ADMIN),
            Self::Unproven => f.write_str(AUDIT_ROLE_UNPROVEN),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
#[non_exhaustive]
pub enum AuditStatus {
    /// The document was executed and succeeded.
    Success,
    /// The document was executed, or refused after its issuer was proven, and
    /// failed.
    Failure,
    /// The document was refused: its issuer was not proven, or may not do
    /// this.
    Unauthorized,
    /// The document had already been executed. Its stored outcome was
    /// returned and nothing was executed again; the entry of the execution
    /// has the same `document_digest`.
    Replayed,
    /// An identical document was being executed when this copy arrived. Nothing
    /// was executed for this copy, which was answered with a retryable
    /// refusal; the entry of the execution records the outcome.
    DuplicateInFlight,
}

impl fmt::Display for AuditStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Success => write!(f, "SUCCESS"),
            Self::Failure => write!(f, "FAILURE"),
            Self::Unauthorized => write!(f, "UNAUTHORIZED"),
            Self::Replayed => write!(f, "REPLAYED"),
            Self::DuplicateInFlight => write!(f, "DUPLICATE_IN_FLIGHT"),
        }
    }
}

/// Why an entry failed or was refused.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditReason {
    /// The error code (`permissionDenied`, `proofInvalid`, ...), when there is
    /// one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub code: Option<String>,
    /// The human-readable detail.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

impl AuditReason {
    /// A reason with an error code and, optionally, a message.
    pub fn coded(code: impl Into<String>, message: Option<String>) -> Self {
        Self {
            code: Some(code.into()),
            message,
        }
    }

    /// A reason that is only text.
    pub fn text(message: impl Into<String>) -> Self {
        Self {
            code: None,
            message: Some(message.into()),
        }
    }
}

/// `code: message`, or whichever of the two there is.
impl fmt::Display for AuditReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match (&self.code, &self.message) {
            (Some(code), Some(message)) => write!(f, "{code}: {message}"),
            (Some(text), None) | (None, Some(text)) => f.write_str(text),
            (None, None) => Ok(()),
        }
    }
}

impl From<String> for AuditReason {
    fn from(message: String) -> Self {
        Self::text(message)
    }
}

impl From<&str> for AuditReason {
    fn from(message: &str) -> Self {
        Self::text(message)
    }
}

/// Builds an [`AuditLog`]. The operation is given up front and the status by
/// the `build_*` method that finishes the entry, so neither has a default.
pub struct AuditLogBuilder {
    audit_log: AuditLog,
}

impl AuditLogBuilder {
    pub fn new(operation: AuditOperation) -> Self {
        Self {
            audit_log: AuditLog {
                operation,
                actor: String::new(),
                role: AuditRole::Unproven,
                // Overwritten by every `build_*`.
                status: AuditStatus::Failure,
                resource: AuditResource::empty(),
                reason: None,
                thread_id: None,
                task: None,
                document_id: None,
                claimed_actor: None,
                authenticated_sender: None,
                document_digest: None,
                verification_method: None,
                proof_created: None,
                sequence: None,
                timestamp: Utc::now(),
            },
        }
    }

    /// The proven issuer. Its [`role`](Self::role) is set separately.
    pub fn actor(mut self, actor: impl Into<String>) -> Self {
        self.audit_log.actor = actor.into();
        self
    }

    pub fn role(mut self, role: AuditRole) -> Self {
        self.audit_log.role = role;
        self
    }

    pub fn resource(mut self, resource: AuditResource) -> Self {
        self.audit_log.resource = resource;
        self
    }

    pub fn thread_id(mut self, thread_id: Option<String>) -> Self {
        self.audit_log.thread_id = thread_id;
        self
    }

    pub fn task(mut self, task: impl Into<String>) -> Self {
        self.audit_log.task = Some(task.into());
        self
    }

    pub fn document_id(mut self, document_id: impl Into<String>) -> Self {
        self.audit_log.document_id = Some(document_id.into());
        self
    }

    pub fn claimed_actor(mut self, claimed_actor: Option<String>) -> Self {
        self.audit_log.claimed_actor = claimed_actor;
        self
    }

    pub fn authenticated_sender(mut self, authenticated_sender: Option<String>) -> Self {
        self.audit_log.authenticated_sender = authenticated_sender;
        self
    }

    pub fn document_digest(mut self, document_digest: Option<String>) -> Self {
        self.audit_log.document_digest = document_digest;
        self
    }

    /// The proof's verification method and `created` time. Set only for a
    /// proof that verified.
    pub fn proof(
        mut self,
        verification_method: Option<String>,
        created: Option<chrono::DateTime<Utc>>,
    ) -> Self {
        self.audit_log.verification_method = verification_method;
        self.audit_log.proof_created = created;
        self
    }

    fn finish(mut self, status: AuditStatus, reason: Option<AuditReason>) -> AuditLog {
        self.audit_log.status = status;
        self.audit_log.reason = reason;
        self.audit_log.timestamp = Utc::now();
        self.audit_log
    }

    pub fn build_success(self) -> AuditLog {
        self.finish(AuditStatus::Success, None)
    }

    pub fn build_failure(self, error: impl Into<AuditReason>) -> AuditLog {
        self.finish(AuditStatus::Failure, Some(error.into()))
    }

    pub fn build_unauthorized(self, reason: impl Into<AuditReason>) -> AuditLog {
        self.finish(AuditStatus::Unauthorized, Some(reason.into()))
    }

    /// A duplicate answered from the replay record: nothing was executed.
    pub fn build_replayed(self) -> AuditLog {
        self.finish(AuditStatus::Replayed, None)
    }

    /// A duplicate that arrived while the original was being executed:
    /// nothing was executed for it.
    pub fn build_duplicate_in_flight(self) -> AuditLog {
        self.finish(AuditStatus::DuplicateInFlight, None)
    }
}

#[async_trait::async_trait]
pub trait AuditLogger: Send + Sync {
    async fn log(&self, audit_log: AuditLog);
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
#[non_exhaustive]
pub enum AuditOperation {
    Create,
    Update,
    Delete,
    Read,
    List,
    Put,
    Grant,
    Revoke,
    Enable,
    Disable,
    Rotate,
    /// Not an operation on the registry: a count of refusals that were not
    /// recorded individually (`BoundedAuditLogger`).
    Summary,
}

impl fmt::Display for AuditOperation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Create => write!(f, "CREATE"),
            Self::Update => write!(f, "UPDATE"),
            Self::Delete => write!(f, "DELETE"),
            Self::Read => write!(f, "READ"),
            Self::List => write!(f, "LIST"),
            Self::Put => write!(f, "PUT"),
            Self::Grant => write!(f, "GRANT"),
            Self::Revoke => write!(f, "REVOKE"),
            Self::Enable => write!(f, "ENABLE"),
            Self::Disable => write!(f, "DISABLE"),
            Self::Rotate => write!(f, "ROTATE"),
            Self::Summary => write!(f, "SUMMARY"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditResource {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub entity_id: Option<EntityId>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authority_id: Option<AuthorityId>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub action: Option<Action>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resource: Option<Resource>,
}

impl AuditResource {
    pub fn new(
        entity_id: Option<EntityId>,
        authority_id: Option<AuthorityId>,
        action: Option<Action>,
        resource: Option<Resource>,
    ) -> Self {
        Self {
            entity_id,
            authority_id,
            action,
            resource,
        }
    }

    pub fn from_record(record: &TrustRecord) -> Self {
        Self {
            entity_id: Some(record.entity_id().clone()),
            authority_id: Some(record.authority_id().clone()),
            action: Some(record.action().clone()),
            resource: Some(record.resource().clone()),
        }
    }

    pub fn empty() -> Self {
        Self {
            entity_id: None,
            authority_id: None,
            action: None,
            resource: None,
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use crate::domain::RecordType;

    use super::*;

    #[test]
    fn test_audit_resource_from_record() {
        use crate::domain::TrustRecordBuilder;

        let record = TrustRecordBuilder::new()
            .entity_id(EntityId::new("entity-1"))
            .authority_id(AuthorityId::new("authority-1"))
            .action(Action::new("action-1"))
            .resource(Resource::new("resource-1"))
            .recognized(true)
            .authorized(true)
            .record_type(RecordType::Authorization)
            .build()
            .unwrap();

        let resource = AuditResource::from_record(&record);

        assert_eq!(resource.entity_id.as_ref().unwrap().as_str(), "entity-1");
        assert_eq!(
            resource.authority_id.as_ref().unwrap().as_str(),
            "authority-1"
        );
        assert_eq!(resource.action.as_ref().unwrap().as_str(), "action-1");
        assert_eq!(resource.resource.as_ref().unwrap().as_str(), "resource-1");
    }
}
