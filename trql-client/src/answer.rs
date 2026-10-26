//! What a registry answered, independent of which spec version carried it.
//!
//! The client speaks `registry/authorization` and `registry/recognition` 0.2
//! and falls back to 0.1 for registries that predate it. The two versions spell
//! their members differently (`entityId` / `entity_id`, `evaluatedAt` /
//! `time_evaluated`, …), so returning the generated spec types would make every
//! spec version a breaking change for this crate's users. These types are what
//! a caller acts on; [`SpecVersion`] says which wire form produced them.

use chrono::{DateTime, Utc};

/// The `registry/*` query version a registry answered in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum SpecVersion {
    /// `registry/{authorization,recognition}/0.1`: snake_case.
    V0_1,
    /// `registry/{authorization,recognition}/0.2`: lowerCamelCase, judged
    /// against the record's validity window.
    V0_2,
}

/// A registry's answer to an authorization query.
#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub struct AuthorizationAnswer {
    /// The entity asked about, as echoed by the registry.
    pub entity_id: String,
    /// The authority asked about, as echoed by the registry.
    pub authority_id: String,
    /// The action asked about.
    pub action: String,
    /// The resource asked about.
    pub resource: String,
    /// Whether the authority authorizes the entity for the action on the
    /// resource at [`as_of`](Self::as_of) (or the registry's clock). Absence
    /// of a record, and a record outside its validity window, are both
    /// `false`.
    pub authorized: bool,
    /// The registry's clock when it produced the answer.
    pub evaluated_at: DateTime<Utc>,
    /// The instant the answer holds for, when the query named one.
    pub as_of: Option<DateTime<Utc>>,
    /// The registry's human-readable detail, e.g. why a statement does not
    /// hold. Advisory: decide on [`authorized`](Self::authorized).
    pub message: Option<String>,
    /// Which spec version carried the answer.
    pub version: SpecVersion,
}

/// A registry's answer to a recognition query.
#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub struct RecognitionAnswer {
    /// The entity asked about, as echoed by the registry.
    pub entity_id: String,
    /// The authority asked about, as echoed by the registry.
    pub authority_id: String,
    /// The action asked about.
    pub action: String,
    /// The resource asked about.
    pub resource: String,
    /// Whether the authority recognizes the entity for the action on the
    /// resource at [`as_of`](Self::as_of) (or the registry's clock).
    pub recognized: bool,
    /// The registry's clock when it produced the answer.
    pub evaluated_at: DateTime<Utc>,
    /// The instant the answer holds for, when the query named one.
    pub as_of: Option<DateTime<Utc>>,
    /// The registry's human-readable detail. Advisory.
    pub message: Option<String>,
    /// Which spec version carried the answer.
    pub version: SpecVersion,
}
