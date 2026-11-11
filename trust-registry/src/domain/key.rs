use std::collections::HashMap;

use crate::{domain::*, storage::repository::TrustRecordQuery};

pub const TR_PK: &str = "TR";
pub const TR_SK_PREFIX: &str = "TR#";

/// Separator between the four identifiers in a storage key.
const SEPARATOR: char = '#';

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct TrustRecordKey {
    authority_id: AuthorityId,
    action: Action,
    resource: Resource,
    entity_id: EntityId,
}

/// Escape one identifier for use in a storage key: `%` becomes `%25` and `#`
/// becomes `%23`, so the separator never appears inside a component and the
/// joined key decodes to exactly one 4-tuple.
///
/// An identifier containing neither character is unchanged, so its key is the
/// same as under the earlier unescaped format.
fn escape_component(component: &str) -> std::borrow::Cow<'_, str> {
    if !component.contains(['%', SEPARATOR]) {
        return std::borrow::Cow::Borrowed(component);
    }
    let mut escaped = String::with_capacity(component.len() + 8);
    for character in component.chars() {
        match character {
            '%' => escaped.push_str("%25"),
            SEPARATOR => escaped.push_str("%23"),
            other => escaped.push(other),
        }
    }
    std::borrow::Cow::Owned(escaped)
}

impl TrustRecordKey {
    pub fn pk() -> &'static str {
        TR_PK
    }

    /// The storage key: `TR#{authority}#{action}#{resource}#{entity}`, each
    /// identifier escaped (see [`escape_component`]) so that distinct records
    /// never share a key.
    pub fn sk(&self) -> String {
        format!(
            "{}{}{SEPARATOR}{}{SEPARATOR}{}{SEPARATOR}{}",
            TR_SK_PREFIX,
            escape_component(self.authority_id.as_str()),
            escape_component(self.action.as_str()),
            escape_component(self.resource.as_str()),
            escape_component(self.entity_id.as_str()),
        )
    }

    /// The key this record had under the earlier format, which joined the
    /// identifiers unescaped, when that differs from [`Self::sk`].
    ///
    /// `None` for every record whose identifiers contain neither `#` nor `%`:
    /// its key never changed. Otherwise the record may still be stored under
    /// this key by an older release, and backends read it from there. Because
    /// the unescaped form is shared by distinct records, anything read from it
    /// must be checked with [`Self::identifies`] before use.
    pub fn legacy_sk(&self) -> Option<String> {
        let legacy = format!(
            "{}{}{SEPARATOR}{}{SEPARATOR}{}{SEPARATOR}{}",
            TR_SK_PREFIX, self.authority_id, self.action, self.resource, self.entity_id
        );
        (legacy != self.sk()).then_some(legacy)
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

    pub fn entity_id(&self) -> &EntityId {
        &self.entity_id
    }

    /// Whether `record` is the record this key names (all four identifiers
    /// equal).
    pub fn identifies(&self, record: &TrustRecord) -> bool {
        record.authority_id() == &self.authority_id
            && record.action() == &self.action
            && record.resource() == &self.resource
            && record.entity_id() == &self.entity_id
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

/// Keep `stored` only if it is the record `key` names.
///
/// A key-value backend returns whatever is stored under the key it was asked
/// for. Under the current format that is always the requested record; under
/// the earlier unescaped format it can be a different record whose
/// identifiers join to the same string. A mismatch is reported and treated as
/// absent, so a lookup never answers with another record.
pub fn verified_record(
    key: &TrustRecordKey,
    storage_key: &str,
    stored: Option<TrustRecord>,
) -> Option<TrustRecord> {
    let record = stored?;
    if key.identifies(&record) {
        return Some(record);
    }
    let stored_under_its_earlier_key =
        TrustRecordKey::from_record(&record).legacy_sk().as_deref() == Some(storage_key);
    if stored_under_its_earlier_key {
        // Expected while records migrate: the string is both this key and
        // another record's earlier-format key.
        tracing::debug!(
            storage_key,
            "record under the earlier key format belongs to different identifiers"
        );
    } else {
        tracing::error!(
            storage_key,
            "stored record's identifiers do not match its key; treating it as absent"
        );
    }
    None
}

/// Collapse a backend listing to one record per identifier 4-tuple.
///
/// While records migrate to the escaped key format, an update writes the new
/// key before removing the old one; if the process stops in between, both
/// copies exist. The copy under the current key ([`TrustRecordKey::sk`]) is
/// the authoritative one.
pub fn dedupe_listing(
    entries: impl IntoIterator<Item = (String, TrustRecord)>,
) -> Vec<TrustRecord> {
    let mut by_key: HashMap<TrustRecordKey, (bool, TrustRecord)> = HashMap::new();
    let mut order: Vec<TrustRecordKey> = Vec::new();
    for (storage_key, record) in entries {
        let key = TrustRecordKey::from_record(&record);
        let current = storage_key == key.sk();
        match by_key.get(&key) {
            Some((true, _)) => {}
            Some((false, _)) if !current => {}
            Some(_) => {
                by_key.insert(key, (current, record));
            }
            None => {
                order.push(key.clone());
                by_key.insert(key, (current, record));
            }
        }
    }
    order
        .into_iter()
        .filter_map(|key| by_key.remove(&key).map(|(_, record)| record))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    fn key(authority: &str, action: &str, resource: &str, entity: &str) -> TrustRecordKey {
        TrustRecordKey {
            authority_id: AuthorityId::new(authority),
            action: Action::new(action),
            resource: Resource::new(resource),
            entity_id: EntityId::new(entity),
        }
    }

    fn record(authority: &str, action: &str, resource: &str, entity: &str) -> TrustRecord {
        TrustRecordBuilder::new()
            .entity_id(EntityId::new(entity))
            .authority_id(AuthorityId::new(authority))
            .action(Action::new(action))
            .resource(Resource::new(resource))
            .recognized(true)
            .authorized(true)
            .record_type(RecordType::Authorization)
            .build()
            .expect("valid record")
    }

    #[test]
    fn identifiers_without_separator_or_escape_keep_their_key() {
        let key = key(
            "did:example:a",
            "issue",
            "https://schema.example/vc",
            "did:example:e",
        );
        assert_eq!(
            key.sk(),
            "TR#did:example:a#issue#https://schema.example/vc#did:example:e"
        );
        assert_eq!(key.legacy_sk(), None);
    }

    #[test]
    fn identifiers_that_joined_to_the_same_string_get_distinct_keys() {
        let first = key("did:a", "sign", "repo#main", "did:e");
        let second = key("did:a", "sign#repo", "main", "did:e");
        assert_eq!(first.legacy_sk(), second.legacy_sk());
        assert_ne!(first.sk(), second.sk());

        let third = key("did:a", "issue", "https://schema.example/vc", "did:x#k1");
        let fourth = key("did:a", "issue", "https://schema.example/vc#did:x", "k1");
        assert_ne!(third.sk(), fourth.sk());
    }

    #[test]
    fn percent_is_escaped_so_an_escape_sequence_cannot_be_imitated() {
        let literal = key("did:a", "act", "x%23y", "did:e");
        let separator = key("did:a", "act", "x#y", "did:e");
        assert_ne!(literal.sk(), separator.sk());
        assert_eq!(literal.sk(), "TR#did:a#act#x%2523y#did:e");
        assert_eq!(separator.sk(), "TR#did:a#act#x%23y#did:e");
        assert_eq!(
            literal.legacy_sk().as_deref(),
            Some("TR#did:a#act#x%23y#did:e")
        );
    }

    #[test]
    fn distinct_tuples_never_share_a_key() {
        // Every 4-tuple over a small alphabet that includes the separator, the
        // escape character and the characters of the escape sequences.
        let alphabet = ['#', '%', '2', '3', 'a'];
        let mut components = vec![String::new()];
        for first in alphabet {
            components.push(first.to_string());
            for second in alphabet {
                components.push(format!("{first}{second}"));
            }
        }
        let mut seen = HashSet::new();
        let mut tuples = 0usize;
        for authority in &components {
            for action in &components {
                for resource in &components {
                    for entity in &components {
                        tuples += 1;
                        assert!(
                            seen.insert(key(authority, action, resource, entity).sk()),
                            "key collision for ({authority:?}, {action:?}, {resource:?}, {entity:?})"
                        );
                    }
                }
            }
        }
        assert_eq!(seen.len(), tuples);
    }

    #[test]
    fn a_record_read_under_the_earlier_key_is_checked_against_the_query() {
        let wanted = key("did:a", "sign#repo", "main", "did:e");
        let stored = record("did:a", "sign", "repo#main", "did:e");
        let legacy = wanted.legacy_sk().expect("legacy key differs");
        assert!(verified_record(&wanted, &legacy, Some(stored.clone())).is_none());

        let owner = TrustRecordKey::from_record(&stored);
        assert_eq!(
            verified_record(&owner, &legacy, Some(stored.clone())),
            Some(stored)
        );
    }

    #[test]
    fn listing_keeps_one_copy_and_prefers_the_current_key() {
        let old = record("did:a", "sign", "repo#main", "did:e").with_authorized(false);
        let new = record("did:a", "sign", "repo#main", "did:e");
        let key = TrustRecordKey::from_record(&new);
        let legacy = key.legacy_sk().expect("legacy key differs");
        let other = record("did:a", "issue", "vc", "did:e");

        for entries in [
            vec![(legacy.clone(), old.clone()), (key.sk(), new.clone())],
            vec![(key.sk(), new.clone()), (legacy.clone(), old.clone())],
        ] {
            let mut entries = entries;
            entries.push((TrustRecordKey::from_record(&other).sk(), other.clone()));
            let listed = dedupe_listing(entries);
            assert_eq!(listed.len(), 2);
            assert!(listed.contains(&new));
            assert!(listed.contains(&other));
        }

        assert_eq!(dedupe_listing(vec![(legacy, old.clone())]), vec![old]);
    }
}
