//! Planning writes for the backends that key records by string (Redis,
//! DynamoDB, fjall).
//!
//! Each record lives under [`TrustRecordKey::sk`]. A record an older release
//! wrote may still live under [`TrustRecordKey::legacy_sk`], the identifiers
//! joined unescaped. That earlier string can equal another record's current
//! key: record B with resource `x%23y` was stored at `TR#…#x%23y#…`, which is
//! the current key of record A with resource `x#y`. So no operation may act on
//! a key without first checking whose record is stored there.
//!
//! The planners here read what they need through a [`KeyedReader`] and return
//! the writes as [`Op`]s, each with the state its key was read in. A backend
//! applies them as one atomic unit that fails if any key changed since it was
//! read (a fjall batch under the store's write lock, a Redis `WATCH`ed
//! `MULTI`/`EXEC`, a DynamoDB `TransactWriteItems` with conditions), then
//! re-plans. Because the unit is atomic, a crash leaves either the old state
//! or the new one.

use crate::domain::TrustRecord;
use crate::domain::key::{TrustRecordKey, verified_record};
use crate::storage::repository::RepositoryError;

/// The longest chain of records moved out of the way for one write.
///
/// Each record in a chain has a longer key than the one before it, so a chain
/// always ends; this bounds the work one write can cause.
pub const MAX_DISPLACEMENT: usize = 16;

/// What a key held when it was read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Expect {
    Absent,
    /// The record with these identifiers.
    Holds(TrustRecordKey),
}

#[derive(Debug, Clone, PartialEq)]
pub enum Action {
    Put(TrustRecord),
    Delete,
}

/// One write, valid only while `storage_key` still holds what `expect` says.
#[derive(Debug, Clone, PartialEq)]
pub struct Op {
    pub storage_key: String,
    pub expect: Expect,
    pub action: Action,
}

/// Raw reads for the planners. A backend that applies writes optimistically
/// (Redis) starts watching each key here.
#[async_trait::async_trait]
pub trait KeyedReader: Send {
    async fn read_at(&mut self, storage_key: &str) -> Result<Option<TrustRecord>, RepositoryError>;
}

fn expect_for(stored: &Option<TrustRecord>) -> Expect {
    match stored {
        None => Expect::Absent,
        Some(record) => Expect::Holds(TrustRecordKey::from_record(record)),
    }
}

/// The record `key` names, from its current key or its earlier one, with the
/// key it was found under. Records stored for other identifiers are skipped.
pub async fn lookup(
    reader: &mut impl KeyedReader,
    key: &TrustRecordKey,
) -> Result<Option<(String, TrustRecord)>, RepositoryError> {
    for storage_key in std::iter::once(key.sk()).chain(key.legacy_sk()) {
        let stored = reader.read_at(&storage_key).await?;
        if let Some(record) = verified_record(key, &storage_key, stored) {
            return Ok(Some((storage_key, record)));
        }
    }
    Ok(None)
}

/// Clear `key`'s current key for its record.
///
/// When that key holds another record (stored there under its earlier key),
/// copy that record to its own current key first, and so on along the chain.
/// Returns the copies, deepest first, and what `key.sk()` holds.
async fn make_room(
    reader: &mut impl KeyedReader,
    key: &TrustRecordKey,
) -> Result<(Vec<Op>, Expect), RepositoryError> {
    let first = reader.read_at(&key.sk()).await?;
    let slot_expect = expect_for(&first);
    let mut copies = Vec::new();
    let mut displaced = match first {
        Some(record) if !key.identifies(&record) => Some(record),
        _ => None,
    };
    while let Some(record) = displaced.take() {
        if copies.len() == MAX_DISPLACEMENT {
            return Err(RepositoryError::ValidationError(format!(
                "writing {} would move more than {MAX_DISPLACEMENT} records stored under the \
                 earlier key format",
                key.sk()
            )));
        }
        let own = TrustRecordKey::from_record(&record);
        let target = own.sk();
        let stored = reader.read_at(&target).await?;
        match &stored {
            // Already moved: the copy under the earlier key is stale.
            Some(existing) if own.identifies(existing) => {}
            _ => {
                copies.push(Op {
                    storage_key: target,
                    expect: expect_for(&stored),
                    action: Action::Put(record),
                });
                displaced = stored;
            }
        }
    }
    copies.reverse();
    Ok((copies, slot_expect))
}

pub async fn plan_create(
    reader: &mut impl KeyedReader,
    record: &TrustRecord,
) -> Result<Vec<Op>, RepositoryError> {
    let key = TrustRecordKey::from_record(record);
    if lookup(reader, &key).await?.is_some() {
        return Err(RepositoryError::RecordAlreadyExists(format!(
            "Record already exists: {}",
            key.sk()
        )));
    }
    let (mut ops, slot_expect) = make_room(reader, &key).await?;
    ops.push(Op {
        storage_key: key.sk(),
        expect: slot_expect,
        action: Action::Put(record.clone()),
    });
    Ok(ops)
}

/// Replace the record. One found under its earlier key moves to its current
/// key in the same unit, so the two never disagree.
pub async fn plan_update(
    reader: &mut impl KeyedReader,
    record: &TrustRecord,
) -> Result<Vec<Op>, RepositoryError> {
    let key = TrustRecordKey::from_record(record);
    let Some((found_under, _)) = lookup(reader, &key).await? else {
        return Err(RepositoryError::RecordNotFound(format!(
            "Record not found: {}",
            key.sk()
        )));
    };
    let current = key.sk();
    if found_under == current {
        return Ok(vec![Op {
            storage_key: current,
            expect: Expect::Holds(key),
            action: Action::Put(record.clone()),
        }]);
    }
    let (mut ops, slot_expect) = make_room(reader, &key).await?;
    ops.push(Op {
        storage_key: current,
        expect: slot_expect,
        action: Action::Put(record.clone()),
    });
    ops.push(Op {
        storage_key: found_under,
        expect: Expect::Holds(key),
        action: Action::Delete,
    });
    Ok(ops)
}

/// Remove every copy of the record, and nothing stored for other identifiers.
pub async fn plan_delete(
    reader: &mut impl KeyedReader,
    key: &TrustRecordKey,
) -> Result<Vec<Op>, RepositoryError> {
    let mut ops = Vec::new();
    for storage_key in key.legacy_sk().into_iter().chain(std::iter::once(key.sk())) {
        let stored = reader.read_at(&storage_key).await?;
        if verified_record(key, &storage_key, stored).is_some() {
            ops.push(Op {
                storage_key,
                expect: Expect::Holds(key.clone()),
                action: Action::Delete,
            });
        }
    }
    if ops.is_empty() {
        return Err(RepositoryError::RecordNotFound(format!(
            "Record not found: {}",
            key.sk()
        )));
    }
    Ok(ops)
}

/// A [`KeyedReader`] over an in-memory map, for tests.
#[cfg(test)]
pub(crate) struct MapReader<'a>(pub &'a std::collections::HashMap<String, TrustRecord>);

#[cfg(test)]
#[async_trait::async_trait]
impl KeyedReader for MapReader<'_> {
    async fn read_at(&mut self, storage_key: &str) -> Result<Option<TrustRecord>, RepositoryError> {
        Ok(self.0.get(storage_key).cloned())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::{
        Action as RecordAction, AuthorityId, EntityId, RecordType, Resource, TrustRecordBuilder,
    };
    use std::collections::HashMap;

    fn record(resource: &str) -> TrustRecord {
        TrustRecordBuilder::new()
            .entity_id(EntityId::new("did:e"))
            .authority_id(AuthorityId::new("did:a"))
            .action(RecordAction::new("act"))
            .resource(Resource::new(resource))
            .recognized(true)
            .authorized(true)
            .record_type(RecordType::Authorization)
            .build()
            .expect("valid record")
    }

    fn apply(store: &mut HashMap<String, TrustRecord>, ops: Vec<Op>) {
        for op in ops {
            let current = store.get(&op.storage_key).map(TrustRecordKey::from_record);
            match &op.expect {
                Expect::Absent => assert!(current.is_none(), "{op:?}"),
                Expect::Holds(key) => assert_eq!(current.as_ref(), Some(key), "{op:?}"),
            }
            match op.action {
                Action::Put(record) => {
                    store.insert(op.storage_key, record);
                }
                Action::Delete => {
                    store.remove(&op.storage_key);
                }
            }
        }
    }

    #[tokio::test]
    async fn a_chain_of_displaced_records_is_copied_deepest_first() {
        // A's current key is B's earlier key; B's current key is C's earlier key.
        let a = record("x#y");
        let b = record("x%23y");
        let c = record("x%2523y");
        let mut store = HashMap::new();
        let b_legacy = TrustRecordKey::from_record(&b)
            .legacy_sk()
            .expect("differs");
        let c_legacy = TrustRecordKey::from_record(&c)
            .legacy_sk()
            .expect("differs");
        assert_eq!(b_legacy, TrustRecordKey::from_record(&a).sk());
        assert_eq!(c_legacy, TrustRecordKey::from_record(&b).sk());
        store.insert(b_legacy.clone(), b.clone());
        store.insert(c_legacy.clone(), c.clone());

        let ops = plan_create(&mut MapReader(&store), &a).await.expect("plan");
        apply(&mut store, ops.clone());
        let targets: Vec<_> = ops.iter().map(|op| op.storage_key.clone()).collect();
        assert_eq!(
            targets,
            vec![
                TrustRecordKey::from_record(&c).sk(),
                TrustRecordKey::from_record(&b).sk(),
                TrustRecordKey::from_record(&a).sk(),
            ]
        );
        for wanted in [&a, &b, &c] {
            let found = lookup(&mut MapReader(&store), &TrustRecordKey::from_record(wanted))
                .await
                .expect("lookup");
            assert_eq!(found.map(|(_, record)| record).as_ref(), Some(wanted));
        }
    }
}
