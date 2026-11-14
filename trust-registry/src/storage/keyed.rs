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
/// always ends; this bounds the work one write can cause. It also keeps a
/// write's atomic unit within DynamoDB's transaction limit: at most this many
/// copies plus the record itself and the removal of its earlier copy, each
/// item at most 400 KB, is under 4 MB.
pub const MAX_DISPLACEMENT: usize = 8;

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

    /// Read two keys as of one point in time, so a write that moves a record
    /// from one to the other between two reads cannot make it look absent.
    /// The default reads them one after the other; backends override it.
    async fn read_pair(
        &mut self,
        first: &str,
        second: &str,
    ) -> Result<(Option<TrustRecord>, Option<TrustRecord>), RepositoryError> {
        let first = self.read_at(first).await?;
        let second = self.read_at(second).await?;
        Ok((first, second))
    }
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
    let current = key.sk();
    let Some(legacy) = key.legacy_sk() else {
        let stored = reader.read_at(&current).await?;
        return Ok(verified_record(key, &current, stored).map(|record| (current, record)));
    };
    let (at_current, at_legacy) = reader.read_pair(&current, &legacy).await?;
    if let Some(record) = verified_record(key, &current, at_current) {
        return Ok(Some((current, record)));
    }
    Ok(verified_record(key, &legacy, at_legacy).map(|record| (legacy, record)))
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
    let mut slot = key.sk();
    let first = reader.read_at(&slot).await?;
    let slot_expect = expect_for(&first);
    let mut copies = Vec::new();
    let mut displaced = match first {
        Some(record) if !key.identifies(&record) => Some(record),
        _ => None,
    };
    while let Some(record) = displaced.take() {
        // Only a record an older release stored under this exact string (its
        // earlier key) is moved. Anything else is not where any release would
        // have put it, and is left alone rather than moved or overwritten.
        let own = TrustRecordKey::from_record(&record);
        if own.legacy_sk().as_deref() != Some(slot.as_str()) {
            tracing::error!(
                storage_key = slot,
                "stored record's identifiers match neither its key nor its earlier key format"
            );
            return Err(RepositoryError::QueryFailed(format!(
                "the record stored under {slot} does not belong there; refusing to write over it"
            )));
        }
        if copies.len() == MAX_DISPLACEMENT {
            return Err(RepositoryError::ValidationError(format!(
                "writing {} would move more than {MAX_DISPLACEMENT} records stored under the \
                 earlier key format",
                key.sk()
            )));
        }
        let target = own.sk();
        let stored = reader.read_at(&target).await?;
        match &stored {
            // Already moved: the copy under the earlier key is stale.
            Some(existing) if own.identifies(existing) => {}
            _ => {
                copies.push(Op {
                    storage_key: target.clone(),
                    expect: expect_for(&stored),
                    action: Action::Put(record),
                });
                displaced = stored;
                slot = target;
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
        return Err(RepositoryError::already_exists(&key));
    }
    let (mut ops, slot_expect) = make_room(reader, &key).await?;
    // `make_room` reads the key again. If the record appeared there after the
    // lookup (a concurrent create), the plan would otherwise be "overwrite the
    // record this key holds", which the backend's condition accepts: the
    // second create would silently replace the first.
    if slot_expect == Expect::Holds(key.clone()) {
        return Err(RepositoryError::already_exists(&key));
    }
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
        return Err(RepositoryError::not_found(&key));
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
        return Err(RepositoryError::not_found(key));
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

    /// Reads `stored` from every read after the first, as if a concurrent
    /// create landed between them.
    struct AppearsAfterFirstRead {
        reads: usize,
        stored: TrustRecord,
    }

    #[async_trait::async_trait]
    impl KeyedReader for AppearsAfterFirstRead {
        async fn read_at(
            &mut self,
            storage_key: &str,
        ) -> Result<Option<TrustRecord>, RepositoryError> {
            self.reads += 1;
            let present =
                self.reads > 1 && storage_key == TrustRecordKey::from_record(&self.stored).sk();
            Ok(present.then(|| self.stored.clone()))
        }
    }

    /// A create whose key gains the record between the existence check and
    /// the slot read is rejected, not planned as an overwrite. The conformance
    /// suite found this on DynamoDB, where it let several concurrent strict
    /// creates of one key all succeed.
    #[tokio::test]
    async fn a_record_created_concurrently_is_not_overwritten() {
        let winner = record("vc");
        let mut reader = AppearsAfterFirstRead {
            reads: 0,
            stored: winner.clone(),
        };
        let result = plan_create(&mut reader, &winner.clone().with_authorized(false)).await;
        assert!(
            matches!(result, Err(RepositoryError::RecordAlreadyExists(_))),
            "{result:?}"
        );
    }

    #[tokio::test]
    async fn a_record_that_belongs_under_neither_key_is_not_moved() {
        let a = record("x#y");
        let stray = record("unrelated");
        let mut store = HashMap::new();
        store.insert(TrustRecordKey::from_record(&a).sk(), stray);

        let result = plan_create(&mut MapReader(&store), &a).await;
        assert!(
            matches!(result, Err(RepositoryError::QueryFailed(_))),
            "{result:?}"
        );
    }
}
