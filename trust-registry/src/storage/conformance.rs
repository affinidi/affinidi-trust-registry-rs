//! The behaviour every [`TrustRecordAdminRepository`] adapter must show, as one
//! test suite each adapter runs.
//!
//! An adapter's test module builds a [`Fixture`] and expands
//! [`repository_conformance_tests!`]:
//!
//! ```ignore
//! async fn fixture() -> Option<Fixture> {
//!     Some(Fixture::new(MyStorage::new()))
//! }
//! crate::storage::conformance::repository_conformance_tests!(my_storage, fixture().await);
//! ```
//!
//! The fixture expression yields `None` to skip the suite, which an adapter
//! backed by an external service does when the variable naming the service is
//! unset (see [`redis_test_url`]); it says so on stderr.
//!
//! Every test writes records under an authority unique to that test, compares
//! only those, and deletes only those, so the suite can run against a store
//! that holds other data. It never deletes anything it did not write.

use std::any::Any;
use std::sync::Arc;

use futures::future::BoxFuture;
use serde_json::json;

use crate::domain::key::TrustRecordKey;
use crate::domain::*;
use crate::storage::repository::{RepositoryError, TrustRecordAdminRepository, TrustRecordQuery};

/// Writes or removes raw bytes under a storage key, bypassing the adapter.
pub(crate) type RawKeyOp = Arc<dyn Fn(String) -> BoxFuture<'static, ()> + Send + Sync>;

/// One adapter instance under test.
pub(crate) struct Fixture {
    repo: Arc<dyn TrustRecordAdminRepository>,
    /// A second handle on the same backing store, as a second registry
    /// replica would hold (a second Redis connection, a second DynamoDB
    /// client). Concurrency tests split their writers between the two.
    peer: Option<Arc<dyn TrustRecordAdminRepository>>,
    /// Stores an undecodable value under a storage key, and removes it.
    corrupter: Option<(RawKeyOp, RawKeyOp)>,
    /// Kept alive for the fixture's lifetime (a temporary directory).
    _guard: Option<Box<dyn Any + Send + Sync>>,
}

impl Fixture {
    pub(crate) fn new(repo: impl TrustRecordAdminRepository + 'static) -> Self {
        Self {
            repo: Arc::new(repo),
            peer: None,
            corrupter: None,
            _guard: None,
        }
    }

    pub(crate) fn with_guard(mut self, guard: impl Any + Send + Sync) -> Self {
        self._guard = Some(Box::new(guard));
        self
    }

    pub(crate) fn with_peer(mut self, peer: impl TrustRecordAdminRepository + 'static) -> Self {
        self.peer = Some(Arc::new(peer));
        self
    }

    pub(crate) fn with_corrupter<W, R>(mut self, write: W, remove: R) -> Self
    where
        W: Fn(String) -> BoxFuture<'static, ()> + Send + Sync + 'static,
        R: Fn(String) -> BoxFuture<'static, ()> + Send + Sync + 'static,
    {
        self.corrupter = Some((Arc::new(write), Arc::new(remove)));
        self
    }

    pub(crate) fn repo(&self) -> &dyn TrustRecordAdminRepository {
        self.repo.as_ref()
    }

    fn handle(&self, index: usize) -> Arc<dyn TrustRecordAdminRepository> {
        match &self.peer {
            Some(peer) if index % 2 == 1 => Arc::clone(peer),
            _ => Arc::clone(&self.repo),
        }
    }
}

/// The Redis the Redis tests run against: `TR_TEST_REDIS_URL`.
///
/// `None` when the variable is unset; the caller skips and this says so on
/// stderr. A set variable means the service must be there: the caller fails
/// when it cannot connect, rather than passing without running anything.
///
/// The tests only delete keys they wrote, but use a dedicated database index
/// all the same (`redis://127.0.0.1:6379/15`).
pub(crate) fn redis_test_url() -> Option<String> {
    service_url("TR_TEST_REDIS_URL", "Redis")
}

/// The DynamoDB endpoint (DynamoDB Local, LocalStack) the DynamoDB tests run
/// against: `TR_TEST_DYNAMODB_ENDPOINT`. Same contract as [`redis_test_url`].
pub(crate) fn dynamodb_test_endpoint() -> Option<String> {
    service_url("TR_TEST_DYNAMODB_ENDPOINT", "DynamoDB")
}

fn service_url(variable: &str, service: &str) -> Option<String> {
    match std::env::var(variable) {
        Ok(url) if !url.trim().is_empty() => Some(url),
        // CI sets this so that a missing service variable fails the run
        // instead of skipping the suite.
        _ if std::env::var("TR_TEST_REQUIRE_SERVICES").is_ok_and(|v| v == "true") => {
            panic!("TR_TEST_REQUIRE_SERVICES=true but {variable} is unset")
        }
        _ => {
            eprintln!(
                "SKIPPED: {service} storage test not run because {variable} is unset; set it to \
                 run the {service} adapter tests"
            );
            None
        }
    }
}

/// Identifiers unique to one test, so it touches only its own records.
struct Namespace {
    authority: String,
}

impl Namespace {
    fn new() -> Self {
        Self {
            authority: format!("did:example:conformance-{}", uuid::Uuid::new_v4()),
        }
    }

    fn record(&self, action: &str, resource: &str, entity: &str) -> TrustRecord {
        TrustRecordBuilder::new()
            .entity_id(EntityId::new(entity))
            .authority_id(AuthorityId::new(self.authority.as_str()))
            .action(Action::new(action))
            .resource(Resource::new(resource))
            .recognized(true)
            .authorized(true)
            .record_type(RecordType::Authorization)
            .build()
            .expect("valid record")
    }

    fn owns(&self, record: &TrustRecord) -> bool {
        record.authority_id().as_str() == self.authority
    }

    /// This test's records in a listing, sorted by key.
    async fn listed(&self, repo: &dyn TrustRecordAdminRepository) -> Vec<TrustRecord> {
        let mut records: Vec<TrustRecord> = repo
            .list()
            .await
            .expect("list")
            .into_records()
            .into_iter()
            .filter(|record| self.owns(record))
            .collect();
        records.sort_by_key(|record| TrustRecordKey::from_record(record).sk());
        records
    }

    /// Delete every record this test wrote.
    async fn cleanup(&self, repo: &dyn TrustRecordAdminRepository) {
        if let Ok(list) = repo.list().await {
            for record in list.into_records() {
                if self.owns(&record) {
                    let _ = repo.delete(query_for(&record)).await;
                }
            }
        }
    }
}

fn query_for(record: &TrustRecord) -> TrustRecordQuery {
    TrustRecordQuery::new(
        record.entity_id().clone(),
        record.authority_id().clone(),
        record.action().clone(),
        record.resource().clone(),
    )
}

fn key_of(record: &TrustRecord) -> TrustRecordKey {
    TrustRecordKey::from_record(record)
}

#[track_caller]
fn assert_already_exists(result: Result<(), RepositoryError>, record: &TrustRecord) {
    let sk = key_of(record).sk();
    match result {
        Err(RepositoryError::RecordAlreadyExists(payload)) => {
            assert_eq!(payload, sk, "the payload is the storage key, once");
            assert_eq!(
                RepositoryError::RecordAlreadyExists(payload).to_string(),
                format!("Record already exists: {sk}")
            );
        }
        other => panic!("expected RecordAlreadyExists({sk}), got {other:?}"),
    }
}

#[track_caller]
fn assert_not_found<T: std::fmt::Debug>(result: Result<T, RepositoryError>, record: &TrustRecord) {
    let sk = key_of(record).sk();
    match result {
        Err(RepositoryError::RecordNotFound(payload)) => {
            assert_eq!(payload, sk, "the payload is the storage key, once");
            assert_eq!(
                RepositoryError::RecordNotFound(payload).to_string(),
                format!("Record not found: {sk}")
            );
        }
        other => panic!("expected RecordNotFound({sk}), got {other:?}"),
    }
}

/// A strict create stores the record; a second create of the same key fails
/// with `RecordAlreadyExists` and leaves the stored record unchanged.
pub(crate) async fn strict_create(fixture: &Fixture) {
    let repo = fixture.repo();
    let ns = Namespace::new();
    let record = ns.record("issue", "vc", "did:example:entity");

    repo.create(record.clone()).await.expect("create");
    assert_eq!(repo.read(query_for(&record)).await.expect("read"), record);

    let other_values = record.clone().with_authorized(false);
    assert_already_exists(repo.create(other_values).await, &record);
    assert_eq!(
        repo.read(query_for(&record)).await.expect("read"),
        record,
        "a rejected create must not overwrite"
    );

    ns.cleanup(repo).await;
}

/// An update of a missing key fails with `RecordNotFound` and creates
/// nothing; an update of a present key replaces it.
pub(crate) async fn strict_update(fixture: &Fixture) {
    let repo = fixture.repo();
    let ns = Namespace::new();
    let record = ns.record("issue", "vc", "did:example:entity");

    assert_not_found(repo.update(record.clone()).await, &record);
    assert_eq!(
        repo.find_by_query(query_for(&record)).await.expect("find"),
        None,
        "a rejected update must not create"
    );

    repo.create(record.clone()).await.expect("create");
    let updated = record
        .clone()
        .with_authorized(false)
        .merge_contexts(Context::new(json!({"note": "updated"})));
    repo.update(updated.clone()).await.expect("update");
    assert_eq!(repo.read(query_for(&record)).await.expect("read"), updated);
    assert_eq!(ns.listed(repo).await, vec![updated]);

    ns.cleanup(repo).await;
}

/// Delete of a missing key fails with `RecordNotFound`; delete of a present
/// key removes it, after which read, update and delete all report it missing.
pub(crate) async fn delete_semantics(fixture: &Fixture) {
    let repo = fixture.repo();
    let ns = Namespace::new();
    let record = ns.record("issue", "vc", "did:example:entity");

    assert_not_found(repo.delete(query_for(&record)).await, &record);

    repo.create(record.clone()).await.expect("create");
    repo.delete(query_for(&record)).await.expect("delete");
    assert_eq!(
        repo.find_by_query(query_for(&record)).await.expect("find"),
        None
    );
    assert_not_found(repo.read(query_for(&record)).await, &record);
    assert_not_found(repo.delete(query_for(&record)).await, &record);
    assert_not_found(repo.update(record.clone()).await, &record);
    assert!(ns.listed(repo).await.is_empty());

    // A deleted key can be created again.
    repo.create(record.clone()).await.expect("re-create");
    assert_eq!(repo.read(query_for(&record)).await.expect("read"), record);

    ns.cleanup(repo).await;
}

/// `read` and `find_by_query` agree, for present and absent keys, and every
/// field survives the round trip through the store and the listing.
pub(crate) async fn read_find_and_list_agree(fixture: &Fixture) {
    let repo = fixture.repo();
    let ns = Namespace::new();
    let from = chrono::DateTime::parse_from_rfc3339("2026-01-01T00:00:00Z")
        .expect("timestamp")
        .to_utc();
    let until = chrono::DateTime::parse_from_rfc3339("2027-06-30T12:34:56Z")
        .expect("timestamp")
        .to_utc();
    let full = TrustRecordBuilder::new()
        .entity_id(EntityId::new("did:example:holder"))
        .authority_id(AuthorityId::new(ns.authority.as_str()))
        .action(Action::new("recognize"))
        .resource(Resource::new("https://schema.example/vc"))
        .recognized(false)
        .authorized(true)
        .record_type(RecordType::Recognition)
        .context(Context::new(
            json!({"nested": {"list": [1, 2, 3], "flag": true}, "text": "a,b\n\"c\""}),
        ))
        .valid_from(Some(from))
        .valid_until(Some(until))
        .build()
        .expect("valid record");
    let plain = ns.record("issue", "vc", "did:example:entity");
    let absent = ns.record("issue", "vc", "did:example:nobody");

    repo.create(full.clone()).await.expect("create");
    repo.create(plain.clone()).await.expect("create");

    for record in [&full, &plain] {
        assert_eq!(
            repo.find_by_query(query_for(record)).await.expect("find"),
            Some(record.clone())
        );
        assert_eq!(
            repo.read(query_for(record)).await.expect("read"),
            record.clone()
        );
    }
    assert_eq!(
        repo.find_by_query(query_for(&absent)).await.expect("find"),
        None
    );
    assert_not_found(repo.read(query_for(&absent)).await, &absent);

    let mut expected = vec![full, plain];
    expected.sort_by_key(|record| key_of(record).sk());
    assert_eq!(ns.listed(repo).await, expected);

    ns.cleanup(repo).await;
}

/// Identifiers containing the key separator or the escape character name
/// distinct records (see `domain::key`).
pub(crate) async fn separator_in_identifiers(fixture: &Fixture) {
    let repo = fixture.repo();
    let ns = Namespace::new();
    let first = ns.record("sign", "repo#main", "did:example:e");
    let second = ns
        .record("sign#repo", "main", "did:example:e")
        .with_authorized(false);
    let third = ns.record("sign", "x%23y", "did:example:e");
    let fourth = ns
        .record("sign", "x#y", "did:example:e")
        .with_authorized(false);

    for record in [&first, &second, &third, &fourth] {
        repo.create(record.clone()).await.expect("create");
    }
    for record in [&first, &second, &third, &fourth] {
        assert_eq!(&repo.read(query_for(record)).await.expect("read"), record);
    }
    repo.delete(query_for(&first)).await.expect("delete");
    repo.delete(query_for(&fourth)).await.expect("delete");
    assert_eq!(repo.read(query_for(&second)).await.expect("read"), second);
    assert_eq!(repo.read(query_for(&third)).await.expect("read"), third);
    assert_eq!(ns.listed(repo).await.len(), 2);

    ns.cleanup(repo).await;
}

const CONCURRENT_WRITERS: usize = 16;

/// Concurrent strict creates of one key: exactly one succeeds, every other
/// one fails with `RecordAlreadyExists`, and the stored record is the
/// winner's.
pub(crate) async fn concurrent_creates_of_one_key(fixture: &Fixture) {
    let ns = Namespace::new();
    let base = ns.record("issue", "vc", "did:example:entity");
    let writers: Vec<_> = (0..CONCURRENT_WRITERS)
        .map(|writer| {
            let repo = fixture.handle(writer);
            let record = base
                .clone()
                .merge_contexts(Context::new(json!({ "writer": writer })));
            tokio::spawn(async move { (record.clone(), repo.create(record).await) })
        })
        .collect();

    let mut winners = Vec::new();
    for writer in writers {
        let (record, result) = writer.await.expect("writer task");
        match result {
            Ok(()) => winners.push(record),
            Err(_) => assert_already_exists(result, &record),
        }
    }
    assert_eq!(winners.len(), 1, "exactly one strict create wins");
    assert_eq!(
        fixture.repo().read(query_for(&base)).await.expect("read"),
        winners[0],
        "the stored record is the winner's"
    );

    ns.cleanup(fixture.repo()).await;
}

/// Concurrent creates of distinct keys all land; none is lost to another's
/// write.
pub(crate) async fn concurrent_creates_of_distinct_keys(fixture: &Fixture) {
    let ns = Namespace::new();
    let records: Vec<_> = (0..CONCURRENT_WRITERS)
        .map(|writer| ns.record("issue", "vc", &format!("did:example:entity-{writer:02}")))
        .collect();
    let writers: Vec<_> = records
        .iter()
        .cloned()
        .enumerate()
        .map(|(writer, record)| {
            let repo = fixture.handle(writer);
            tokio::spawn(async move { repo.create(record).await })
        })
        .collect();
    for writer in writers {
        writer.await.expect("writer task").expect("create");
    }
    assert_eq!(ns.listed(fixture.repo()).await, records);

    ns.cleanup(fixture.repo()).await;
}

/// A stored value that does not decode: a lookup of its key fails with
/// `SerializationFailed` (never "absent"), and a listing leaves it out but
/// reports it in `TrustRecordList::unreadable`, so a filtering caller can fail
/// when it could have matched. Adapters with no raw access (in-memory) skip
/// this.
pub(crate) async fn corrupt_value_is_an_error(fixture: &Fixture) {
    let Some((write, remove)) = &fixture.corrupter else {
        return;
    };
    let repo = fixture.repo();
    let ns = Namespace::new();
    let record = ns.record("issue", "vc", "did:example:corrupt");
    let storage_key = key_of(&record).sk();

    let neighbour = ns.record("issue", "vc", "did:example:readable");
    repo.create(neighbour.clone()).await.expect("create");
    write(storage_key.clone()).await;
    let found = repo.find_by_query(query_for(&record)).await;
    let read = repo.read(query_for(&record)).await;
    let listed = repo.list().await;
    // Remove it before asserting, so a failure leaves nothing behind for
    // other tests listing the same store.
    remove(storage_key.clone()).await;
    ns.cleanup(repo).await;

    assert!(
        matches!(found, Err(RepositoryError::SerializationFailed(_))),
        "find_by_query: {found:?}"
    );
    assert!(
        matches!(read, Err(RepositoryError::SerializationFailed(_))),
        "read: {read:?}"
    );
    let listed = listed.expect("a listing does not fail on an undecodable value");
    assert!(
        listed
            .unreadable()
            .iter()
            .any(|unreadable| unreadable.storage_key() == storage_key),
        "the listing reports the undecodable value"
    );
    assert!(
        listed.records().contains(&neighbour),
        "the rest of the listing is intact"
    );
    assert!(
        !listed
            .records()
            .iter()
            .any(|r| key_of(r).sk() == storage_key),
        "the undecodable value is not listed as a record"
    );
}

/// Expand the conformance suite as `#[tokio::test]`s in a `conformance`
/// child module.
///
/// `$group` names the `serial_test` group the tests run in, one at a time.
/// Every test of one external store (the suite *and* the adapter's own tests
/// against it) must use the same group: the corrupt-value test plants an
/// undecodable value that another test's listing would otherwise see;
/// `$fixture` is an expression yielding `Option<Fixture>`, evaluated in each
/// test.
macro_rules! repository_conformance_tests {
    ($group:ident, $fixture:expr) => {
        mod conformance {
            #[allow(unused_imports)]
            use super::*;

            $crate::storage::conformance::repository_conformance_tests!(
                @tests $group, $fixture,
                strict_create,
                strict_update,
                delete_semantics,
                read_find_and_list_agree,
                separator_in_identifiers,
                concurrent_creates_of_one_key,
                concurrent_creates_of_distinct_keys,
                corrupt_value_is_an_error
            );
        }
    };
    (@tests $group:ident, $fixture:expr, $($test:ident),+) => {
        $(
            #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
            #[::serial_test::serial($group)]
            async fn $test() {
                let Some(fixture) = $fixture else {
                    return;
                };
                $crate::storage::conformance::$test(&fixture).await;
            }
        )+
    };
}
pub(crate) use repository_conformance_tests;
