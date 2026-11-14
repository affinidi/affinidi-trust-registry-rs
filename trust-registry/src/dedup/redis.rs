//! The record of accepted document identifiers in Redis (feature
//! `storage-redis`), shared by every registry replica on one Redis.
//!
//! Each document is one hash under its [`message_key`](super::message_key)
//! (`MID#<issuer>#<id>`, clear of the records' `TR#` keys) with the fields
//! `digest`, `state` (`inflight` or `done`) and, while in flight, `token` and
//! `lease_until`; once done, `outcome` (the [`StoredOutcome`] as JSON).
//!
//! Every operation is one Lua script, so it is atomic against every other
//! replica:
//!
//! - **claim** takes the key when it is absent or holds an in-flight claim
//!   whose lease has lapsed (judged by the Redis server's clock, `TIME`, so
//!   the replicas' clocks do not matter), and otherwise reports what holds
//!   it;
//! - **complete** stores the outcome only while the claim's token still holds
//!   the key, and sets the key to expire after the retention;
//! - **release** deletes the key only while the claim's token holds it.
//!
//! An in-flight key expires after the lease plus the retention, so a lapsed
//! claim nobody took over can still be completed by its claimant, and nothing
//! outlives the retention for long. Entries are bounded by their expiry only:
//! Redis's own memory limit applies, and only callers that passed the proof,
//! admin and authority checks reach a claim.

use std::sync::LazyLock;

use async_trait::async_trait;
use redis::Script;
use redis::aio::ConnectionManager;

use super::{Claim, ClaimToken, DedupError, MessageIdStore, StoredOutcome};
use crate::configs::MessageIdStoreConfig;

/// KEYS[1]: the entry. ARGV: digest, token, lease in ms, key lifetime in ms.
static CLAIM: LazyLock<Script> = LazyLock::new(|| {
    Script::new(
        r"
local now = redis.call('TIME')
local now_ms = tonumber(now[1]) * 1000 + math.floor(tonumber(now[2]) / 1000)
local held = redis.call('HMGET', KEYS[1], 'digest', 'state', 'lease_until', 'outcome')
if held[1] then
  local lapsed = held[2] == 'inflight' and tonumber(held[3] or '0') <= now_ms
  if not lapsed then
    if held[1] ~= ARGV[1] then return {'conflict'} end
    if held[2] == 'done' then return {'replay', held[4]} end
    return {'inflight'}
  end
  redis.call('DEL', KEYS[1])
end
redis.call('HSET', KEYS[1], 'digest', ARGV[1], 'state', 'inflight', 'token', ARGV[2],
  'lease_until', tostring(now_ms + tonumber(ARGV[3])))
redis.call('PEXPIRE', KEYS[1], ARGV[4])
return {'acquired'}
",
    )
});

/// KEYS[1]: the entry. ARGV: token, outcome JSON, retention in ms.
static COMPLETE: LazyLock<Script> = LazyLock::new(|| {
    Script::new(
        r"
local held = redis.call('HMGET', KEYS[1], 'state', 'token')
if held[1] ~= 'inflight' or held[2] ~= ARGV[1] then return 0 end
redis.call('HSET', KEYS[1], 'state', 'done', 'outcome', ARGV[2])
redis.call('HDEL', KEYS[1], 'token', 'lease_until')
redis.call('PEXPIRE', KEYS[1], ARGV[3])
return 1
",
    )
});

/// KEYS[1]: the entry. ARGV: token.
static RELEASE: LazyLock<Script> = LazyLock::new(|| {
    Script::new(
        r"
local held = redis.call('HMGET', KEYS[1], 'state', 'token')
if held[1] == 'inflight' and held[2] == ARGV[1] then
  redis.call('DEL', KEYS[1])
  return 1
end
return 0
",
    )
});

fn millis(duration: std::time::Duration) -> u64 {
    u64::try_from(duration.as_millis())
        .unwrap_or(u64::MAX)
        .max(1)
}

fn unavailable(e: impl std::fmt::Display) -> DedupError {
    DedupError::Unavailable(format!("Redis: {e}"))
}

/// The Redis-backed [`MessageIdStore`]. Built by
/// [`RedisStorage`](crate::storage::adapters::redis_storage::RedisStorage)
/// over its own connection.
#[derive(Clone)]
pub struct RedisMessageIdStore {
    connection: ConnectionManager,
    config: MessageIdStoreConfig,
}

impl RedisMessageIdStore {
    pub fn new(connection: ConnectionManager, config: MessageIdStoreConfig) -> Self {
        Self { connection, config }
    }
}

#[async_trait]
impl MessageIdStore for RedisMessageIdStore {
    async fn claim(&self, key: &str, digest: &str) -> Result<Claim, DedupError> {
        let token = ClaimToken::new();
        let lease = millis(self.config.in_flight_lease);
        let lifetime = lease.saturating_add(millis(self.config.retention));
        let mut connection = self.connection.clone();
        let answer: Vec<String> = CLAIM
            .key(key)
            .arg(digest)
            .arg(token.as_str())
            .arg(lease)
            .arg(lifetime)
            .invoke_async(&mut connection)
            .await
            .map_err(unavailable)?;
        match answer.first().map(String::as_str) {
            Some("acquired") => Ok(Claim::Acquired(token)),
            Some("inflight") => Ok(Claim::InFlight),
            Some("conflict") => Ok(Claim::Conflict),
            Some("replay") => {
                let stored = answer
                    .get(1)
                    .ok_or_else(|| unavailable(format!("the entry for {key} has no outcome")))?;
                let outcome: StoredOutcome = serde_json::from_str(stored).map_err(|e| {
                    unavailable(format!("the outcome stored for {key} does not decode: {e}"))
                })?;
                Ok(Claim::Replay(Box::new(outcome)))
            }
            other => Err(unavailable(format!(
                "unexpected answer from the claim script: {other:?}"
            ))),
        }
    }

    async fn complete(
        &self,
        key: &str,
        token: &ClaimToken,
        outcome: &StoredOutcome,
    ) -> Result<(), DedupError> {
        let outcome = serde_json::to_string(outcome).map_err(unavailable)?;
        let mut connection = self.connection.clone();
        let stored: i64 = COMPLETE
            .key(key)
            .arg(token.as_str())
            .arg(outcome)
            .arg(millis(self.config.retention))
            .invoke_async(&mut connection)
            .await
            .map_err(unavailable)?;
        if stored == 1 {
            Ok(())
        } else {
            Err(DedupError::ClaimLost(format!(
                "{key} is no longer held by this claim"
            )))
        }
    }

    async fn release(&self, key: &str, token: &ClaimToken) -> Result<(), DedupError> {
        let mut connection = self.connection.clone();
        let _released: i64 = RELEASE
            .key(key)
            .arg(token.as_str())
            .invoke_async(&mut connection)
            .await
            .map_err(unavailable)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;
    use crate::dedup::conformance::StoreFixture;
    use crate::storage::adapters::redis_storage::RedisStorage;
    use crate::storage::repository::TrustRecordAdminRepository;

    /// Each handle is a new `RedisStorage` (its own connection) on the
    /// Redis at `TR_TEST_REDIS_URL`, as a replica would hold.
    fn fixture() -> Option<StoreFixture> {
        let url = crate::storage::conformance::redis_test_url()?;
        Some(
            StoreFixture::new(move |config| {
                let url = url.clone();
                Box::pin(async move {
                    let storage = RedisStorage::new(&url)
                        .await
                        .expect("TR_TEST_REDIS_URL is set but Redis is unreachable");
                    storage
                        .message_id_store(&config)
                        .await
                        .expect("store")
                        .expect("Redis has a durable store")
                })
            })
            .shared()
            .unbounded()
            // Nothing to restart: a new handle is a new connection, and the
            // entries live in Redis.
            .with_restart(|| Box::pin(async {})),
        )
    }

    crate::dedup::conformance::message_id_store_conformance_tests!(redis_dedup, fixture());

    /// #194: one document delivered to two registries (two connections to one
    /// Redis) is executed once, and the second gets the first's response; a
    /// copy whose handler panicked is executed again on retry, not left in
    /// flight.
    #[tokio::test]
    #[serial_test::serial(redis_dedup)]
    async fn two_replicas_execute_a_document_once() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        use futures::FutureExt;

        use crate::dedup::{Disposition, execute_once};

        let Some(url) = crate::storage::conformance::redis_test_url() else {
            return;
        };
        let replica = || async {
            RedisStorage::new(&url)
                .await
                .expect("TR_TEST_REDIS_URL is set but Redis is unreachable")
                .message_id_store(&MessageIdStoreConfig::default())
                .await
                .expect("store")
                .expect("Redis has a durable store")
        };
        let (first, second) = (replica().await, replica().await);
        let mut doc = trust_tasks_rs::TrustTask::new(
            uuid::Uuid::new_v4().to_string(),
            "https://trusttasks.org/spec/registry/record/put/0.1"
                .parse()
                .expect("type uri"),
            serde_json::json!({ "n": 1 }),
        );
        doc.issuer = Some("did:example:replicas".to_string());

        let runs = AtomicUsize::new(0);
        let run = |doc: trust_tasks_rs::TrustTask<serde_json::Value>| {
            runs.fetch_add(1, Ordering::SeqCst);
            async move { Ok(doc) }
        };
        let on_first = execute_once(first.as_ref(), doc.clone(), run).await;
        let on_second = execute_once(second.as_ref(), doc.clone(), run).await;
        assert_eq!(runs.load(Ordering::SeqCst), 1);
        assert_eq!(on_first.disposition, Disposition::Executed);
        assert_eq!(on_second.disposition, Disposition::Replayed);
        assert_eq!(
            on_first.outcome.expect("executed"),
            on_second.outcome.expect("replayed")
        );

        let mut panics = doc.clone();
        panics.id = uuid::Uuid::new_v4().to_string();
        let panicked =
            std::panic::AssertUnwindSafe(execute_once(first.as_ref(), panics.clone(), |_| async {
                panic!("handler bug")
            }))
            .catch_unwind()
            .await;
        assert!(panicked.is_err());
        let retried = execute_once(second.as_ref(), panics, run).await;
        assert_eq!(retried.disposition, Disposition::Executed);
    }

    #[test]
    fn durations_are_whole_milliseconds_of_at_least_one() {
        assert_eq!(millis(std::time::Duration::from_micros(10)), 1);
        assert_eq!(millis(std::time::Duration::from_secs(2)), 2_000);
    }
}
