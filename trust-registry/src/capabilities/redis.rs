//! Capability enablement state in Redis (feature `storage-redis`), shared by
//! every registry replica on one Redis.
//!
//! The state is one hash, [`STATE_KEY`] (`CAP#enablements`), apart from the
//! records' `TR#` keys and the accepted document identifiers' `MID#` keys, so
//! no record listing ever reads it. Each field is one enablement: the field
//! name is its [`EnablementKey`] as a JSON array (`["git-trust","did:..."]`,
//! `["badge",null]`), and the value is `<revision>:<state as JSON>`.
//!
//! - **load** is one `HGETALL`, so it reads every enablement at one point in
//!   time.
//! - **put** is one Lua script that writes the field only while it is still
//!   at the expected revision, and bumps the revision, atomically against
//!   every other replica.

use std::sync::LazyLock;

use async_trait::async_trait;
use redis::Script;
use redis::aio::ConnectionManager;

use super::{
    CapabilityState, CapabilityStateStore, CapabilityStates, EnablementKey, Put, field, key_of,
};

/// The hash every enablement is a field of.
pub const STATE_KEY: &str = "CAP#enablements";

/// KEYS[1]: the hash. ARGV: field, expected revision, state JSON. Answers the
/// new revision, or -1 when the field is not at the expected revision.
static PUT: LazyLock<Script> = LazyLock::new(|| {
    Script::new(
        r"
local held = redis.call('HGET', KEYS[1], ARGV[1])
local revision = 0
if held then
  revision = tonumber(string.match(held, '^(%d+):')) or -1
end
if revision ~= tonumber(ARGV[2]) then return -1 end
local next = revision + 1
redis.call('HSET', KEYS[1], ARGV[1], tostring(next) .. ':' .. ARGV[3])
return next
",
    )
});

fn unavailable(e: impl std::fmt::Display) -> String {
    format!("Redis: {e}")
}

/// The Redis-backed [`CapabilityStateStore`]. Built by
/// [`RedisStorage`](crate::storage::adapters::redis_storage::RedisStorage)
/// over its own connection.
#[derive(Clone)]
pub struct RedisCapabilityStore {
    connection: ConnectionManager,
    key: String,
}

impl RedisCapabilityStore {
    /// The store in the hash [`STATE_KEY`].
    pub fn new(connection: ConnectionManager) -> Self {
        Self::with_key(connection, STATE_KEY)
    }

    /// The store in the hash `key` instead, so several registries (or tests)
    /// can keep separate state on one Redis. Keep it clear of `TR#` and
    /// `MID#`.
    pub fn with_key(connection: ConnectionManager, key: impl Into<String>) -> Self {
        Self {
            connection,
            key: key.into(),
        }
    }
}

#[async_trait]
impl CapabilityStateStore for RedisCapabilityStore {
    async fn load(&self) -> Result<CapabilityStates, String> {
        let mut connection = self.connection.clone();
        let fields: Vec<(String, String)> = redis::cmd("HGETALL")
            .arg(&self.key)
            .query_async(&mut connection)
            .await
            .map_err(unavailable)?;
        let mut states = CapabilityStates::new();
        for (field, value) in fields {
            let key = key_of(&field)?;
            let (revision, json) = value
                .split_once(':')
                .ok_or_else(|| format!("capability state {field} has no revision"))?;
            let revision: u64 = revision
                .parse()
                .map_err(|e| format!("capability state {field} has a bad revision: {e}"))?;
            let state: CapabilityState = serde_json::from_str(json)
                .map_err(|e| format!("capability state {field} is corrupt: {e}"))?;
            super::check_entry(&key, &state)?;
            states.insert(key, CapabilityState { revision, ..state });
        }
        Ok(states)
    }

    async fn put(
        &self,
        key: &EnablementKey,
        expected: u64,
        state: &CapabilityState,
    ) -> Result<Put, String> {
        let json = serde_json::to_string(&CapabilityState {
            revision: 0,
            ..state.clone()
        })
        .map_err(|e| e.to_string())?;
        let mut connection = self.connection.clone();
        let written: i64 = PUT
            .key(&self.key)
            .arg(field(key)?)
            .arg(expected)
            .arg(json)
            .invoke_async(&mut connection)
            .await
            .map_err(unavailable)?;
        Ok(match u64::try_from(written) {
            Ok(revision) => Put::Written(revision),
            Err(_) => Put::Conflict,
        })
    }

    fn is_shared(&self) -> bool {
        true
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;
    use crate::capabilities::conformance::CapabilityStoreFixture;
    use crate::storage::adapters::redis_storage::RedisStorage;
    use crate::storage::repository::TrustRecordAdminRepository;

    /// Each test gets a hash of its own on the Redis at `TR_TEST_REDIS_URL`,
    /// and each handle its own connection, as a replica would hold.
    fn fixture() -> Option<CapabilityStoreFixture> {
        let url = crate::storage::conformance::redis_test_url()?;
        Some(CapabilityStoreFixture::new(move || {
            let url = url.clone();
            let hash = format!("CAP#test-{}", uuid::Uuid::new_v4());
            Box::pin(async move {
                let handle = || async {
                    let storage = RedisStorage::new(&url)
                        .await
                        .expect("TR_TEST_REDIS_URL is set but Redis is unreachable");
                    Box::new(RedisCapabilityStore::with_key(
                        storage.connection(),
                        hash.clone(),
                    )) as Box<dyn CapabilityStateStore>
                };
                (handle().await, handle().await)
            })
        }))
    }

    crate::capabilities::conformance::capability_store_conformance_tests!(redis_caps, fixture());
    crate::capabilities::conformance::replica_tests!(redis_replicas, fixture());

    #[test]
    fn fields_round_trip_every_enablement() {
        for key in [
            EnablementKey::new("git-trust", Some("did:web:example.com#x:\"y\"")),
            EnablementKey::new("badge", None),
        ] {
            assert_eq!(key_of(&field(&key).unwrap()).unwrap(), key);
        }
        assert_eq!(
            field(&EnablementKey::new("badge", None)).unwrap(),
            r#"["badge",null]"#
        );
    }

    /// The repository's own store is the shared one, in `CAP#enablements`,
    /// which no record listing reads.
    #[tokio::test]
    async fn the_repository_store_is_shared_and_not_listed() {
        let Some(url) = crate::storage::conformance::redis_test_url() else {
            return;
        };
        let storage = RedisStorage::new(&url).await.expect("Redis");
        let store = storage
            .capability_store()
            .await
            .expect("store")
            .expect("Redis has a shared store");
        assert!(store.is_shared());
        // A capability no registry has, so no set adopts it.
        let probe = EnablementKey::new(format!("listing-probe-{}", uuid::Uuid::new_v4()), None);
        let state = crate::capabilities::conformance::state(true, None);
        assert!(matches!(
            store.put(&probe, 0, &state).await.expect("put"),
            Put::Written(1)
        ));
        let listed = storage.list().await.expect("list");
        assert!(
            listed
                .unreadable()
                .iter()
                .all(|u| !u.storage_key().starts_with("CAP#")),
            "the capability state is not read as a record"
        );
        assert!(store.load().await.expect("load").contains_key(&probe));
        let mut connection = storage.connection();
        let _: () = redis::cmd("HDEL")
            .arg(STATE_KEY)
            .arg(field(&probe).unwrap())
            .query_async(&mut connection)
            .await
            .expect("HDEL");
    }
}
