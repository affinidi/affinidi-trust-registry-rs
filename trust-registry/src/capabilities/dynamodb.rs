//! Capability enablement state in DynamoDB (feature `storage-ddb`), shared by
//! every registry replica on one table.
//!
//! Each enablement is one item in the records' table, in the partition
//! `PK` = [`STATE_PARTITION`] (`CAP#enablements`), apart from the records'
//! `PK = TR` partition (which every record listing queries, and nothing else)
//! and the accepted document identifiers' `MID#...` partitions. Its sort key
//! `SK` is the [`EnablementKey`] as a JSON array (`["git-trust","did:..."]`,
//! `["badge",null]`); its attributes are `revision` (a number) and `state`
//! (the state as JSON).
//!
//! - **load** is one strongly consistent `Query` of the partition.
//! - **put** is a conditional `PutItem`: the item must be absent (expected
//!   revision 0) or still at the expected revision, so two replicas writing
//!   one enablement at once cannot both succeed.

use std::collections::HashMap;

use async_trait::async_trait;
use aws_sdk_dynamodb::Client;
use aws_sdk_dynamodb::error::DisplayErrorContext;
use aws_sdk_dynamodb::types::AttributeValue;

use super::{CapabilityState, CapabilityStateStore, CapabilityStates, EnablementKey, Put};
use super::{field, key_of};

/// The partition every enablement is an item of.
pub const STATE_PARTITION: &str = "CAP#enablements";

const PK_ATTR: &str = "PK";
const SK_ATTR: &str = "SK";
const REVISION_ATTR: &str = "revision";
const STATE_ATTR: &str = "state";

fn unavailable(context: &str, err: impl std::error::Error + 'static) -> String {
    format!("DynamoDB {context}: {}", DisplayErrorContext(&err))
}

/// The DynamoDB-backed [`CapabilityStateStore`]. Built by
/// [`DynamoDbStorage`](crate::storage::adapters::ddb_storage::DynamoDbStorage)
/// over its own client and table.
#[derive(Clone)]
pub struct DynamoDbCapabilityStore {
    client: Client,
    table_name: String,
    partition: String,
}

impl DynamoDbCapabilityStore {
    /// The store in the partition [`STATE_PARTITION`] of `table_name`.
    pub fn new(client: Client, table_name: impl Into<String>) -> Self {
        Self::with_partition(client, table_name, STATE_PARTITION)
    }

    /// The store in the partition `partition` instead, so several registries
    /// (or tests) can keep separate state in one table. Keep it clear of `TR`
    /// and `MID#`.
    pub fn with_partition(
        client: Client,
        table_name: impl Into<String>,
        partition: impl Into<String>,
    ) -> Self {
        Self {
            client,
            table_name: table_name.into(),
            partition: partition.into(),
        }
    }
}

fn text<'a>(item: &'a HashMap<String, AttributeValue>, name: &str) -> Option<&'a str> {
    match item.get(name) {
        Some(AttributeValue::S(value)) => Some(value),
        _ => None,
    }
}

#[async_trait]
impl CapabilityStateStore for DynamoDbCapabilityStore {
    async fn load(&self) -> Result<CapabilityStates, String> {
        let items: Vec<_> = self
            .client
            .query()
            .table_name(&self.table_name)
            .consistent_read(true)
            .key_condition_expression("#pk = :pk")
            .expression_attribute_names("#pk", PK_ATTR)
            .expression_attribute_values(":pk", AttributeValue::S(self.partition.clone()))
            .into_paginator()
            .items()
            .send()
            .try_collect()
            .await
            .map_err(|e| unavailable("Query", e))?;
        let mut states = CapabilityStates::new();
        for item in items {
            let field = text(&item, SK_ATTR).unwrap_or_default();
            let key = key_of(field)?;
            let revision: u64 = match item.get(REVISION_ATTR) {
                Some(AttributeValue::N(n)) => n
                    .parse()
                    .map_err(|e| format!("capability state {field} has a bad revision: {e}"))?,
                _ => return Err(format!("capability state {field} has no revision")),
            };
            let state: CapabilityState = serde_json::from_str(
                text(&item, STATE_ATTR)
                    .ok_or_else(|| format!("capability state {field} has no state"))?,
            )
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
        let revision = expected + 1;
        let request = self
            .client
            .put_item()
            .table_name(&self.table_name)
            .item(PK_ATTR, AttributeValue::S(self.partition.clone()))
            .item(SK_ATTR, AttributeValue::S(field(key)?))
            .item(REVISION_ATTR, AttributeValue::N(revision.to_string()))
            .item(STATE_ATTR, AttributeValue::S(json));
        // A comparison with a missing attribute is false, so the second
        // condition also refuses an item that is gone.
        let request = if expected == 0 {
            request
                .condition_expression("attribute_not_exists(#pk)")
                .expression_attribute_names("#pk", PK_ATTR)
        } else {
            request
                .condition_expression("#revision = :expected")
                .expression_attribute_names("#revision", REVISION_ATTR)
                .expression_attribute_values(":expected", AttributeValue::N(expected.to_string()))
        };
        match request.send().await {
            Ok(_) => Ok(Put::Written(revision)),
            Err(err)
                if err
                    .as_service_error()
                    .is_some_and(|e| e.is_conditional_check_failed_exception()) =>
            {
                Ok(Put::Conflict)
            }
            Err(err) => Err(unavailable("PutItem", err)),
        }
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

    /// Each test gets a partition of its own in the test table at
    /// `TR_TEST_DYNAMODB_ENDPOINT`, and each handle its own client, as a
    /// replica would hold.
    async fn fixture() -> Option<CapabilityStoreFixture> {
        // Creates the table if it is missing, before any store uses it.
        crate::storage::adapters::ddb_storage::tests::test_storage().await?;
        Some(CapabilityStoreFixture::new(|| {
            let partition = format!("CAP#test-{}", uuid::Uuid::new_v4());
            Box::pin(async move {
                let handle = || async {
                    let storage = crate::storage::adapters::ddb_storage::tests::test_storage()
                        .await
                        .expect("TR_TEST_DYNAMODB_ENDPOINT is set");
                    let (client, table) = storage.client_and_table();
                    Box::new(DynamoDbCapabilityStore::with_partition(
                        client,
                        table,
                        partition.clone(),
                    )) as Box<dyn CapabilityStateStore>
                };
                (handle().await, handle().await)
            })
        }))
    }

    crate::capabilities::conformance::capability_store_conformance_tests!(
        dynamodb_caps,
        fixture().await
    );
    crate::capabilities::conformance::replica_tests!(dynamodb_replicas, fixture().await);

    /// The repository's own store is the shared one, in its own partition,
    /// which no record listing reads.
    #[tokio::test]
    async fn the_repository_store_is_shared_and_not_listed() {
        use crate::storage::repository::TrustRecordAdminRepository;
        let Some(storage) = crate::storage::adapters::ddb_storage::tests::test_storage().await
        else {
            return;
        };
        let store = storage
            .capability_store()
            .await
            .expect("store")
            .expect("DynamoDB has a shared store");
        assert!(store.is_shared());
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
                .all(|u| !u.storage_key().starts_with("CAP#")
                    && !u.storage_key().starts_with("[\"listing-probe")),
            "the capability state is not read as a record"
        );
        assert!(store.load().await.expect("load").contains_key(&probe));
        let (client, table) = storage.client_and_table();
        client
            .delete_item()
            .table_name(table)
            .key(PK_ATTR, AttributeValue::S(STATE_PARTITION.to_string()))
            .key(SK_ATTR, AttributeValue::S(field(&probe).unwrap()))
            .send()
            .await
            .expect("delete the probe");
    }
}
