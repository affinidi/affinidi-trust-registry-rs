use std::collections::HashMap;

use anyhow::Result as AnyResult;
use aws_config::BehaviorVersion;
use aws_sdk_dynamodb::{
    Client,
    error::{BuildError, DisplayErrorContext},
    types::{AttributeValue, Delete, Get, Put, TransactGetItem, TransactWriteItem},
};
use aws_types::region::Region;
use tracing::debug;

use crate::{
    configs::DynamoDbStorageConfig,
    domain::{
        TrustRecord,
        key::{TrustRecordKey, dedupe_listing},
    },
    storage::keyed::{
        Action as KeyedAction, Expect, KeyedReader, Op, lookup, plan_create, plan_delete,
        plan_update,
    },
    storage::repository::{
        RepositoryError, TrustRecordAdminRepository, TrustRecordList, TrustRecordQuery,
        TrustRecordRepository,
    },
};

const PK_ATTR: &str = "PK";
const SK_ATTR: &str = "SK";

#[derive(Clone)]
pub struct DynamoDbStorage {
    client: Client,
    table_name: String,
}

impl DynamoDbStorage {
    pub async fn new(config: DynamoDbStorageConfig) -> AnyResult<Self> {
        let mut loader = aws_config::defaults(BehaviorVersion::latest());

        if let Some(profile) = &config.profile {
            loader = loader.profile_name(profile);
        }

        if let Some(region) = config.region.clone() {
            loader = loader.region(Region::new(region));
        }

        if let Some(endpoint_url) = &config.endpoint_url {
            loader = loader.endpoint_url(endpoint_url.clone());
        }
        // Only on explicit request (`DDB_USE_TEST_CREDENTIALS=true`): inferring
        // it from the endpoint swapped real credentials for fake ones on any
        // in-cluster `*.local` hostname.
        if config.use_test_credentials {
            loader = loader.test_credentials();
        }

        let shared_config = loader.load().await;
        let client = Client::new(&shared_config);

        Ok(Self::with_client(client, config.table_name))
    }

    pub fn with_client(client: Client, table_name: impl Into<String>) -> Self {
        Self {
            client,
            table_name: table_name.into(),
        }
    }

    fn build_key(storage_key: &str) -> HashMap<String, AttributeValue> {
        let mut key = HashMap::with_capacity(2);
        key.insert(
            PK_ATTR.to_string(),
            AttributeValue::S(TrustRecordKey::pk().to_string()),
        );
        key.insert(
            SK_ATTR.to_string(),
            AttributeValue::S(storage_key.to_string()),
        );
        key
    }

    fn build_item(
        record: &TrustRecord,
        storage_key: &str,
    ) -> Result<HashMap<String, AttributeValue>, RepositoryError> {
        let mut item: HashMap<String, AttributeValue> = serde_dynamo::to_item(record)
            .map_err(|e| RepositoryError::SerializationFailed(e.to_string()))?;
        item.extend(Self::build_key(storage_key));
        Ok(item)
    }

    async fn get_record(&self, storage_key: &str) -> Result<Option<TrustRecord>, RepositoryError> {
        let response = self
            .client
            .get_item()
            .table_name(&self.table_name)
            .set_key(Some(Self::build_key(storage_key)))
            .consistent_read(true)
            .send()
            .await
            .map_err(|err| {
                RepositoryError::ConnectionFailed(format!(
                    "Failed to fetch item from DynamoDB: {}",
                    DisplayErrorContext(err)
                ))
            })?;
        response
            .item
            .map(|item| {
                serde_dynamo::from_item(item)
                    .map_err(|e| RepositoryError::SerializationFailed(e.to_string()))
            })
            .transpose()
    }

    async fn find(&self, key: &TrustRecordKey) -> Result<Option<TrustRecord>, RepositoryError> {
        let mut reader = DdbReader(self);
        Ok(lookup(&mut reader, key).await?.map(|(_, record)| record))
    }

    /// The condition that `op`'s key still holds what it was read as.
    fn condition(
        expect: &Expect,
    ) -> (
        String,
        HashMap<String, String>,
        HashMap<String, AttributeValue>,
    ) {
        match expect {
            Expect::Absent => (
                "attribute_not_exists(SK)".to_string(),
                HashMap::new(),
                HashMap::new(),
            ),
            Expect::Holds(key) => {
                let names = HashMap::from([
                    ("#authority".to_string(), "authority_id".to_string()),
                    ("#action".to_string(), "action".to_string()),
                    ("#resource".to_string(), "resource".to_string()),
                    ("#entity".to_string(), "entity_id".to_string()),
                ]);
                let values = HashMap::from([
                    (
                        ":authority".to_string(),
                        AttributeValue::S(key.authority_id().as_str().to_string()),
                    ),
                    (
                        ":action".to_string(),
                        AttributeValue::S(key.action().as_str().to_string()),
                    ),
                    (
                        ":resource".to_string(),
                        AttributeValue::S(key.resource().as_str().to_string()),
                    ),
                    (
                        ":entity".to_string(),
                        AttributeValue::S(key.entity_id().as_str().to_string()),
                    ),
                ]);
                (
                    "#authority = :authority AND #action = :action AND #resource = :resource \
                     AND #entity = :entity"
                        .to_string(),
                    names,
                    values,
                )
            }
        }
    }

    fn transact_item(&self, op: &Op) -> Result<TransactWriteItem, RepositoryError> {
        let (condition, names, values) = Self::condition(&op.expect);
        let names = (!names.is_empty()).then_some(names);
        let values = (!values.is_empty()).then_some(values);
        let build_error = |e: BuildError| RepositoryError::QueryFailed(e.to_string());
        Ok(match &op.action {
            KeyedAction::Put(record) => TransactWriteItem::builder()
                .put(
                    Put::builder()
                        .table_name(&self.table_name)
                        .set_item(Some(Self::build_item(record, &op.storage_key)?))
                        .condition_expression(condition)
                        .set_expression_attribute_names(names)
                        .set_expression_attribute_values(values)
                        .build()
                        .map_err(build_error)?,
                )
                .build(),
            KeyedAction::Delete => TransactWriteItem::builder()
                .delete(
                    Delete::builder()
                        .table_name(&self.table_name)
                        .set_key(Some(Self::build_key(&op.storage_key)))
                        .condition_expression(condition)
                        .set_expression_attribute_names(names)
                        .set_expression_attribute_values(values)
                        .build()
                        .map_err(build_error)?,
                )
                .build(),
        })
    }

    /// Plan a write and apply it as one transaction whose conditions check
    /// every key still holds what the plan read, re-planning when one does
    /// not.
    async fn write<F>(&self, plan: F) -> Result<(), RepositoryError>
    where
        F: for<'a, 'b> Fn(
            &'a mut DdbReader<'b>,
        )
            -> futures::future::BoxFuture<'a, Result<Vec<Op>, RepositoryError>>,
    {
        for attempt in 0..MAX_WRITE_ATTEMPTS {
            if attempt > 0 {
                tokio::time::sleep(retry_delay(attempt)).await;
            }
            let ops = {
                let mut reader = DdbReader(self);
                plan(&mut reader).await?
            };
            let items = ops
                .iter()
                .map(|op| self.transact_item(op))
                .collect::<Result<Vec<_>, _>>()?;
            match self
                .client
                .transact_write_items()
                .set_transact_items(Some(items))
                .send()
                .await
            {
                Ok(_) => return Ok(()),
                Err(err)
                    if err
                        .as_service_error()
                        .is_some_and(|e| e.is_transaction_canceled_exception()) =>
                {
                    debug!(
                        "DynamoDB transaction cancelled, re-planning: {}",
                        DisplayErrorContext(&err)
                    );
                }
                Err(err) => {
                    return Err(RepositoryError::QueryFailed(format!(
                        "Failed to write records: {}",
                        DisplayErrorContext(err)
                    )));
                }
            }
        }
        Err(RepositoryError::QueryFailed(format!(
            "the items this write depends on kept changing; gave up after {MAX_WRITE_ATTEMPTS} \
             attempts"
        )))
    }

    pub fn client(&self) -> &Client {
        &self.client
    }

    pub fn table_name(&self) -> &str {
        &self.table_name
    }
}

impl std::fmt::Debug for DynamoDbStorage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DynamoDbStorage")
            .field("table_name", &self.table_name)
            .finish()
    }
}

fn not_found(key: &TrustRecordKey) -> RepositoryError {
    RepositoryError::RecordNotFound(format!("Record not found: {}", key.sk()))
}

/// How many times a write is re-planned when an item it read changed before
/// its transaction ran.
const MAX_WRITE_ATTEMPTS: usize = 5;

/// Strongly consistent reads for the planners.
pub(crate) struct DdbReader<'a>(&'a DynamoDbStorage);

#[async_trait::async_trait]
impl KeyedReader for DdbReader<'_> {
    async fn read_at(&mut self, storage_key: &str) -> Result<Option<TrustRecord>, RepositoryError> {
        self.0.get_record(storage_key).await
    }

    /// Both items in one `TransactGetItems`, which reads them at one point in
    /// time.
    async fn read_pair(
        &mut self,
        first: &str,
        second: &str,
    ) -> Result<(Option<TrustRecord>, Option<TrustRecord>), RepositoryError> {
        let get = |storage_key: &str| -> Result<TransactGetItem, RepositoryError> {
            Ok(TransactGetItem::builder()
                .get(
                    Get::builder()
                        .table_name(&self.0.table_name)
                        .set_key(Some(DynamoDbStorage::build_key(storage_key)))
                        .build()
                        .map_err(|e| RepositoryError::QueryFailed(e.to_string()))?,
                )
                .build())
        };
        let response = self
            .0
            .client
            .transact_get_items()
            .transact_items(get(first)?)
            .transact_items(get(second)?)
            .send()
            .await
            .map_err(|err| {
                RepositoryError::ConnectionFailed(format!(
                    "Failed to fetch items from DynamoDB: {}",
                    DisplayErrorContext(err)
                ))
            })?;
        let mut items = response
            .responses
            .unwrap_or_default()
            .into_iter()
            .map(|response| response.item);
        let mut next = || {
            items
                .next()
                .flatten()
                .map(|item| {
                    serde_dynamo::from_item(item)
                        .map_err(|e| RepositoryError::SerializationFailed(e.to_string()))
                })
                .transpose()
        };
        Ok((next()?, next()?))
    }
}

/// How long to wait before re-planning a cancelled transaction: an
/// exponential base (20, 40, 80, 160 ms) plus up to as much again at random,
/// so writers that collided do not collide again in step.
fn retry_delay(attempt: usize) -> std::time::Duration {
    let base_ms = 20u64 << attempt.saturating_sub(1).min(8);
    let jitter_ms = (uuid::Uuid::new_v4().as_u128() % u128::from(base_ms)) as u64;
    std::time::Duration::from_millis(base_ms + jitter_ms)
}

#[async_trait::async_trait]
impl TrustRecordRepository for DynamoDbStorage {
    async fn find_by_query(
        &self,
        query: TrustRecordQuery,
    ) -> Result<Option<TrustRecord>, RepositoryError> {
        debug!(
            entity = query.entity_id.as_str(),
            authority = query.authority_id.as_str(),
            action = query.action.as_str(),
            resource = query.resource.as_str(),
            "Querying trust record in DynamoDB"
        );
        self.find(&TrustRecordKey::from_query(&query)).await
    }
}

#[async_trait::async_trait]
impl TrustRecordAdminRepository for DynamoDbStorage {
    async fn create(&self, record: TrustRecord) -> Result<(), RepositoryError> {
        debug!(
            entity = record.entity_id().as_str(),
            authority = record.authority_id().as_str(),
            action = record.action().as_str(),
            resource = record.resource().as_str(),
            "Creating trust record in DynamoDB"
        );
        self.write(|reader| {
            let record = record.clone();
            Box::pin(async move { plan_create(reader, &record).await })
        })
        .await
    }

    async fn update(&self, record: TrustRecord) -> Result<(), RepositoryError> {
        debug!(
            entity = record.entity_id().as_str(),
            authority = record.authority_id().as_str(),
            action = record.action().as_str(),
            resource = record.resource().as_str(),
            "Updating trust record in DynamoDB"
        );
        self.write(|reader| {
            let record = record.clone();
            Box::pin(async move { plan_update(reader, &record).await })
        })
        .await
    }

    async fn delete(&self, query: TrustRecordQuery) -> Result<(), RepositoryError> {
        debug!(
            entity = query.entity_id.as_str(),
            authority = query.authority_id.as_str(),
            action = query.action.as_str(),
            resource = query.resource.as_str(),
            "Deleting trust record from DynamoDB"
        );
        let key = TrustRecordKey::from_query(&query);
        self.write(|reader| {
            let key = key.clone();
            Box::pin(async move { plan_delete(reader, &key).await })
        })
        .await
    }

    async fn list(&self) -> Result<TrustRecordList, RepositoryError> {
        debug!("Listing all trust records from DynamoDB");

        let items: Vec<_> = self
            .client
            .query()
            .table_name(&self.table_name)
            .key_condition_expression("PK = :pk AND begins_with(SK, :sk_prefix)")
            .expression_attribute_values(":pk", AttributeValue::S(TrustRecordKey::pk().to_string()))
            .expression_attribute_values(
                ":sk_prefix",
                AttributeValue::S(crate::domain::key::TR_SK_PREFIX.to_string()),
            )
            .into_paginator()
            .items()
            .send()
            .try_collect()
            .await
            .map_err(|err| RepositoryError::QueryFailed(format!("Failed to query table: {err}")))?;

        let mut entries = Vec::with_capacity(items.len());

        for item in items {
            let storage_key = match item.get(SK_ATTR) {
                Some(AttributeValue::S(storage_key)) => storage_key.clone(),
                _ => String::new(),
            };
            let record: TrustRecord = serde_dynamo::from_item(item)
                .map_err(|e| RepositoryError::SerializationFailed(e.to_string()))?;
            entries.push((storage_key, record));
        }

        Ok(TrustRecordList::new(dedupe_listing(entries)))
    }

    async fn read(&self, query: TrustRecordQuery) -> Result<TrustRecord, RepositoryError> {
        debug!(
            entity = query.entity_id.as_str(),
            authority = query.authority_id.as_str(),
            action = query.action.as_str(),
            resource = query.resource.as_str(),
            "Reading trust record from DynamoDB"
        );
        let key = TrustRecordKey::from_query(&query);
        self.find(&key).await?.ok_or_else(|| not_found(&key))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn retry_delays_grow_and_stay_bounded() {
        for attempt in 1..MAX_WRITE_ATTEMPTS {
            let base = 20u64 << (attempt - 1);
            for _ in 0..50 {
                let delay = retry_delay(attempt).as_millis() as u64;
                assert!(
                    (base..2 * base).contains(&delay),
                    "attempt {attempt}: {delay} ms"
                );
            }
        }
    }
}
