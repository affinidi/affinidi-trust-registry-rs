use std::collections::HashMap;

use anyhow::Result as AnyResult;
use aws_config::BehaviorVersion;
use aws_sdk_dynamodb::{Client, types::AttributeValue};
use aws_types::region::Region;
use tracing::debug;

use crate::{
    configs::DynamoDbStorageConfig,
    domain::{
        TrustRecord,
        key::{TrustRecordKey, dedupe_listing, verified_record},
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
            if endpoint_url.contains("local") {
                loader = loader.test_credentials();
            }
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
            .send()
            .await
            .map_err(|err| {
                RepositoryError::ConnectionFailed(format!(
                    "Failed to fetch item from DynamoDB: {err}",
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

    /// Read the record `key` names, from its current sort key or, for a record
    /// an older release wrote, from the earlier unescaped sort key.
    async fn lookup(&self, key: &TrustRecordKey) -> Result<Option<TrustRecord>, RepositoryError> {
        let current = key.sk();
        let stored = self.get_record(&current).await?;
        if let Some(record) = verified_record(key, &current, stored) {
            return Ok(Some(record));
        }
        self.lookup_earlier(key).await
    }

    /// The record `key` names if it is stored under the earlier unescaped sort
    /// key, checked against `key`'s identifiers.
    async fn lookup_earlier(
        &self,
        key: &TrustRecordKey,
    ) -> Result<Option<TrustRecord>, RepositoryError> {
        let Some(legacy) = key.legacy_sk() else {
            return Ok(None);
        };
        let stored = self.get_record(&legacy).await?;
        Ok(verified_record(key, &legacy, stored))
    }

    async fn delete_item(
        &self,
        storage_key: &str,
        must_exist: bool,
    ) -> Result<bool, RepositoryError> {
        let mut request = self
            .client
            .delete_item()
            .table_name(&self.table_name)
            .set_key(Some(Self::build_key(storage_key)));
        if must_exist {
            request = request.condition_expression("attribute_exists(SK)");
        }
        match request.send().await {
            Ok(_) => Ok(true),
            Err(err) if err.to_string().contains("ConditionalCheckFailed") => Ok(false),
            Err(err) => Err(RepositoryError::QueryFailed(format!(
                "Failed to delete record: {err}"
            ))),
        }
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

        self.lookup(&TrustRecordKey::from_query(&query)).await
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

        let key = TrustRecordKey::from_record(&record);
        let already_exists =
            || RepositoryError::RecordAlreadyExists(format!("Record already exists: {}", key.sk()));
        if self.lookup_earlier(&key).await?.is_some() {
            return Err(already_exists());
        }

        self.client
            .put_item()
            .table_name(&self.table_name)
            .set_item(Some(Self::build_item(&record, &key.sk())?))
            .condition_expression("attribute_not_exists(SK)")
            .send()
            .await
            .map_err(|err| {
                if err.to_string().contains("ConditionalCheckFailed") {
                    already_exists()
                } else {
                    RepositoryError::QueryFailed(format!("Failed to create record: {err}"))
                }
            })?;

        Ok(())
    }

    async fn update(&self, record: TrustRecord) -> Result<(), RepositoryError> {
        debug!(
            entity = record.entity_id().as_str(),
            authority = record.authority_id().as_str(),
            action = record.action().as_str(),
            resource = record.resource().as_str(),
            "Updating trust record in DynamoDB"
        );

        let key = TrustRecordKey::from_record(&record);
        let storage_key = key.sk();
        let item = Self::build_item(&record, &storage_key)?;

        let result = self
            .client
            .put_item()
            .table_name(&self.table_name)
            .set_item(Some(item.clone()))
            .condition_expression("attribute_exists(SK)")
            .send()
            .await;
        match result {
            Ok(_) => return Ok(()),
            Err(err) if err.to_string().contains("ConditionalCheckFailed") => {}
            Err(err) => {
                return Err(RepositoryError::QueryFailed(format!(
                    "Failed to update record: {err}"
                )));
            }
        }

        // Not under the current key: it may still be under the earlier one.
        if self.lookup_earlier(&key).await?.is_none() {
            return Err(not_found(&key));
        }
        // Write the current key first: if the process stops before the earlier
        // key is removed, both copies exist and the current one wins on read
        // and in listings.
        self.client
            .put_item()
            .table_name(&self.table_name)
            .set_item(Some(item))
            .send()
            .await
            .map_err(|err| {
                RepositoryError::QueryFailed(format!("Failed to update record: {err}"))
            })?;
        if let Some(legacy) = key.legacy_sk() {
            self.delete_item(&legacy, false).await?;
        }

        Ok(())
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

        // The earlier key goes first: if the process stops in between, the
        // record is still present under its current key and a retried delete
        // removes it. The other order would leave the old copy to be read back.
        let mut deleted = false;
        if self.lookup_earlier(&key).await?.is_some()
            && let Some(legacy) = key.legacy_sk()
        {
            deleted |= self.delete_item(&legacy, true).await?;
        }
        deleted |= self.delete_item(&key.sk(), true).await?;

        if !deleted {
            return Err(not_found(&key));
        }
        Ok(())
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
        self.lookup(&key).await?.ok_or_else(|| not_found(&key))
    }
}
