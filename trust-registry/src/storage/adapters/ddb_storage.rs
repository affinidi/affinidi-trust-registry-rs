use std::collections::HashMap;

use anyhow::Result as AnyResult;
use aws_config::BehaviorVersion;
use aws_sdk_dynamodb::{Client, types::AttributeValue};
use aws_types::region::Region;
use tracing::debug;

use crate::{
    configs::DynamoDbStorageConfig,
    domain::{TrustRecord, key::TrustRecordKey},
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

    fn build_key(query: &TrustRecordQuery) -> HashMap<String, AttributeValue> {
        let record_key = TrustRecordKey::from_query(query);
        let mut key = HashMap::with_capacity(2);
        key.insert(
            PK_ATTR.to_string(),
            AttributeValue::S(TrustRecordKey::pk().to_string()),
        );
        key.insert(SK_ATTR.to_string(), AttributeValue::S(record_key.sk()));
        key
    }

    fn build_key_from_record(record: &TrustRecord) -> HashMap<String, AttributeValue> {
        let record_key = TrustRecordKey::from_record(record);
        let mut key = HashMap::with_capacity(2);
        key.insert(
            PK_ATTR.to_string(),
            AttributeValue::S(TrustRecordKey::pk().to_string()),
        );
        key.insert(SK_ATTR.to_string(), AttributeValue::S(record_key.sk()));
        key
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

        let key = Self::build_key(&query);

        let response = self
            .client
            .get_item()
            .table_name(&self.table_name)
            .set_key(Some(key))
            .send()
            .await
            .map_err(|err| {
                RepositoryError::ConnectionFailed(format!(
                    "Failed to fetch item from DynamoDB: {err}",
                ))
            })?;

        if let Some(item) = response.item {
            let trust_record: TrustRecord = serde_dynamo::from_item(item)
                .map_err(|e| RepositoryError::SerializationFailed(e.to_string()))?;
            return Ok(Some(trust_record));
        }

        Ok(None)
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

        let mut item: HashMap<String, AttributeValue> = serde_dynamo::to_item(&record)
            .map_err(|e| RepositoryError::SerializationFailed(e.to_string()))?;

        let key = Self::build_key_from_record(&record);
        item.extend(key);

        self.client
            .put_item()
            .table_name(&self.table_name)
            .set_item(Some(item))
            .condition_expression("attribute_not_exists(SK)")
            .send()
            .await
            .map_err(|err| {
                if err.to_string().contains("ConditionalCheckFailed") {
                    RepositoryError::RecordAlreadyExists(format!(
                        "Record already exists: {}#{}#{}#{}",
                        record.authority_id(),
                        record.action(),
                        record.resource(),
                        record.entity_id()
                    ))
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

        let mut item: HashMap<String, AttributeValue> = serde_dynamo::to_item(&record)
            .map_err(|e| RepositoryError::SerializationFailed(e.to_string()))?;

        let key = Self::build_key_from_record(&record);
        item.extend(key);

        self.client
            .put_item()
            .table_name(&self.table_name)
            .set_item(Some(item))
            .condition_expression("attribute_exists(SK)")
            .send()
            .await
            .map_err(|err| {
                if err.to_string().contains("ConditionalCheckFailed") {
                    RepositoryError::RecordNotFound(format!(
                        "Record not found: {}#{}#{}#{}",
                        record.authority_id(),
                        record.action(),
                        record.resource(),
                        record.entity_id()
                    ))
                } else {
                    RepositoryError::QueryFailed(format!("Failed to update record: {err}"))
                }
            })?;

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

        let key = Self::build_key(&query);

        self.client
            .delete_item()
            .table_name(&self.table_name)
            .set_key(Some(key))
            .condition_expression("attribute_exists(SK)")
            .send()
            .await
            .map_err(|err| {
                if err.to_string().contains("ConditionalCheckFailed") {
                    RepositoryError::RecordNotFound(format!(
                        "Record not found: {}#{}#{}#{}",
                        query.authority_id, query.action, query.resource, query.entity_id
                    ))
                } else {
                    RepositoryError::QueryFailed(format!("Failed to delete record: {err}"))
                }
            })?;

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

        let mut records = Vec::with_capacity(items.len());

        for item in items {
            let record: TrustRecord = serde_dynamo::from_item(item)
                .map_err(|e| RepositoryError::SerializationFailed(e.to_string()))?;
            records.push(record);
        }

        Ok(TrustRecordList::new(records))
    }

    async fn read(&self, query: TrustRecordQuery) -> Result<TrustRecord, RepositoryError> {
        debug!(
            entity = query.entity_id.as_str(),
            authority = query.authority_id.as_str(),
            action = query.action.as_str(),
            resource = query.resource.as_str(),
            "Reading trust record from DynamoDB"
        );

        let key = Self::build_key(&query);

        let response = self
            .client
            .get_item()
            .table_name(&self.table_name)
            .set_key(Some(key))
            .send()
            .await
            .map_err(|err| {
                RepositoryError::ConnectionFailed(format!(
                    "Failed to fetch item from DynamoDB: {err}",
                ))
            })?;

        if let Some(item) = response.item {
            let trust_record: TrustRecord = serde_dynamo::from_item(item)
                .map_err(|e| RepositoryError::SerializationFailed(e.to_string()))?;
            return Ok(trust_record);
        }

        Err(RepositoryError::RecordNotFound(format!(
            "Record not found: {}#{}#{}#{}",
            query.authority_id, query.action, query.resource, query.entity_id
        )))
    }
}
