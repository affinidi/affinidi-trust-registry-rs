use std::collections::HashMap;

use anyhow::Result as AnyResult;
use aws_config::BehaviorVersion;
use aws_sdk_dynamodb::{Client, types::AttributeValue};
use aws_types::region::Region;
use tracing::debug;

use crate::{
    configs::DynamoDbStorageConfig,
    domain::TrustRecord,
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

        let shared_config = loader.load().await;
        let client = Client::new(&shared_config);
        // TODO: describe table to check connection to fail fast?

        Ok(Self::with_client(client, config.table_name))
    }

    pub fn with_client(client: Client, table_name: impl Into<String>) -> Self {
        Self {
            client,
            table_name: table_name.into(),
        }
    }

    fn build_key(&self, query: &TrustRecordQuery) -> HashMap<String, AttributeValue> {
        let key_value = format!(
            "{}|{}|{}",
            query.entity_id, query.authority_id, query.assertion_id
        );
        let mut key = HashMap::with_capacity(2);
        key.insert(PK_ATTR.to_string(), AttributeValue::S(key_value.clone()));
        key.insert(SK_ATTR.to_string(), AttributeValue::S(key_value));
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
            assertion = query.assertion_id.as_str(),
            "Querying trust record in DynamoDB"
        );

        let key = self.build_key(&query);

        let response = self
            .client
            .get_item()
            .table_name(&self.table_name)
            .set_key(Some(key))
            .send()
            .await
            .map_err(|err| {
                RepositoryError::ConnectionFailed(format!(
                    "Failed to fetch item from DynamoDB: {}",
                    err
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
            assertion = record.assertion_id().as_str(),
            "Creating trust record in DynamoDB"
        );

        let mut item: HashMap<String, AttributeValue> = serde_dynamo::to_item(&record)
            .map_err(|e| RepositoryError::SerializationFailed(e.to_string()))?;

        // Add PK and SK for DynamoDB
        let key_value = format!(
            "{}|{}|{}",
            record.entity_id(),
            record.authority_id(),
            record.assertion_id()
        );
        item.insert(PK_ATTR.to_string(), AttributeValue::S(key_value.clone()));
        item.insert(SK_ATTR.to_string(), AttributeValue::S(key_value));

        // Use condition expression to prevent overwriting existing records
        self.client
            .put_item()
            .table_name(&self.table_name)
            .set_item(Some(item))
            .condition_expression("attribute_not_exists(PK)")
            .send()
            .await
            .map_err(|err| {
                if err.to_string().contains("ConditionalCheckFailed") {
                    RepositoryError::RecordAlreadyExists(format!(
                        "Record already exists: {}|{}|{}",
                        record.entity_id(),
                        record.authority_id(),
                        record.assertion_id()
                    ))
                } else {
                    RepositoryError::QueryFailed(format!("Failed to create record: {}", err))
                }
            })?;

        Ok(())
    }

    async fn update(&self, record: TrustRecord) -> Result<(), RepositoryError> {
        debug!(
            entity = record.entity_id().as_str(),
            authority = record.authority_id().as_str(),
            assertion = record.assertion_id().as_str(),
            "Updating trust record in DynamoDB"
        );

        let mut item: HashMap<String, AttributeValue> = serde_dynamo::to_item(&record)
            .map_err(|e| RepositoryError::SerializationFailed(e.to_string()))?;

        // Add PK and SK
        let key_value = format!(
            "{}|{}|{}",
            record.entity_id(),
            record.authority_id(),
            record.assertion_id()
        );
        item.insert(PK_ATTR.to_string(), AttributeValue::S(key_value.clone()));
        item.insert(SK_ATTR.to_string(), AttributeValue::S(key_value));

        // Use condition expression to ensure record exists before updating
        self.client
            .put_item()
            .table_name(&self.table_name)
            .set_item(Some(item))
            .condition_expression("attribute_exists(PK)")
            .send()
            .await
            .map_err(|err| {
                if err.to_string().contains("ConditionalCheckFailed") {
                    RepositoryError::RecordNotFound(format!(
                        "Record not found: {}|{}|{}",
                        record.entity_id(),
                        record.authority_id(),
                        record.assertion_id()
                    ))
                } else {
                    RepositoryError::QueryFailed(format!("Failed to update record: {}", err))
                }
            })?;

        Ok(())
    }

    async fn delete(&self, query: TrustRecordQuery) -> Result<(), RepositoryError> {
        debug!(
            entity = query.entity_id.as_str(),
            authority = query.authority_id.as_str(),
            assertion = query.assertion_id.as_str(),
            "Deleting trust record from DynamoDB"
        );

        let key = self.build_key(&query);

        self.client
            .delete_item()
            .table_name(&self.table_name)
            .set_key(Some(key))
            .condition_expression("attribute_exists(PK)")
            .send()
            .await
            .map_err(|err| {
                if err.to_string().contains("ConditionalCheckFailed") {
                    RepositoryError::RecordNotFound(format!(
                        "Record not found: {}|{}|{}",
                        query.entity_id, query.authority_id, query.assertion_id
                    ))
                } else {
                    RepositoryError::QueryFailed(format!("Failed to delete record: {}", err))
                }
            })?;

        Ok(())
    }

    async fn list(&self) -> Result<TrustRecordList, RepositoryError> {
        debug!("Listing all trust records from DynamoDB");

        let response = self
            .client
            .scan()
            .table_name(&self.table_name)
            .send()
            .await
            .map_err(|err| {
                RepositoryError::QueryFailed(format!("Failed to scan table: {}", err))
            })?;

        let items = response.items.unwrap_or_default();
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
            assertion = query.assertion_id.as_str(),
            "Reading trust record from DynamoDB"
        );

        let key = self.build_key(&query);

        let response = self
            .client
            .get_item()
            .table_name(&self.table_name)
            .set_key(Some(key))
            .send()
            .await
            .map_err(|err| {
                RepositoryError::ConnectionFailed(format!(
                    "Failed to fetch item from DynamoDB: {}",
                    err
                ))
            })?;

        if let Some(item) = response.item {
            let trust_record: TrustRecord = serde_dynamo::from_item(item)
                .map_err(|e| RepositoryError::SerializationFailed(e.to_string()))?;
            return Ok(trust_record);
        }

        Err(RepositoryError::RecordNotFound(format!(
            "Record not found: {}|{}|{}",
            query.entity_id, query.authority_id, query.assertion_id
        )))
    }
}
