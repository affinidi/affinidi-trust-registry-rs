use std::collections::HashMap;

use anyhow::Result as AnyResult;
use aws_config::BehaviorVersion;
use aws_sdk_dynamodb::{Client, types::AttributeValue};
use aws_types::region::Region;
use tracing::debug;

use crate::{
    domain::TrustRecord,
    storage::repository::{RepositoryError, TrustRecordQuery, TrustRecordRepository},
};

const PK_ATTR: &str = "PK";
const SK_ATTR: &str = "SK";

#[derive(Debug, Clone)]
pub struct DynamoDbConfig {
    pub table_name: String,
    pub region: Option<String>,
    pub endpoint_url: Option<String>,
    pub profile: Option<String>,
}

impl DynamoDbConfig {
    pub fn new(table_name: impl Into<String>) -> Self {
        Self {
            table_name: table_name.into(),
            region: None,
            endpoint_url: None,
            profile: None,
        }
    }

    pub fn set_region(mut self, region: Option<String>) -> Self {
        self.region = region;
        self
    }

    pub fn set_endpoint_url(mut self, endpoint_url: Option<String>) -> Self {
        self.endpoint_url = endpoint_url;
        self
    }

    pub fn set_profile(mut self, profile: Option<String>) -> Self {
        self.profile = profile;
        self
    }
}

#[derive(Clone)]
pub struct DynamoDbStorage {
    client: Client,
    table_name: String,
}

impl DynamoDbStorage {
    pub async fn new(config: DynamoDbConfig) -> AnyResult<Self> {
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
