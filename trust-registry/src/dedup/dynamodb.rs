//! The record of accepted document identifiers in DynamoDB (feature
//! `storage-ddb`), shared by every registry replica on one table.
//!
//! Each document is one item in the records' table, with the partition key
//! `PK` = its [`message_key`](super::message_key) (`MID#<issuer>#<id>`) and
//! the sort key `SK` = `MID`, apart from the records' `PK = TR` partition. Its
//! attributes are `digest`, `state` (`inflight` or `done`), `expires_at`
//! (milliseconds since the epoch), `ttl` (the same, in seconds) and, while in
//! flight, `token` and `lease_until`; once done, `outcome` (the
//! [`StoredOutcome`] as JSON).
//!
//! - **claim** is a conditional `PutItem` that succeeds only when the item is
//!   absent, has expired, or is an in-flight claim whose lease has lapsed;
//!   when the condition fails, the item that failed it says why (conflict,
//!   replay or in flight).
//! - **complete** is a conditional `PutItem` of the outcome that succeeds
//!   only while the claim's token still holds the item.
//! - **release** is a conditional `DeleteItem` on the same condition.
//!
//! Expiry is decided in those conditions, from the registry's clock, so it
//! does not depend on DynamoDB's TTL. Enabling TTL on the table with the
//! attribute `ttl` lets DynamoDB delete expired items; without it they stay
//! until overwritten. Replicas' clocks should agree to well within the
//! in-flight lease. Entries are bounded by their expiry only.

use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use aws_sdk_dynamodb::Client;
use aws_sdk_dynamodb::error::{DisplayErrorContext, SdkError};
use aws_sdk_dynamodb::types::{AttributeValue, ReturnValuesOnConditionCheckFailure};

use super::{Claim, ClaimToken, DedupError, MessageIdStore, StoredOutcome};
use crate::configs::MessageIdStoreConfig;

const PK_ATTR: &str = "PK";
const SK_ATTR: &str = "SK";
/// The sort key of every message-id item.
const SK_VALUE: &str = "MID";
const INFLIGHT: &str = "inflight";
const DONE: &str = "done";

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX))
        .unwrap_or(0)
}

fn millis(duration: std::time::Duration) -> u64 {
    u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
}

fn number(value: u64) -> AttributeValue {
    AttributeValue::N(value.to_string())
}

fn string(value: impl Into<String>) -> AttributeValue {
    AttributeValue::S(value.into())
}

fn sdk_unavailable<E, R>(context: &str, err: SdkError<E, R>) -> DedupError
where
    E: std::error::Error + 'static,
    R: std::fmt::Debug,
{
    DedupError::Unavailable(format!("DynamoDB {context}: {}", DisplayErrorContext(&err)))
}

fn text<'a>(item: &'a HashMap<String, AttributeValue>, name: &str) -> Option<&'a str> {
    match item.get(name) {
        Some(AttributeValue::S(value)) => Some(value),
        _ => None,
    }
}

/// The DynamoDB-backed [`MessageIdStore`]. Built by
/// [`DynamoDbStorage`](crate::storage::adapters::ddb_storage::DynamoDbStorage)
/// over its own client and table.
#[derive(Clone)]
pub struct DynamoDbMessageIdStore {
    client: Client,
    table_name: String,
    config: MessageIdStoreConfig,
}

impl DynamoDbMessageIdStore {
    pub fn new(
        client: Client,
        table_name: impl Into<String>,
        config: MessageIdStoreConfig,
    ) -> Self {
        Self {
            client,
            table_name: table_name.into(),
            config,
        }
    }

    fn key(key: &str) -> HashMap<String, AttributeValue> {
        HashMap::from([
            (PK_ATTR.to_string(), string(key)),
            (SK_ATTR.to_string(), string(SK_VALUE)),
        ])
    }

    /// What an item that refused a claim means for it.
    fn refused_by(
        key: &str,
        digest: &str,
        item: &HashMap<String, AttributeValue>,
    ) -> Result<Claim, DedupError> {
        if text(item, "digest") != Some(digest) {
            return Ok(Claim::Conflict);
        }
        if text(item, "state") != Some(DONE) {
            return Ok(Claim::InFlight);
        }
        let outcome = text(item, "outcome").ok_or_else(|| {
            DedupError::Unavailable(format!("the entry for {key} has no outcome"))
        })?;
        let outcome: StoredOutcome = serde_json::from_str(outcome).map_err(|e| {
            DedupError::Unavailable(format!("the outcome stored for {key} does not decode: {e}"))
        })?;
        Ok(Claim::Replay(Box::new(outcome)))
    }

    /// The item as stored now, for a refused claim whose error did not carry
    /// it.
    async fn current(
        &self,
        key: &str,
    ) -> Result<Option<HashMap<String, AttributeValue>>, DedupError> {
        Ok(self
            .client
            .get_item()
            .table_name(&self.table_name)
            .set_key(Some(Self::key(key)))
            .consistent_read(true)
            .send()
            .await
            .map_err(|e| sdk_unavailable("GetItem", e))?
            .item)
    }

    /// The condition that the claim `token` names still holds the item.
    fn held_by(
        token: &ClaimToken,
    ) -> (
        &'static str,
        HashMap<String, String>,
        HashMap<String, AttributeValue>,
    ) {
        (
            "#token = :token AND #state = :inflight",
            HashMap::from([
                ("#token".to_string(), "token".to_string()),
                ("#state".to_string(), "state".to_string()),
            ]),
            HashMap::from([
                (":token".to_string(), string(token.as_str())),
                (":inflight".to_string(), string(INFLIGHT)),
            ]),
        )
    }
}

#[async_trait]
impl MessageIdStore for DynamoDbMessageIdStore {
    async fn claim(&self, key: &str, digest: &str) -> Result<Claim, DedupError> {
        let token = ClaimToken::new();
        let now = now_ms();
        let lease_until = now.saturating_add(millis(self.config.in_flight_lease));
        let expires_at = lease_until.saturating_add(millis(self.config.retention));
        let mut item = Self::key(key);
        item.extend([
            ("digest".to_string(), string(digest)),
            ("state".to_string(), string(INFLIGHT)),
            ("token".to_string(), string(token.as_str())),
            ("lease_until".to_string(), number(lease_until)),
            ("expires_at".to_string(), number(expires_at)),
            ("ttl".to_string(), number(expires_at.div_ceil(1000))),
        ]);
        let put = self
            .client
            .put_item()
            .table_name(&self.table_name)
            .set_item(Some(item))
            .condition_expression(
                "attribute_not_exists(PK) OR #expires < :now \
                 OR (#state = :inflight AND #lease < :now)",
            )
            .expression_attribute_names("#expires", "expires_at")
            .expression_attribute_names("#state", "state")
            .expression_attribute_names("#lease", "lease_until")
            .expression_attribute_values(":now", number(now))
            .expression_attribute_values(":inflight", string(INFLIGHT))
            .return_values_on_condition_check_failure(ReturnValuesOnConditionCheckFailure::AllOld)
            .send()
            .await;
        match put {
            Ok(_) => Ok(Claim::Acquired(token)),
            Err(err) => match err.as_service_error() {
                Some(e) if e.is_conditional_check_failed_exception() => {
                    let returned = match e {
                        aws_sdk_dynamodb::operation::put_item::PutItemError::ConditionalCheckFailedException(
                            failed,
                        ) => failed.item().cloned(),
                        _ => None,
                    };
                    let item = match returned {
                        Some(item) => Some(item),
                        // Not every DynamoDB implementation returns the item.
                        None => self.current(key).await?,
                    };
                    match item {
                        Some(item) => Self::refused_by(key, digest, &item),
                        // Removed since: the claim lost a race; the caller's
                        // sender retries.
                        None => Ok(Claim::InFlight),
                    }
                }
                _ => Err(sdk_unavailable("PutItem", err)),
            },
        }
    }

    async fn complete(
        &self,
        key: &str,
        token: &ClaimToken,
        outcome: &StoredOutcome,
    ) -> Result<(), DedupError> {
        let outcome =
            serde_json::to_string(outcome).map_err(|e| DedupError::Unavailable(e.to_string()))?;
        let expires_at = now_ms().saturating_add(millis(self.config.retention));
        let (condition, mut names, mut values) = Self::held_by(token);
        names.extend([
            ("#outcome".to_string(), "outcome".to_string()),
            ("#expires".to_string(), "expires_at".to_string()),
            ("#ttl".to_string(), "ttl".to_string()),
            ("#lease".to_string(), "lease_until".to_string()),
        ]);
        values.extend([
            (":done".to_string(), string(DONE)),
            (":outcome".to_string(), string(outcome)),
            (":expires".to_string(), number(expires_at)),
            (":ttl".to_string(), number(expires_at.div_ceil(1000))),
        ]);
        let put = self
            .client
            .update_item()
            .table_name(&self.table_name)
            .set_key(Some(Self::key(key)))
            .update_expression(
                "SET #state = :done, #outcome = :outcome, #expires = :expires, #ttl = :ttl \
                 REMOVE #token, #lease",
            )
            .condition_expression(condition)
            .set_expression_attribute_names(Some(names))
            .set_expression_attribute_values(Some(values))
            .send()
            .await;
        match put {
            Ok(_) => Ok(()),
            Err(err)
                if err
                    .as_service_error()
                    .is_some_and(|e| e.is_conditional_check_failed_exception()) =>
            {
                Err(DedupError::ClaimLost(format!(
                    "{key} is no longer held by this claim"
                )))
            }
            Err(err) => Err(sdk_unavailable("UpdateItem", err)),
        }
    }

    async fn release(&self, key: &str, token: &ClaimToken) -> Result<(), DedupError> {
        let (condition, names, values) = Self::held_by(token);
        let delete = self
            .client
            .delete_item()
            .table_name(&self.table_name)
            .set_key(Some(Self::key(key)))
            .condition_expression(condition)
            .set_expression_attribute_names(Some(names))
            .set_expression_attribute_values(Some(values))
            .send()
            .await;
        match delete {
            Ok(_) => Ok(()),
            // Not this claim's any more: nothing to release.
            Err(err)
                if err
                    .as_service_error()
                    .is_some_and(|e| e.is_conditional_check_failed_exception()) =>
            {
                Ok(())
            }
            Err(err) => Err(sdk_unavailable("DeleteItem", err)),
        }
    }
}
