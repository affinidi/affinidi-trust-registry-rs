use std::str::FromStr;
use trust_registry::{
    domain::*,
    storage::{adapters::redis_storage::RedisStorage, repository::*},
};

async fn get_test_storage() -> Option<RedisStorage> {
    // Use a test Redis instance, skip if not available
    match RedisStorage::new("redis://127.0.0.1:6379").await {
        Ok(storage) => Some(storage),
        Err(_) => {
            println!("Redis not available, skipping integration test");
            None
        }
    }
}

async fn cleanup_test_data(storage: &RedisStorage) {
    // Use the list and delete all records approach since we can't access internals
    if let Ok(list) = storage.list().await {
        for record in list.into_records() {
            let query = TrustRecordQuery::new(
                record.entity_id().clone(),
                record.authority_id().clone(),
                record.action().clone(),
                record.resource().clone(),
            );
            let _ = storage.delete(query).await;
        }
    }
}

fn create_test_record(
    entity: &str,
    authority: &str,
    action: &str,
    resource: &str,
    recognized: bool,
    authorized: bool,
    record_type: &str,
) -> TrustRecord {
    TrustRecordBuilder::new()
        .entity_id(EntityId::new(entity))
        .authority_id(AuthorityId::new(authority))
        .action(Action::new(action))
        .resource(Resource::new(resource))
        .recognized(recognized)
        .authorized(authorized)
        .record_type(RecordType::from_str(record_type).unwrap())
        .build()
        .unwrap()
}

#[tokio::test]
async fn test_redis_create_record() {
    let Some(storage) = get_test_storage().await else {
        return;
    };
    cleanup_test_data(&storage).await;

    let record = create_test_record(
        "did:example:clinic1",
        "did:example:healthdept",
        "issue",
        "HealthCredential",
        true,
        true,
        "assertion",
    );

    let result = storage.create(record.clone()).await;
    assert!(result.is_ok());

    // Verify the record was created
    let query = TrustRecordQuery::new(
        EntityId::new("did:example:clinic1"),
        AuthorityId::new("did:example:healthdept"),
        Action::new("issue"),
        Resource::new("HealthCredential"),
    );
    let retrieved = storage.read(query).await;
    assert!(retrieved.is_ok());

    cleanup_test_data(&storage).await;
}

#[tokio::test]
async fn test_redis_read_record() {
    let Some(storage) = get_test_storage().await else {
        return;
    };
    cleanup_test_data(&storage).await;

    // Create a record
    let record = create_test_record(
        "did:example:clinic1",
        "did:example:healthdept",
        "issue",
        "HealthCredential",
        true,
        true,
        "assertion",
    );
    storage.create(record).await.unwrap();

    // Test reading the record
    let query = TrustRecordQuery::new(
        EntityId::new("did:example:clinic1"),
        AuthorityId::new("did:example:healthdept"),
        Action::new("issue"),
        Resource::new("HealthCredential"),
    );

    let retrieved = storage.read(query).await.unwrap();
    assert_eq!(retrieved.entity_id().as_str(), "did:example:clinic1");
    assert_eq!(retrieved.authority_id().as_str(), "did:example:healthdept");
    assert_eq!(retrieved.action().as_str(), "issue");
    assert_eq!(retrieved.resource().as_str(), "HealthCredential");
    assert!(retrieved.is_authorized());
    assert!(retrieved.is_recognized());

    cleanup_test_data(&storage).await;
}

#[tokio::test]
async fn test_redis_update_record() {
    let Some(storage) = get_test_storage().await else {
        return;
    };
    cleanup_test_data(&storage).await;

    // Create initial record
    let record = create_test_record(
        "did:example:clinic1",
        "did:example:healthdept",
        "issue",
        "HealthCredential",
        true,
        true,
        "assertion",
    );
    storage.create(record).await.unwrap();

    // Update the record
    let updated_record = create_test_record(
        "did:example:clinic1",
        "did:example:healthdept",
        "issue",
        "HealthCredential",
        false,
        false,
        "assertion",
    );

    let result = storage.update(updated_record).await;
    assert!(result.is_ok());

    // Verify the update
    let query = TrustRecordQuery::new(
        EntityId::new("did:example:clinic1"),
        AuthorityId::new("did:example:healthdept"),
        Action::new("issue"),
        Resource::new("HealthCredential"),
    );
    let retrieved = storage.read(query).await.unwrap();
    assert!(!retrieved.is_authorized());
    assert!(!retrieved.is_recognized());

    cleanup_test_data(&storage).await;
}

#[tokio::test]
async fn test_redis_delete_record() {
    let Some(storage) = get_test_storage().await else {
        return;
    };
    cleanup_test_data(&storage).await;

    // Create a record first
    let record = create_test_record(
        "did:example:clinic1",
        "did:example:healthdept",
        "issue",
        "HealthCredential",
        true,
        true,
        "assertion",
    );
    storage.create(record).await.unwrap();

    // Delete the record
    let query = TrustRecordQuery::new(
        EntityId::new("did:example:clinic1"),
        AuthorityId::new("did:example:healthdept"),
        Action::new("issue"),
        Resource::new("HealthCredential"),
    );

    let result = storage.delete(query.clone()).await;
    assert!(result.is_ok());

    // Verify deletion
    let read_result = storage.read(query).await;
    assert!(read_result.is_err());
    assert!(matches!(
        read_result,
        Err(RepositoryError::RecordNotFound(_))
    ));

    cleanup_test_data(&storage).await;
}

#[tokio::test]
async fn test_redis_list_records() {
    let Some(storage) = get_test_storage().await else {
        return;
    };
    cleanup_test_data(&storage).await;

    // Create multiple records
    let record1 = create_test_record(
        "did:example:clinic1",
        "did:example:healthdept",
        "issue",
        "HealthCredential",
        true,
        true,
        "assertion",
    );
    let record2 = create_test_record(
        "did:example:hospital1",
        "did:example:healthdept",
        "verify",
        "MedicalRecord",
        true,
        false,
        "recognition",
    );
    let record3 = create_test_record(
        "did:example:pharmacy1",
        "did:example:healthdept",
        "dispense",
        "Prescription",
        false,
        true,
        "assertion",
    );

    storage.create(record1).await.unwrap();
    storage.create(record2).await.unwrap();
    storage.create(record3).await.unwrap();

    // Test list operation
    let list = storage.list().await.unwrap();
    assert_eq!(list.records().len(), 3);

    cleanup_test_data(&storage).await;
}

#[tokio::test]
async fn test_redis_find_by_query_success() {
    let Some(storage) = get_test_storage().await else {
        return;
    };
    cleanup_test_data(&storage).await;

    // Create test record
    let record = create_test_record(
        "did:example:issuer1",
        "did:example:authority1",
        "issue",
        "DriverLicense",
        true,
        true,
        "assertion",
    );
    storage.create(record).await.unwrap();

    // Test find_by_query
    let query = TrustRecordQuery::new(
        EntityId::new("did:example:issuer1"),
        AuthorityId::new("did:example:authority1"),
        Action::new("issue"),
        Resource::new("DriverLicense"),
    );

    let result = storage.find_by_query(query).await.unwrap();
    assert!(result.is_some());

    let record = result.unwrap();
    assert_eq!(record.entity_id().as_str(), "did:example:issuer1");
    assert_eq!(record.authority_id().as_str(), "did:example:authority1");
    assert_eq!(record.action().as_str(), "issue");
    assert_eq!(record.resource().as_str(), "DriverLicense");

    cleanup_test_data(&storage).await;
}

#[tokio::test]
async fn test_redis_find_by_query_not_found() {
    let Some(storage) = get_test_storage().await else {
        return;
    };
    cleanup_test_data(&storage).await;

    // Test query for non-existent record
    let query = TrustRecordQuery::new(
        EntityId::new("did:example:nonexistent"),
        AuthorityId::new("did:example:authority1"),
        Action::new("issue"),
        Resource::new("DriverLicense"),
    );

    let result = storage.find_by_query(query).await.unwrap();
    assert!(result.is_none());

    cleanup_test_data(&storage).await;
}

// Error handling tests - one per error scenario

#[tokio::test]
async fn test_redis_create_duplicate_record_error() {
    let Some(storage) = get_test_storage().await else {
        return;
    };
    cleanup_test_data(&storage).await;

    let record = create_test_record(
        "did:example:test",
        "did:example:authority",
        "action",
        "resource",
        true,
        true,
        "assertion",
    );

    // Create record first time - should succeed
    storage.create(record.clone()).await.unwrap();

    // Attempt to create duplicate - should fail
    let duplicate_result = storage.create(record).await;
    assert!(duplicate_result.is_err());
    assert!(matches!(
        duplicate_result,
        Err(RepositoryError::RecordAlreadyExists(_))
    ));

    cleanup_test_data(&storage).await;
}

#[tokio::test]
async fn test_redis_update_nonexistent_record_error() {
    let Some(storage) = get_test_storage().await else {
        return;
    };
    cleanup_test_data(&storage).await;

    let non_existent_record = create_test_record(
        "did:example:nonexistent",
        "did:example:authority",
        "action",
        "resource",
        true,
        true,
        "assertion",
    );

    let update_result = storage.update(non_existent_record).await;
    assert!(update_result.is_err());
    assert!(matches!(
        update_result,
        Err(RepositoryError::RecordNotFound(_))
    ));

    cleanup_test_data(&storage).await;
}

#[tokio::test]
async fn test_redis_delete_nonexistent_record_error() {
    let Some(storage) = get_test_storage().await else {
        return;
    };
    cleanup_test_data(&storage).await;

    let delete_query = TrustRecordQuery::new(
        EntityId::new("did:example:nonexistent"),
        AuthorityId::new("did:example:authority"),
        Action::new("action"),
        Resource::new("resource"),
    );

    let delete_result = storage.delete(delete_query).await;
    assert!(delete_result.is_err());
    assert!(matches!(
        delete_result,
        Err(RepositoryError::RecordNotFound(_))
    ));

    cleanup_test_data(&storage).await;
}

#[tokio::test]
async fn test_redis_read_nonexistent_record_error() {
    let Some(storage) = get_test_storage().await else {
        return;
    };
    cleanup_test_data(&storage).await;

    let read_query = TrustRecordQuery::new(
        EntityId::new("did:example:nonexistent"),
        AuthorityId::new("did:example:authority"),
        Action::new("action"),
        Resource::new("resource"),
    );

    let read_result = storage.read(read_query).await;
    assert!(read_result.is_err());
    assert!(matches!(
        read_result,
        Err(RepositoryError::RecordNotFound(_))
    ));

    cleanup_test_data(&storage).await;
}

// Comprehensive workflow test validating the complete CRUD flow

#[tokio::test]
async fn test_redis_complete_crud_workflow() {
    let Some(storage) = get_test_storage().await else {
        return;
    };
    cleanup_test_data(&storage).await;

    // Step 1: Create multiple records
    let record1 = create_test_record(
        "did:example:clinic1",
        "did:example:healthdept",
        "issue",
        "HealthCredential",
        true,
        true,
        "assertion",
    );
    let record2 = create_test_record(
        "did:example:hospital1",
        "did:example:healthdept",
        "verify",
        "MedicalRecord",
        true,
        false,
        "recognition",
    );
    let record3 = create_test_record(
        "did:example:pharmacy1",
        "did:example:healthdept",
        "dispense",
        "Prescription",
        false,
        true,
        "assertion",
    );

    storage.create(record1.clone()).await.unwrap();
    storage.create(record2.clone()).await.unwrap();
    storage.create(record3.clone()).await.unwrap();

    // Step 2: Verify all records exist via list
    let list = storage.list().await.unwrap();
    assert_eq!(list.records().len(), 3);

    // Step 3: Read a specific record
    let query1 = TrustRecordQuery::new(
        EntityId::new("did:example:clinic1"),
        AuthorityId::new("did:example:healthdept"),
        Action::new("issue"),
        Resource::new("HealthCredential"),
    );
    let retrieved = storage.read(query1.clone()).await.unwrap();
    assert_eq!(retrieved.entity_id().as_str(), "did:example:clinic1");
    assert!(retrieved.is_authorized());
    assert!(retrieved.is_recognized());

    // Step 4: Update a record
    let updated_record = create_test_record(
        "did:example:clinic1",
        "did:example:healthdept",
        "issue",
        "HealthCredential",
        false,
        false,
        "assertion",
    );
    storage.update(updated_record).await.unwrap();

    // Step 5: Verify update took effect
    let retrieved_after_update = storage.read(query1.clone()).await.unwrap();
    assert!(!retrieved_after_update.is_authorized());
    assert!(!retrieved_after_update.is_recognized());

    // Step 6: Delete a record
    storage.delete(query1.clone()).await.unwrap();

    // Step 7: Verify deletion
    let result = storage.read(query1).await;
    assert!(result.is_err());
    assert!(matches!(result, Err(RepositoryError::RecordNotFound(_))));

    // Step 8: Verify list count decreased
    let list_after_delete = storage.list().await.unwrap();
    assert_eq!(list_after_delete.records().len(), 2);

    // Step 9: Query remaining records
    let query2 = TrustRecordQuery::new(
        EntityId::new("did:example:hospital1"),
        AuthorityId::new("did:example:healthdept"),
        Action::new("verify"),
        Resource::new("MedicalRecord"),
    );
    let found = storage.find_by_query(query2).await.unwrap();
    assert!(found.is_some());

    cleanup_test_data(&storage).await;
}

#[tokio::test]
async fn test_redis_context_serialization() {
    let Some(storage) = get_test_storage().await else {
        return;
    };
    cleanup_test_data(&storage).await;

    // Create a record with complex context
    let context = serde_json::json!({
        "governance_framework": "Healthcare Trust Framework",
        "version": "2.0",
        "issuer_type": "clinic",
        "metadata": {
            "location": "US-CA",
            "accreditation": ["ISO-9001", "HIPAA"]
        }
    });

    let mut record = create_test_record(
        "did:example:clinic",
        "did:example:healthdept",
        "issue",
        "HealthCredential",
        true,
        true,
        "assertion",
    );

    record = record.merge_contexts(Context::new(context.clone()));

    // Create and retrieve the record
    storage.create(record.clone()).await.unwrap();

    let query = TrustRecordQuery::new(
        EntityId::new("did:example:clinic"),
        AuthorityId::new("did:example:healthdept"),
        Action::new("issue"),
        Resource::new("HealthCredential"),
    );

    let retrieved = storage.read(query).await.unwrap();

    // Verify context is properly serialized and deserialized
    let retrieved_context = retrieved.context().as_value();
    assert_eq!(
        retrieved_context["governance_framework"],
        "Healthcare Trust Framework"
    );
    assert_eq!(retrieved_context["version"], "2.0");
    assert_eq!(
        retrieved_context["metadata"]["accreditation"][0],
        "ISO-9001"
    );

    cleanup_test_data(&storage).await;
}
