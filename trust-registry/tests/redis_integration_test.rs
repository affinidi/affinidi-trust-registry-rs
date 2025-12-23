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
async fn test_redis_full_crud_workflow() {
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

    // Test CREATE operations
    storage.create(record1.clone()).await.unwrap();
    storage.create(record2.clone()).await.unwrap();
    storage.create(record3.clone()).await.unwrap();

    // Test LIST operation
    let list = storage.list().await.unwrap();
    assert_eq!(list.records().len(), 3);

    // Test READ operation
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

    // Test UPDATE operation
    let updated_record = create_test_record(
        "did:example:clinic1",
        "did:example:healthdept",
        "issue",
        "HealthCredential",
        false, // Changed
        false, // Changed
        "assertion",
    );

    storage.update(updated_record).await.unwrap();

    let retrieved_after_update = storage.read(query1.clone()).await.unwrap();
    assert!(!retrieved_after_update.is_authorized());
    assert!(!retrieved_after_update.is_recognized());

    // Test DELETE operation
    storage.delete(query1.clone()).await.unwrap();

    let result = storage.read(query1).await;
    assert!(result.is_err());
    assert!(matches!(result, Err(RepositoryError::RecordNotFound(_))));

    // Verify list count after delete
    let list_after_delete = storage.list().await.unwrap();
    assert_eq!(list_after_delete.records().len(), 2);

    cleanup_test_data(&storage).await;
}

#[tokio::test]
async fn test_redis_query_operations() {
    let Some(storage) = get_test_storage().await else {
        return;
    };
    cleanup_test_data(&storage).await;

    // Create test records
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

    // Test find_by_query (from TrustRecordRepository trait)
    let query = TrustRecordQuery::new(
        EntityId::new("did:example:issuer1"),
        AuthorityId::new("did:example:authority1"),
        Action::new("issue"),
        Resource::new("DriverLicense"),
    );

    let result = storage.find_by_query(query.clone()).await.unwrap();
    assert!(result.is_some());

    let record = result.unwrap();
    assert_eq!(record.entity_id().as_str(), "did:example:issuer1");
    assert_eq!(record.authority_id().as_str(), "did:example:authority1");
    assert_eq!(record.action().as_str(), "issue");
    assert_eq!(record.resource().as_str(), "DriverLicense");

    // Test query for non-existent record
    let non_existent_query = TrustRecordQuery::new(
        EntityId::new("did:example:nonexistent"),
        AuthorityId::new("did:example:authority1"),
        Action::new("issue"),
        Resource::new("DriverLicense"),
    );

    let result = storage.find_by_query(non_existent_query).await.unwrap();
    assert!(result.is_none());

    cleanup_test_data(&storage).await;
}

#[tokio::test]
async fn test_redis_error_handling() {
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

    // Test creating duplicate record
    storage.create(record.clone()).await.unwrap();
    let duplicate_result = storage.create(record.clone()).await;
    assert!(duplicate_result.is_err());
    assert!(matches!(
        duplicate_result,
        Err(RepositoryError::RecordAlreadyExists(_))
    ));

    // Test updating non-existent record
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

    // Test deleting non-existent record
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

    // Test reading non-existent record
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
