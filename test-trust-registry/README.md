# test-trust-registry

Embedded [Trust Registry](../trust-registry) fixture for integration tests.

Mirrors `affinidi-messaging-test-mediator`'s `TestMediator::spawn()` model: boots
an in-process Trust Registry on an ephemeral `127.0.0.1:0` port over an in-memory
store, and hands back a handle with the bound URL and a `shutdown()`. No
environment variables, no external database, no ports to reserve.

```rust
use test_trust_registry::TestTrustRegistry;

#[tokio::test]
async fn queries_a_seeded_registry() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let tr = TestTrustRegistry::spawn().await?;

    let resp = reqwest::Client::new()
        .post(format!("{}/recognition", tr.base_url()))
        .json(&serde_json::json!({
            "entity_id": "did:example:entity",
            "authority_id": "did:example:authority",
            "action": "issue",
            "resource": "vc",
        }))
        .send()
        .await?;
    assert_eq!(resp.status(), 200);

    tr.shutdown().await;
    Ok(())
}
```

Seed records with the builder:

```rust
let tr = TestTrustRegistry::builder().records(my_records).spawn().await?;
```

## Scope

- **Now:** the REST/TRQP surface (`/recognition`, `/authorization`, health) over an in-memory `LocalStorage`.
- **Planned:** `spawn_with_mediator(&TestMediatorHandle)` to wire the DIDComm and TSP Trust Task listeners against a spawned test mediator, for end-to-end Trust Task tests.
