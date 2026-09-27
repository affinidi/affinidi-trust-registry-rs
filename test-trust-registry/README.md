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

    // A `registry/recognition` Trust Task over the HTTPS binding.
    let resp = reqwest::Client::new()
        .post(format!("{}/trust-tasks", tr.base_url()))
        .json(&serde_json::json!({
            "id": "urn:uuid:3f0c6a52-0d7e-4a8e-9d55-1c2b7c9e0a11",
            "type": "https://trusttasks.org/spec/registry/recognition/0.1",
            "payload": {
                "entity_id": "did:example:entity",
                "authority_id": "did:example:authority",
                "action": "issue",
                "resource": "vc",
            },
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

## Mediator-wired transports (`--features mediator` / `tsp`)

`spawn_with_mediator(&TestMediatorHandle)` mints the registry's DIDComm identity
on an `affinidi-messaging-test-mediator` and starts the DIDComm (and, under
`--features tsp`, TSP) Trust Task listeners. The handle's `did()` is where a test
client addresses Trust Task envelopes.

```rust
use affinidi_messaging_test_mediator::TestEnvironment;
use test_trust_registry::TestTrustRegistry;

let env = TestEnvironment::spawn().await?;
let tr = TestTrustRegistry::builder()
    .record(seed)
    .admin_dids(vec![client_did.clone()]) // may send record-mutating Trust Tasks
    .spawn_with_mediator(&env.mediator)
    .await?;
let registry_did = tr.did().unwrap(); // address Trust Tasks here
```

Full client → mediator → registry → mediator → client round-trips of
`registry/recognition` and `registry/authorization` are exercised over **DIDComm**
and **TSP** by `tests/mediator.rs` (`--ignored`, since the mediator stack has a
heavy cold compile).

## Scope

- **HTTPS Trust Tasks** (`POST /trust-tasks`, health) over in-memory `LocalStorage` — always on.
- **DIDComm Trust Tasks** via `spawn_with_mediator` (`--features mediator`) — round-trip proven end-to-end.
- **TSP Trust Tasks** via `spawn_with_mediator` (`--features tsp`) — round-trip proven end-to-end.
