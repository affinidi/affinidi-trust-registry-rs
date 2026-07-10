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

A full client → mediator → registry → mediator → client **DIDComm** Trust Task
round-trip is exercised by `tests/mediator.rs` (`--ignored`, since the mediator
stack has a heavy cold compile).

## Scope

- **REST/TRQP** (`/recognition`, `/authorization`, health) over in-memory `LocalStorage` — always on.
- **DIDComm Trust Tasks** via `spawn_with_mediator` (`--features mediator`) — round-trip proven end-to-end.
- **TSP Trust Tasks** listener starts under `--features tsp`; a full routed TSP round-trip (client↔registry TSP routing) is a follow-up.
