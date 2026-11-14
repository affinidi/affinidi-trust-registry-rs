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

## Querying with `trql-client` over HTTPS

The registry also answers Trust Tasks on `POST /trust-tasks` (read-only). Give
it a DID with `.did(...)`: `trql-client` addresses every document to the
registry's DID, and the registry refuses a document addressed to anyone else.
The fixture listens on loopback, so the client's transport must be told the
address is trusted.

```rust
use std::sync::Arc;
use test_trust_registry::TestTrustRegistry;
use trql_client::{HttpsTransport, HttpsTransportConfig, TrqlClient, TrqpQuery};

let tr = TestTrustRegistry::builder()
    .did("did:example:test-registry")
    .record(seed)
    .spawn()
    .await?;
let transport = HttpsTransport::new(
    HttpsTransportConfig::new(tr.base_url()).with_allow_non_public_addresses(true),
)?;
let client = TrqlClient::new(Arc::new(transport), "did:example:test-registry");
let answer = client.authorization(TrqpQuery::new(entity, authority, action, resource)).await?;
```

`tests/trql_client_https.rs` does this, and runs with a plain `cargo test`.

## Mediator-wired transports (`--features mediator` / `tsp`)

`spawn_with_mediator(&TestMediatorHandle)` mints the registry's DIDComm identity
on an `affinidi-messaging-test-mediator` and starts the DIDComm Trust Task
listener (and, with `--features tsp` and `.tsp(true)`, TSP). The handle's
`did()` is where a test client addresses Trust Task envelopes.

```rust
use affinidi_messaging_test_mediator::TestEnvironment;
use test_trust_registry::TestTrustRegistry;

let env = TestEnvironment::spawn().await?;
let tr = TestTrustRegistry::builder()
    .record(seed)
    // May send record-mutating Trust Tasks, each only for records under its
    // own DID as `authority_id`: a write under any other authority is refused
    // with `permissionDenied`.
    .admin_dids(vec![client_did.clone()])
    .spawn_with_mediator(&env.mediator)
    .await?;
let registry_did = tr.did().unwrap(); // address Trust Tasks here
```

`tests/mediator.rs` drives full client → mediator → registry → mediator →
client round trips, both with hand-built envelopes and through `trql-client`'s
`DidcommTransport` and `TspTransport` (including two concurrent queries on one
transport, and a correlated reply from a third identity, which must not answer
the query):

- **DIDComm**: `recognition_round_trips_over_didcomm`, the signed record writes,
  `trql_client_queries_the_registry_over_didcomm`,
  `trql_client_ignores_a_reply_from_a_third_identity_over_didcomm`.
- **TSP**: `recognition_round_trips_over_tsp`,
  `trql_client_queries_the_registry_over_tsp`.

The routed tests are `#[ignore]`d (the mediator stack has a heavy cold compile)
and need what `affinidi-messaging-test-mediator` needs: a Redis on
`127.0.0.1:6379`. Run them with:

```sh
cargo test -p test-trust-registry --features mediator --test mediator -- --ignored
cargo test -p test-trust-registry --features tsp      --test mediator -- --ignored
```

A TSP test of your own needs three things the TSP tests show:

1. `.tsp(true)` on the builder (a `tsp` build alone ignores TSP frames);
2. `TestEnvironment::spawn_with_direct_delivery()`: client and registry share
   the test mediator, and its default refuses local direct delivery, which TSP
   uses between them;
3. a TSP relationship with the registry before the first Trust Task (Spec
   Rev 3 §7.2.2): see `relate_with_registry` in `tests/mediator.rs`.

With TSP on, the registry keeps its TSP relationships in
`./.trust-registry/messaging/` under the test's working directory (ignored by
git), or under `TR_MESSAGING_STORE_PATH`.

## Scope

- **REST/TRQP** (`/recognition`, `/authorization`, health) and read-only
  **`POST /trust-tasks`** over in-memory `LocalStorage`: always on.
- **DIDComm Trust Tasks** via `spawn_with_mediator` (`--features mediator`):
  round trips proven end to end, by hand and through `trql-client`.
- **TSP Trust Tasks** via `spawn_with_mediator` with `.tsp(true)`
  (`--features tsp`): round trips proven end to end, by hand and through
  `trql-client`.
