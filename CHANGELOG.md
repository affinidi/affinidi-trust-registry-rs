# Changelog

All notable changes to this project will be documented in this file.

## Changelog History

### Why are there skipped version numbers?

Some versions are omitted because certain CI/CD deployment iterations included minor tooling or deployment‑only adjustments that did not affect application behaviour or source code.

Missing versions simply reflect internal deployment‑related patches.

---

## [0.9.0] – 2026‑07‑25

### Added

- **The Trust Registry can be embedded in a host application.** `TrustRegistry`
  (via `TrustRegistry::builder`) assembles a registry that binds no socket,
  reads no environment, installs no tracing subscriber and never calls
  `process::exit`. A host mounts `registry.router()` into its own axum app —
  deliberately with no CORS layer and no `/health`, both of which belong to the
  host — or skips HTTP entirely and feeds documents to
  `registry.task_handler()`. See the "Embedding the Trust Registry" section of
  the README and `examples/embedded_axum.rs`, which is a complete host
  application.

  Injectable: the repository, capability definitions, the capability-state
  store, the message-id dedup store, the proof verifier, the DIDComm source and
  the shutdown token. Each falls back to what the standalone service uses.

- **`DidCommSource` decides who owns the mediator websocket.** The mediator
  permits one per DID, so a host that already holds the registry's connection
  can now lend it (`SharedAtm`) or keep the receive loop and route documents in
  itself (`HostDriven`, with `TrustRegistry::route_didcomm_envelope`). Default
  is `Managed` — the registry opens its own, as before.

- **`TrustRegistryConfig::embedded(data_dir)` and `DidcommConfig::disabled()`**
  for building configuration programmatically.

### Changed

- **Optional backends are behind features, all default-on.** New `storage-csv`,
  `storage-ddb`, `storage-redis`, `loaders-aws` and `standalone` features join
  the existing `storage-fjall`, so an embedded registry can build with
  `default-features = false` and skip the AWS SDKs, Redis, `serde_dynamo`,
  `dotenvy`, `crossterm` and `vti-secrets` (~750 crates to ~620). Standalone
  builds are unchanged.

- **`vti-secrets` is optional, behind the `secrets-*` features.** It is a
  workspace member of `verifiable-trust-infrastructure`, so a VTC embedding the
  registry would otherwise carry both its own path copy and a crates.io copy of
  it (and of `vti-common` beneath it). `vta` and `dev-tools` now imply
  `secrets-config`, since both genuinely need a secret store.

- **`didwebvh-rs` 0.1 → 0.6**, matching the rest of the ecosystem and removing
  the last duplicate `affinidi-did-common` / `affinidi-data-integrity` chain
  from the graph. `setup_did_web_tr` is now `async`, because 0.6 made
  `create_log_entry` async.

- **One shared apply path across every transport.** The
  `validate_basic` → write-ACL → proof-verification → dispatch sequence, and
  the `authorize_write` that was copy-pasted between the DIDComm and TSP
  bindings, now live once in `trust_tasks::handler::TaskHandler`. Three
  behaviour changes follow:
  - `registry/did/rotate` now works over TSP; it was previously intercepted
    only in the DIDComm binding and came back `UnsupportedType` over TSP.
  - An unauthenticated caller is denied every write on the ACL, rather than
    relying on the read-only dispatcher registering no write types. Anonymous
    writes over HTTP now return `PermissionDenied` instead of
    `UnsupportedType`.
  - The Data-Integrity verifier is built once in `serve()` and shared, instead
    of separately inside the listener.

- **`TR_CAPABILITY_STATE` moved onto `ServerConfig`.** `serve()` no longer reads
  it from the environment, so an embedded registry's capability-state location
  is not decided by the host's environment. Unset keeps the previous default.
  `configs` is now the only module in the crate that reads environment
  variables.

- **`vta-sdk` updated to 0.19**, along with the `affinidi-tdk` chain and
  `vti-secrets`, so the graph carries a single `vta-sdk` node. Required for any
  host in the `verifiable-trust-infrastructure` workspace, which patches
  `vta-sdk` to a local 0.19.

---

## [0.8.1] – 2026‑07‑24

### Fixed

- **Secret-store env configuration now covers every backend field.**
  `secrets_config_from_env()` previously mapped only four `vault_*` fields, so
  selecting the HashiCorp Vault backend from the environment left
  `vault_auth_method` at its `kubernetes` default with no way to supply the
  required `vault_k8s_role` — the backend failed to initialise the moment
  `TR_SECRETS_VAULT_ADDR` was set. Token auth was likewise unreachable (the
  token was read but the auth method could not be switched).

  - **Impact:** the Vault backend (`secrets-vault`) is now usable from the
    environment for all three auth methods (`kubernetes`, `token`, `approle`).
  - Newly mapped: `TR_SECRETS_VAULT_AUTH_METHOD`, `TR_SECRETS_VAULT_K8S_ROLE`,
    `TR_SECRETS_VAULT_K8S_MOUNT`, `TR_SECRETS_VAULT_K8S_JWT_PATH`,
    `TR_SECRETS_VAULT_KV_MOUNT`, `TR_SECRETS_VAULT_SECRET_KEY`,
    `TR_SECRETS_VAULT_APPROLE_ROLE_ID`, `TR_SECRETS_VAULT_APPROLE_SECRET_ID`,
    `TR_SECRETS_VAULT_APPROLE_MOUNT`, `TR_SECRETS_VAULT_SKIP_VERIFY`, and
    `TR_SECRETS_K8S_SECRET_KEY`.
  - The canonical `VAULT_ADDR` / `VAULT_NAMESPACE` / `VAULT_TOKEN` /
    `VAULT_SKIP_VERIFY` names are now honoured (taking precedence over the
    `TR_SECRETS_VAULT_*` spelling), matching `vta-service`.

### Documentation

- Expanded the README "Secret-store backends" section into a full per-backend
  setup reference (activating variable, defaults, priority order, in-cluster
  Vault example) and added a matching commented block to `.env.example`.

## [0.6.0] – 2026‑02‑18

### Changed

- Updated record key structure for consistent key construction across storage adapters.
  - **New key format:** `TR#{authority}#{action}#{resource}#{entity}`
  - Aligns with a single‑table design (PK/SK pattern) for DynamoDB and Redis.

  - **Impact:**  
    Affects **DynamoDB and Redis** deployments only.  
    Records stored using the previous key format remain in the database, but TRQP lookups will return **"Record not found"** because the application now generates keys using the updated structure.  
    File‑based (CSV) storage is **not affected**, as the change does not alter how CSV data is stored.

  - **Required Action:**  
    - Export existing records from DynamoDB or Redis.  
    - Re-import the exported data.  
      - During re‑import, the system will **automatically generate new keys** using the updated format — no manual key reconstruction is required.

---

## [0.5.0] – 2026‑02‑18

### Changed

- Updated Rust version requirement from 1.88.0 to 1.90.0.
- Aligned record type serialisation across storage adapters:
  - `assertion` → `authorization`
  - `Authorization` → `authorization`

  - **Impact:**  
    Affects **CSV file-based storage** only.  
    Records using old identifiers (`assertion`, `Authorization`) will not match queries expecting the new standardised type (`authorization`).  
    Schema and API behaviour remain unchanged.  
    DynamoDB and Redis storage **are not affected**, as they already use the corrected type mapping.

  - **Required Action:**  
    - Update existing CSV records to replace `assertion` and `Authorization` with `authorization`.  
    - Review and update code paths that rely on matching the old type names (filters, lookups, assertions, UI labels).  
    - Update tests that compare record types as string values.

### Updated Dependencies

- affinidi-tdk: 0.3 → 0.4  
- aws-sdk-dynamodb: 1.100 → 1.104  
- aws-sdk-ssm: 1.100 → 1.103  
- aws-sdk-secretsmanager: 1.95 → 1.99  
- redis: 1.0.2 → 1.0.3  

---

## [0.4.0] – 2026‑02‑05

### Added

- Graceful shutdown for background tasks using `CancellationToken`.  
- `did:web` support with AWS SSM and Secrets Manager integration.  
- Error handling improvements using `thiserror` (`unwrap_used` and `expect_used` lints enforced workspace‑wide).  
- TRQL and TRQP client crates.  
- DynamoDB, Redis, and file‑based (CSV) storage backends.  
- Unit and integration tests for DIDComm and HTTP servers.

### Changed

- Merged `didcomm-server` and `http-server` into unified `trust-registry` crate.  
- Migrated to full Result propagation pattern (removed `.unwrap()` calls).  
- Workspace restructured into four members: `test-client`, `trust-registry`, `trql-client`, `trqp`.

### Fixed

- `bytes` vulnerability.  
- Resource leaks on shutdown.  
- Redundant message processing in DIDComm server.

### Updated Dependencies

- affinidi-tdk: 0.2.4 → 0.3  
- axum: 0.8.1 → 0.8.7  
- axum-server: 0.7 → 0.8  
- tokio: 1.47 → 1.48  
- aws-sdk-dynamodb: 1.47 → 1.100  
- aws-sdk-ssm: 1.47 → 1.100  
- aws-sdk-secretsmanager: 1.47 → 1.95  
- redis: 0.27 → 1.0.2  
- serde: 1.0.136 → 1.0.228  

---

## [0.1.0] – 2025‑10‑13

### Added

- Initial workspace setup with HTTP server foundation.  
- Core dependencies:  
  - axum 0.8.1  
  - tokio 1.47  
  - tracing  
  - serde  
  - chrono  