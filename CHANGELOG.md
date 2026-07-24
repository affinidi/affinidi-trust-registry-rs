# Changelog

All notable changes to this project will be documented in this file.

## Changelog History

### Why are there skipped version numbers?

Some versions are omitted because certain CI/CD deployment iterations included minor tooling or deployment‑only adjustments that did not affect application behaviour or source code.

Missing versions simply reflect internal deployment‑related patches.

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