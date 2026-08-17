# Changelog

All notable changes to this project will be documented in this file.

## Changelog History

### Why are there skipped version numbers?

Some versions are omitted because certain CI/CD deployment iterations included minor tooling or deployment‑only adjustments that did not affect application behaviour or source code.

Missing versions simply reflect internal deployment‑related patches.

---

## [0.14.0] – 2026‑08‑17

### Changed

- **Trust Tasks 0.6 → 0.9, `vta-sdk` 0.23 → 0.25, and the messaging stack with
  them** (`affinidi-messaging-sdk` 0.19.8, `-mediator` 0.18.19, `-test-mediator`
  0.2.51, `vti-common` 0.12.1).

  **No source changed.** Three breaking framework releases sit in the gap and
  none of them reaches this repo:

  - **0.7.0** made `StandardCode` `#[non_exhaustive]`. Nothing here matches on
    it. It is also the last time a new framework error code will break a
    downstream `match`.
  - **0.8.0** added `StandardCode::Cancelled` and the `trust-task-control/0.1`
    payloads. Additive in Rust, because of the attribute above.
  - **0.9.0** gave `consume_inbound` a required `PayloadPolicy` argument
    (SPEC.md §7.2 item 2) and replaced `ValidatedPayload::SCHEMA_JSON` with
    `Payload::PAYLOAD_SCHEMA`. This repo calls neither — it has no
    `consume_inbound` call site and used no `SCHEMA_JSON`.

  The whole `trust-tasks-*` family has to move together: `trust-tasks-rs`'s core
  types cross the public API of `-https` / `-didcomm` / `-proof` / `-tsp`, so a
  graph mixing majors does not type-check.

  `vta-sdk` moves two minors in the same change deliberately. It is not
  cosmetic: `vta-sdk` 0.23.2 is built on `trust-tasks-rs` 0.6, so pinning the
  framework to 0.9 without moving the SDK would put two copies of
  `trust-tasks-rs` in the graph — which fails as a handful of `E0308`s naming
  two identical-looking types, pointing at a call site rather than at the
  lockfile that caused it.

  Verified with `cargo tree -d -e normal,build` **and** `-e normal,build,dev`:
  neither lists `trust-tasks-rs`, `trust-tasks-capability-client`, `vta-sdk`,
  `vti-common` or `affinidi-tdk`.

- **The spec versions this registry speaks are unchanged, and were checked
  rather than assumed.** Every Trust Task URI here is `registry/*/0.1`
  (`authorization`, `did/rotate`, `recognition`, `record/put`, `record/query`)
  plus the `binding/didcomm/0.1` envelope, and `0.1` remains the only published
  version of each. A library bump does not move which specification version a
  service speaks — the generated `v0_1` / `v0_2` / `v0_3` modules coexist — so
  the two are independent decisions and this release makes only the first.

## [0.13.0] – 2026‑08‑14

### Added

- **The registry now checks, at startup, whether the DID document it publishes
  matches what it can actually serve** — and says so, per transport.

  `TransportFlags::validate` already refuses `ENABLE_TSP=true` on a build without
  the `tsp` feature, but that guards the document this process *builds* and
  serves at `/.well-known/did.json`. It cannot guard the document peers resolve:
  a `did:webvh` log is published by the VTA / DID-hosting service at provisioning
  time and never revisited, so the two can disagree indefinitely — and
  `ENABLE_TSP` defaults to `false`.

  That gap cost a live deployment days. `#tsp` was published at provisioning,
  the service ran with `ENABLE_TSP` unset, and every TSP frame was dropped
  unread. Peers read the document, correctly chose the highest-preference
  transport it advertised, sent, and waited; the VTC reported
  `registry_status=degraded` with a 60-second timeout and no way to tell that the
  registry was answering on a different protocol. Both ends behaved exactly as
  designed and the deployment was still broken.

  On boot the registry now resolves its own DID over the network — the published
  view, not the local mirror — and reports each disagreement:

  - advertised but unservable → `ERROR`, naming both remedies (rebuild with the
    feature and set the flag, or drop the service entry).
  - servable but unadvertised → `INFO`. Normal mid-rollout.

  It is **advisory and never fails startup**. Unknown is not the same as bad: a
  resolver blip must not stop a registry from answering DIDComm. `vtc-service`
  draws the same line — it refuses to boot only on the *local* document it
  controls, and treats the resolved view as advisory.

  Matching is on the service **`type`**, never the `#id` fragment, which is an
  arbitrary label (`#tsp` here, `#tsp-transport` upstream, `#vta-didcomm` from an
  older template). `type` is also read as either a string or an array, because
  both occur — the reference mediator publishes `["DIDCommMessaging"]` while this
  registry writes a bare string, and a reader handling only one shape sees no
  services at all on the other.

## [0.12.0] – 2026‑08‑14

### Changed

- **Adopts the Trust Tasks framework 0.6 libraries** (`trust-tasks-rs` 0.6.1,
  `-proof` / `-https` / `-tsp` / `-didcomm` 0.6.0), up from 0.3. Three breaking
  releases sit in between and none of them changes this repo's source:
  - **0.4.0** made digest-carrying payload members the generated
    `DigestMultibase` newtype rather than `String`.
  - **0.5.0** added an optional `ceremony` member to the `TrustTask<P>`
    envelope, recording that a document is one step of a Trust Ceremony. It
    breaks struct-literal construction and exhaustive destructuring only; this
    repo builds documents through `TrustTask::for_payload` / `respond_with` and
    `reject_with_recipient`, so nothing here constructs one by literal.
  - **0.6.0** narrowed `DigestMultibase` to the two multibase headers W3C
    Controlled Identifiers 1.0 §2.4 normatively requires — `z` (base58btc) and
    `u` (base64url-no-pad) — and enforces each alphabet rather than assuming it.

  That last one is **visible to consumers**: a digest a client previously got
  away with (base32, base16, base64pad, or a `z`-prefixed string that was never
  valid base58) is now rejected at parse. The wire format is unchanged for
  conforming values. A registry whose purpose is interoperability should not
  accept digests a conforming verifier may be unable to read, so this is the
  intended direction — but it is why this is a minor and not a patch.

- Tracks `affinidi-messaging-sdk` 0.19.7, `affinidi-messaging-mediator` 0.18.17
  and `affinidi-messaging-test-mediator` 0.2.50. 0.19.7 carries two inbound-stream
  fixes that matter to this service (affinidi/affinidi-tdk-rs#708): a torn-down
  profile no longer spins its inbound poll at 2Hz forever, and an inbound TSP
  frame that cannot be unpacked is now deleted from the mediator instead of
  being redelivered on every reconnect and restart.

- **Moves `vta-sdk` 0.21 → 0.23**, which is what keeps the graph to one copy of
  everything. Taking `trust-tasks-rs` 0.6 alone left **two** copies of it — 0.6.1
  directly, and 0.4.1 behind the published `vti-common` — and taking the newer
  `vti-common` on its own added a **second `vta-sdk`** (0.21.21 beside 0.23.1)
  rather than failing, because a caret requirement lets Cargo satisfy both by
  duplicating.
  
  Neither duplicate broke the build here, since no `trust-tasks` or `vta-sdk`
  type crosses the `vti-common` boundary in this repo — which is exactly what
  makes the shape dangerous: it is invisible until the first call that does, and
  then it surfaces as an `E0308` between two identically-named types. Moving the
  pins together resolves both. The graph now carries one `trust-tasks-rs`
  (0.6.1) and one `vta-sdk` (0.23.2).

## [0.11.0] – 2026‑08‑09

### Fixed

- **`trust-registry` 0.10.0 does not build from crates.io with `--features tsp`.**
  The `tsp` feature turns on `affinidi-messaging-sdk/tsp` through a direct
  `^0.18` dependency that exists solely to set that flag, while `affinidi-tdk`
  0.8.5 moved to `affinidi-messaging-sdk` `^0.19`. A Cargo feature unifies only
  within one semver-compatible copy, so the graph carried two SDKs and the flag
  landed on the one tdk does *not* re-export — `atm.tsp()` and
  `send_delivery_request_frames` were missing from the `ATM` the listener
  actually holds. The direct dependency now tracks `^0.19`, and the requirement
  that it move in lockstep with tdk's is stated at the declaration.

### Changed

- **Adopts the Trust Tasks framework 0.3 libraries** (`trust-tasks-rs`,
  `-proof`, `-https`, `-didcomm`, `-tsp` all 0.3.0). Two changes are visible on
  the wire, both from the binding crates rather than this repo:
  - error responses are emitted as `trust-task-error/0.3` (carrying the new
    optional `inResponseTo`), not `0.2`. A consumer asserting the exact Type URI
    needs updating; per SPEC §5.2 forward-minor compatibility a `0.2` consumer
    SHOULD accept it. `trql-client` matches on the slug, so it is unaffected.
  - a DIDComm response now sets `thid` from the request document's `threadId`
    (falling back to its `id`), so it continues the request's DIDComm thread
    instead of starting a new one.

- **`registry/did/rotate` uses the VTA's canonical rotate-keys task.**
  `vta-sdk` 0.21 deprecates `rotate_did_webvh_keys` — it rides the legacy
  DIDComm protocol message, which has no TSP dispatcher — in favour of
  `rotate_did_webvh_keys_by_did`, which keys on the DID itself. Rotation no
  longer reads `TR_VTA_CONTEXT_ID` or derives an SCID; the `did:webvh` check is
  kept so a wrong DID fails locally rather than as a VTA protocol error.
  `TR_VTA_CONTEXT_ID` is still required by the `vta` startup path.

- Remaining dependency moves: `vta-sdk` 0.19 → 0.21, `base64` 0.22 → 0.23,
  `tower-http` 0.6 → 0.7, `serial_test` 3 → 4, plus a full `cargo update`.

## [0.10.0] – 2026‑07‑29

### Changed

- **The record CRUD collapses to `registry/record/put` + `registry/record/query`**
  (affinidi/affinidi-trust-registry-rs#120, clean cutover — pre-production, no
  dual-accept). `put` is create-or-replace at the record's four-part key, with
  an optional `expectedExisting` assertion recovering strict create-only /
  update-only semantics (the `vault/upsert` precedent); `query` is an exact
  fetch when all four key parts are supplied (notFound on a miss) and a
  filtered, cursor-paginated enumeration otherwise — closing the pagination gap
  `record/list` conceded. The four superseded Trust Task URIs are **removed**
  and no longer routed:
  - `https://trusttasks.org/spec/registry/record/create/0.1`
  - `https://trusttasks.org/spec/registry/record/update/0.1`
  - `https://trusttasks.org/spec/registry/record/read/0.1`
  - `https://trusttasks.org/spec/registry/record/list/0.1`

  `registry/record/delete`, `registry/recognition` and `registry/authorization`
  are unchanged (the TRQP pair deliberately stays split, mirroring TRQP v2.0's
  two endpoints).

- **`registry/did/rotate/0.1` now has a published spec** in the Trust Tasks
  registry (it was previously a code-only wire contract); the local payload
  types are unchanged and match it.

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