# Affinidi Trust Registry

[![License: Apache](https://img.shields.io/badge/license-Apache%202.0-blue)](LICENSE)

A high-performance, Rust-based implementation of a Trust Registry, fully compliant with the [Trust Registry Query Protocol (TRQP) v2.0](https://trustoverip.github.io/tswg-trust-registry-protocol/) specification. Built for scalability and reliability, it enables secure, standards-based verification of trusted entities within decentralised identity ecosystems.

## Query protocols

The registry answers recognition/authorization queries over three protocols. All three are supported; none is deprecated.

| Protocol | Transport & endpoint | Purpose |
| --- | --- | --- |
| **TRQP REST** | HTTPS: `POST /authorization`, `POST /recognition` | The ToIP [Trust Registry Query Protocol v2.0](https://trustoverip.github.io/tswg-trust-registry-protocol/) over plain HTTPS, unsigned. Use this for ToIP interop: callers that speak TRQP directly and expect its REST binding. |
| **TRQP DIDComm** | The DIDComm `trqp/1.0` protocol (`query-recognition` / `query-authorization`), via the mediator | The same TRQP queries carried as DIDComm messages instead of REST. Use this for ToIP interop over a DIDComm mediator connection. See [DIDCOMM_PROTOCOLS.md](DIDCOMM_PROTOCOLS.md#query-recognition) / [`#query-authorization`](DIDCOMM_PROTOCOLS.md#query-authorization). |
| **Trust Tasks** | Signed `registry/*` Trust Task documents (`https://trusttasks.org/spec/registry/recognition/0.1`, `.../registry/authorization/0.1`, plus record-management and governance tasks), carried over TSP, DIDComm, or HTTPS `POST /trust-tasks` | Transport-agnostic, cryptographically sender-bound requests. Use this for signed queries/writes and ecosystem integration (VTC/VTA, record management, governance) — see [Trust Task protocol surface](#trust-task-protocol-surface). |

TRQP (REST or DIDComm) is unsigned and read-only, matching the ToIP spec verbatim. Trust Tasks are the superset: the same recognition/authorization reads, plus signed record writes and governance operations, over any of the three transports.

## Table of Contents

- [Query protocols](#query-protocols)
- [Quickstart](#quickstart)
- [What is Trust Registry](#what-is-trust-registry)
  - [Why a Trust Registry Matters](#why-a-trust-registry-matters)
  - [Sample Use Cases](#sample-use-cases)
- [Key Components](#key-components)
  - [Crates in this workspace](#crates-in-this-workspace)
- [Requirements](#requirements)
- [Set up Trust Registry](#set-up-trust-registry)
  - [Run with DIDComm Enabled](#run-with-didcomm-enabled)
  - [Run with DIDComm Enabled In Private Mode](#run-with-didcomm-enabled-in-private-mode)
  - [Run with DIDComm Disabled](#run-with-didcomm-disabled)
- [Run Trust Registry on Docker](#run-trust-registry-on-docker)
- [Using Redis as Storage Backend](#using-redis-as-storage-backend)
  - [Prerequisites](#prerequisites)
  - [Setup Redis Storage](#setup-redis-storage)
  - [Redis Storage Features](#redis-storage-features)
  - [Production Considerations](#production-considerations)
  - [Docker Compose with Redis](#docker-compose-with-redis)
  - [Migrating from CSV/DynamoDB to Redis](#migrating-from-csvdynamodb-to-redis)
  - [Troubleshooting](#troubleshooting)
- [Test the API](#test-the-api)
  - [Recognition Query](#recognition-query)
  - [Authorization Query](#authorization-query)
- [Manage Trust Records](#manage-trust-records)
- [Embedding the Trust Registry](#embedding-the-trust-registry)
  - [Mounting into an existing axum app](#mounting-into-an-existing-axum-app)
  - [Driving it from your own transport](#driving-it-from-your-own-transport)
  - [DIDComm: who owns the socket](#didcomm-who-owns-the-socket)
  - [A lean dependency tree](#a-lean-dependency-tree)
  - [What the registry never does to its host](#what-the-registry-never-does-to-its-host)
- [Trust Tasks, Transports & Identity](#trust-tasks-transports--identity)
  - [Cargo feature flags](#cargo-feature-flags)
  - [Trust Task protocol surface](#trust-task-protocol-surface)
  - [Identity from a VTA (`vta`)](#identity-from-a-vta-vta)
  - [Secret-store backends (`secrets-*`)](#secret-store-backends-secrets-)
  - [DynamoDB storage (`storage-ddb`)](#dynamodb-storage-storage-ddb)
  - [Embedded fjall storage (`storage-fjall`)](#embedded-fjall-storage-storage-fjall)
  - [CSV file storage](#csv-file-storage)
  - [Storage key layout](#storage-key-layout)
- [Environment Variables](#environment-variables)
  - [Profile Config Options](#profile-config-options)
- [Additional Resources](#additional-resources)
- [Support \& feedback](#support--feedback)
  - [Reporting technical issues](#reporting-technical-issues)
- [Contributing](#contributing)
- [Changelog](#changelog)

## Quickstart

Get the Trust Registry up and running quickly with default settings (DIDComm disabled).

1. Run the setup command to generate default configurations.

```bash
cargo run --bin setup-trust-registry --features="dev-tools"
```

2. Start the Trust Registry server. The setup wrote `ENABLE_DIDCOMM=false` to `.env`, so the same `.env` also works for [Docker](#run-trust-registry-on-docker).

```bash
RUST_LOG=info cargo run --bin trust-registry
```

The Trust Registry will start on `http://localhost:3232` using CSV file storage with sample data from `./sample-data/data.csv`.

3. Test your Trust Registry setup.

```bash
# Query authorization
curl --location 'http://localhost:3232/authorization' \
--header 'Content-Type: application/json' \
--data '{
    "authority_id": "did:example:authority1",
    "entity_id": "did:example:entity1",
    "action": "action1",
    "resource": "resource1"
}'
```

For more details on how to set up and run the Trust Registry, see the [Set up Trust Registry](#set-up-trust-registry) section.

## What is Trust Registry

A **Trust Registry** is a system that maintains and provides authoritative information about which entities, such as organisations, issuers, and verifiers, are authorised to perform specific actions on defined resources within a trust framework. Each entity is identified by its Decentralised Identifier (DID), ensuring cryptographic integrity and interoperability across decentralised identity ecosystems.

### Why a Trust Registry Matters

In decentralised identity and verifiable credentials, verifiers need to answer critical trust questions before accepting or validating credentials, such as:

- "Is this issuer authorised to issue driver's licences?"
- "Is this credential verifier recognised by the appropriate authority?"
- "Can this entity perform a specific action within this trust framework?"

The Trust Registry provides a standardised, queryable database that answers these trust questions by maintaining trust records and their permitted roles within a governance framework.

**Authorisation Queries:** “Has Authority A authorised Entity B to take Action X on Resource Y?”

**Recognition Queries:** "Does Authority X recognise Entity B as an authority to authorise taking Action X on Resource Y?”

The Trust Registry links:

- **Entity IDs** (who) - DIDs representing issuers, verifiers, or other participants.
- **Authority IDs** (governed by whom) - DIDs of governing authorities.
- **Actions** (what) - Operations like "issue", "verify", "revoke".
- **Resources** (on what) - Credential types like "driverlicence", "diploma".
- **Context** - Additional metadata for authorisation decisions.

This ensures **security**, **compliance**, and **interoperability** across decentralised identity systems.

### Sample Use Cases

- **Credential Issuance Verification**

  Verifies whether an issuer is authorised by a government or regulatory body to issue specific credential types (e.g., driver’s licences, professional certifications).

- **Trust Framework Compliance**

  Ensures that all participants in a digital trust ecosystem, such as issuers, verifiers, and relying parties, are recognised and approved by the appropriate governance authorities.

## Key Components

- **`trust-registry`**: Unified server providing both RESTful API (TRQP endpoints for recognition and authorisation queries) and an optional DIDComm interface over which administrators manage records with the `registry/record/*` Trust Tasks.

- **Storage backends**: Stores authoritative records about the entities for querying. It supports the following storage types:
  - CSV file storage
  - AWS DynamoDB
  - Redis
  - Embedded [fjall](https://github.com/fjall-rs/fjall) LSM store (behind the `storage-fjall` feature)

- **Trust Tasks & transports** _(optional)_: Every Trust Registry operation is also modelled as a versioned [Trust Task](https://trusttasks.org) (`registry/*`) that verifiers and communities (VTC/OpenVTC) can invoke over DIDComm, HTTP, or TSP. See [Trust Tasks, Transports & Identity](#trust-tasks-transports--identity).

- **VTA identity** _(optional)_: The Trust Registry can source its DID and keys from a [Verifiable Trust Agent](https://docs.affinidi.com) instead of a local `PROFILE_CONFIG` (behind the `vta` feature).

### Crates in this workspace

| Crate | Published | What it is |
| --- | --- | --- |
| `trust-registry` | yes | The registry: the standalone server and the library for [embedding](#embedding-the-trust-registry) it. |
| `trql-client` | yes | The client library for querying a registry with TRQP over Trust Tasks, by HTTPS, DIDComm or TSP. See [trql-client/README.md](trql-client/README.md). `trql` is only the crate's name; the protocol is TRQP. |
| `test-trust-registry` | no | An in-process registry fixture for integration tests. See [test-trust-registry/README.md](test-trust-registry/README.md). |
| `test-client` | no | A development client that drives a running registry over DIDComm. |
| `trqp` | no | A placeholder for a TRQP command-line client. Earlier releases published it to crates.io; those versions remain there, and do nothing. |

## Requirements

1. Install Rust on your machine.

- **Rust**: the `rust-version` in the root [`Cargo.toml`](Cargo.toml) (currently 1.95.0) or higher
- **Edition**: 2024
- **Cargo**: Latest version bundled with Rust

Verify that your Rust installation meets the requirements.

```bash
rustc --version
cargo --version
```

2. **Required for DIDComm-enabled.** DIDComm mediator instance is required if you want to enable DIDComm for secure trust record management and querying.

To deploy and run a DIDComm mediator, see the [deployment options](https://docs.affinidi.com/products/affinidi-messaging/didcomm-mediator/deployment-options/) page in the documentation.

**Mediator compatibility.** The Trust Registry sets its own access-list mode (`ACL_MODE`) at the mediator with the `messaging/account/get` and `messaging/account/update` Trust Tasks, so the mediator must answer them. affinidi-messaging-mediator 0.31.0 and later accepts only Trust Tasks for administration (the legacy `mediator/1.0` account and ACL protocols are removed). This release is checked against 0.33.1. Trust Registry releases before 0.19.0 use the legacy protocols and cannot set their mode on a 0.31.0 or later mediator. If the mediator refuses the update, a public registry (`ACL_MODE=ExplicitDeny`) logs `Failed to set ACL mode` and keeps running, since at worst it stays private: unreachable rather than exposed. A private registry (`ACL_MODE=ExplicitAllow`) fails closed. Its DIDComm listener does not start, so it never serves from an account that may still accept anyone. `/health` reports `"status": "degraded"` with the failure class in `detail` (the error itself is in the log), and REST reads keep answering.

`setup-trust-registry` gives the registry an Ed25519 signing key and an X25519 key-agreement key, the pair a mediator holds by default. A mediator with `security.trust_task_verification = "enforce"` (the default `mediator-setup` writes) accepts these Trust Tasks only when they carry a proof, and the messaging SDK signs them only with an **Ed25519** key. A registry DID whose keys are all P-256 (what it and the former `generate-secrets` generated before this release) is affected twice. It cannot authenticate to a mediator that holds no P-256 key (`mediator-setup` adds one only with `--key-suite p256`). Even on one that does, it sends these Trust Tasks unsigned, so an enforcing mediator refuses them (`proof_required`) and the mode is not applied. A private registry then does not serve DIDComm at all (see above). Re-key such a registry, or run its mediator with a P-256 key and `trust_task_verification = "warn"`.

`trust-registry/tests/mediator_e2e.rs` runs the registry against the mediator image in Docker (v0.33.1, enforcing): TRQP over REST and DIDComm, signed `registry/record/*` writes and queries, and an unsigned write refused. It also checks that a private P-256 registry, whose mode the mediator refuses, does not serve DIDComm. It needs Docker and is ignored by default: `cargo test -p trust-registry --test mediator_e2e -- --ignored --nocapture`. `E2E_IDENTITY_KEYS=p256` runs the main test with P-256 identities, which reproduces the refusal above.

## Set up Trust Registry

Configure the environment to run Trust Registry. The setup command creates the `.env` file with default configurations, editing only the lines it sets (comments and the rest of the file are kept). With `--with-test-identities` it also creates test identities in `.env.test` (from the tracked `.env.pipeline` template with `--test-in-pipeline`). The files it writes are readable by their owner only, and it does not print private keys.

Re-running it is safe: it refuses to replace the registry's identity (`PROFILE_CONFIG`, `MEDIATOR_DID`, `ADMIN_DIDS`, `ACL_MODE`, `ADMIN_AUTHORITIES` in `.env`, a bundle in the configured secret store, or `did.json` / `did.jsonl` / `did-update-keys.json`) unless given `--force`, which backs each one up first.

### Run with DIDComm Enabled

**Prerequisites:** You must have a running and accessible DIDComm mediator instance before proceeding. The mediator provides the messaging layer for secure communication between administrators, verifiers, and the Trust Registry.

If you don't have a mediator yet, see [deployment options](https://docs.affinidi.com/products/affinidi-messaging/didcomm-mediator/deployment-options/).

To enable DIDComm for managing and querying trust records, run the following command with your mediator's DID:

```bash
cargo run --bin setup-trust-registry --features="dev-tools" -- \
 --mediator-did=<MEDIATOR_DID> \
 --did-method=peer
```

The command generates the following:

- Creates a Decentralised Identifier (DID) for the Trust Registry using the **did:peer** method (`--did-method` also takes `web`, `webvh` and `scid`; or use an existing identity with `--tr-did`/`--tr-did-secret-file` or `--profile`).
- Writes `ENABLE_DIDCOMM=true`, `MEDIATOR_DID` and `PROFILE_CONFIG` to `.env`.
- Populates the environment variables with default values, such as Storage Backend (`csv`) and audit log format (`json`).
- Only with `--with-test-identities` (development and CI): creates test Trust Registry and client DIDs, opens their mediator accounts, and writes them to `.env.test`.

### Run with DIDComm Enabled In Private Mode

By default, the Trust Registry runs in **public mode** (`ACL_MODE=ExplicitDeny`), which accepts messages from any DID. To enable **private mode** where only pre-authorized DIDs can send messages to the Trust Registry, use the `--acl-mode=ExplicitAllow` option:

```bash
cargo run --bin setup-trust-registry --features="dev-tools" -- \
 --mediator-did=<MEDIATOR_DID> \
 --did-method=peer \
 --acl-mode=ExplicitAllow
```

**With this setup command:**

- Sets the Trust Registry ACL mode to `ExplicitAllow` (private mode).
- Only DIDs in the mediator's allow list for the Trust Registry can send messages (configured via the mediator ACLs during setup).
- Denies all other DIDs, enhancing security for sensitive deployments.

**Use cases for private mode:**

- Production environments that require strict access control.
- Scenarios where only specific administrators should manage trust records.
- Compliance requirements that demand explicit authorisation.

After successful setup, it displays the command to run the Trust Registry.

```bash
RUST_LOG=info cargo run --bin trust-registry
```

### Run with DIDComm Disabled

To configure the Trust Registry without integration with DIDComm, run the following command:

```bash
cargo run --bin setup-trust-registry --features="dev-tools"
```

The command generates the following:

- Populates the environment variables with default values, such as Storage Backend (`csv`) and audit log format (`json`).
- Writes `ENABLE_DIDCOMM=false`, and leaves the DIDComm variables out.

After successful setup, it displays the command to run the Trust Registry.

```bash
RUST_LOG=info cargo run --bin trust-registry
```

For more details on setting up the Trust Registry, refer to the [setup guide](https://github.com/affinidi/affinidi-trust-registry-rs/blob/main/SETUP_COMMAND_REFERENCES.md) document.

## Run Trust Registry on Docker

After setting up the Trust Registry, review the Docker settings in `./docker-compose.yaml`. Start the containers using the following command:

```bash
docker compose up --build
```

The Trust Registry will be available at `http://localhost:3232`.

The image is built for the platform Docker builds for, the host's by default. For another one, or several, use `docker buildx build --platform linux/amd64,linux/arm64 -f trust-registry/Dockerfile .`: the builder stage runs on each target platform (under emulation for a non-native one), so each image holds a binary for its own architecture. `--build-arg FEATURES="vta tsp"` adds Cargo features. Rebuilds reuse compiled dependencies through BuildKit cache mounts.

**Note:** The `sample-data` folder is mounted as a volume to synchronise the changes from data.csv to the container automatically. If you have configured a different path for the data using CSV as the storage backend, configure the Docker settings accordingly.

The registry's port is published on `127.0.0.1` only; change the `ports` entry in `docker-compose.yaml` to expose it on other interfaces. The LocalStack service used for the DynamoDB backend is not started by default: run `docker compose --profile dynamodb up` (or `docker compose up localstack`) when you need it.

The image runs the registry as the unprivileged user `trustregistry` (UID/GID 10001), with `/app` as its working and data directory. A bind-mounted directory the registry writes to (the CSV file, a fjall store, `.trust-registry`) must be writable by that UID, for example `sudo chown -R 10001:10001 ./sample-data` on Linux, or run the container with `user: "<uid>:<gid>"` of the directory's owner. The image has a `HEALTHCHECK` that expects `GET /health` to answer `200` on `LISTEN_ADDRESS`; for a registry run with `ENABLE_REST=false`, disable it (`docker run --no-healthcheck`, or `healthcheck: {disable: true}` in compose).

## Using Redis as Storage Backend

Redis is a high-performance, in-memory data store that can be used as a storage backend for Trust Registry. Redis provides fast read/write operations and is ideal for production deployments requiring low-latency access to trust records.

### Prerequisites

- Redis server 5.0 or higher
- Network access to the Redis instance from the Trust Registry

### Setup Redis Storage

1. **Install Redis** (if not already available)

   ```bash
   # macOS
   brew install redis
   
   # Ubuntu/Debian
   sudo apt-get install redis-server
   
   # Docker
   docker run -d -p 6379:6379 redis:7-alpine
   ```

2. **Start Redis** (if installed locally)

   ```bash
   redis-server
   ```

3. **Configure Trust Registry to use Redis**

   Set the following environment variables:

   ```bash
   TR_STORAGE_BACKEND=redis
   REDIS_URL="redis://localhost:6379"
   ```

   For Redis with authentication:

   ```bash
   REDIS_URL="redis://username:password@localhost:6379"
   ```

   For Redis with a specific database:

   ```bash
   REDIS_URL="redis://localhost:6379/0"
   ```

4. **Run Trust Registry**

   ```bash
   ENABLE_DIDCOMM=false RUST_LOG=info cargo run --bin trust-registry
   ```

### Redis Storage Features

- **Fast Operations**: In-memory storage provides sub-millisecond response times
- **Persistence**: Redis can be configured for data persistence using RDB snapshots or AOF (Append Only File)
- **Scalability**: Supports clustering and replication for high availability
- **Data Structure**: Trust records are stored as JSON strings under keys of the form `TR#<authority_id>#<action>#<resource>#<entity_id>` (see [Storage key layout](#storage-key-layout) for how `#` and `%` in an identifier are escaped)
- **Atomic writes**: Each create, update and delete reads the keys it depends on under `WATCH` and applies its change in one `MULTI`/`EXEC`, so registry replicas sharing one Redis cannot both create the same record, and an update racing a delete cannot bring the record back

### Production Considerations

For production deployments:

1. **Enable Persistence**: Configure Redis persistence to prevent data loss

   ```bash
   # In redis.conf
   save 900 1
   save 300 10
   save 60 10000
   appendonly yes
   ```

2. **Use Authentication**: Always enable Redis authentication in production

   ```bash
   # In redis.conf
   requirepass your_strong_password
   ```

3. **Configure Memory Limits**: Set appropriate memory limits and eviction policies

   ```bash
   # In redis.conf
   maxmemory 2gb
   maxmemory-policy noeviction
   ```

4. **Use TLS**: For secure connections, use Redis with TLS

   ```bash
   export REDIS_URL="rediss://username:password@host:6380"
   ```

5. **Monitor Performance**: Use Redis monitoring tools to track performance

   ```bash
   redis-cli INFO
   redis-cli MONITOR
   ```

### Docker Compose with Redis

Example `docker-compose.yaml` configuration:

```yaml
version: '3.8'

services:
  redis:
    image: redis:7-alpine
    # Replace your_password with a generated secret (e.g. `openssl rand -hex 32`).
    command: redis-server --requirepass your_password --appendonly yes
    # Only needed to reach Redis from the host; the registry uses the compose
    # network. Bound to loopback.
    ports:
      - "127.0.0.1:6379:6379"
    volumes:
      - redis-data:/data
    restart: unless-stopped

  trust-registry:
    build:
      context: .
      dockerfile: trust-registry/Dockerfile
    environment:
      - TR_STORAGE_BACKEND=redis
      - REDIS_URL=redis://:your_password@redis:6379
      - ENABLE_DIDCOMM=false
      - CORS_ALLOWED_ORIGINS=http://localhost:3000
      - AUDIT_LOG_FORMAT=json
    ports:
      - "127.0.0.1:3232:3232"
    depends_on:
      - redis
    restart: unless-stopped

volumes:
  redis-data:
```

### Migrating from CSV/DynamoDB to Redis

To migrate existing trust records to Redis:

1. Export records from your current storage backend
2. Create the records in the Redis-backed registry with the `registry/record/put` Trust Task (see [Manage Trust Records](#manage-trust-records))
3. Verify all records are migrated correctly
4. Update the `TR_STORAGE_BACKEND` environment variable to `redis`

### Troubleshooting

**Connection Issues:**
```bash
# Test Redis connectivity
redis-cli -h localhost -p 6379 ping
# Expected output: PONG
```

**View stored records:**
```bash
# List the trust record keys (SCAN does not block the server the way KEYS does)
redis-cli --scan --pattern 'TR#*'

# Get a specific record: TR#<authority_id>#<action>#<resource>#<entity_id>
redis-cli GET 'TR#did:example:authority1#action1#resource1#did:example:entity1'
```

An identifier containing `#` or `%` appears escaped in its key (`%23`, `%25`);
see [Storage key layout](#storage-key-layout).

**Running the Redis tests:** the adapter's tests run only when
`TR_TEST_REDIS_URL` is set, and fail if it is set but unreachable. Point it at a
dedicated database, never at one holding registry data; the tests delete only
the keys they write, but a dedicated database keeps them apart entirely:

```bash
TR_TEST_REDIS_URL=redis://127.0.0.1:6379/15 cargo test -p trust-registry --lib redis_storage
```

The DynamoDB adapter's tests likewise run only when `TR_TEST_DYNAMODB_ENDPOINT`
names a DynamoDB Local or LocalStack endpoint (for example
`http://localhost:4566`); they create the table `TR_TEST_DYNAMODB_TABLE`
(default `trust-registry-conformance`) if it is missing. With
`TR_TEST_REQUIRE_SERVICES=true` (as CI sets it), an unset service variable
fails the tests instead of skipping them.

## Test the API

You can test the Trust Registry by querying the sample data stored in `./sample-data/data.csv`:

### Recognition Query

```bash
curl --location 'http://localhost:3232/recognition' \
--header 'Content-Type: application/json' \
--data '{
    "authority_id": "did:example:authority1",
    "entity_id": "did:example:entity1",
    "action": "action1",
    "resource": "resource1"
}'
```

The API will return whether the specified entity is recognised by the given authority for the requested action and resource.

To query Trust Registry using DIDComm, refer to the [Trust Registry Recognition Query](https://github.com/affinidi/affinidi-trust-registry-rs/blob/main/DIDCOMM_PROTOCOLS.md#query-recognition) protocol.

### Authorization Query

```bash
curl --location 'http://localhost:3232/authorization' \
--header 'Content-Type: application/json' \
--data '{
    "authority_id": "did:example:authority1",
    "entity_id": "did:example:entity1",
    "action": "action1",
    "resource": "resource1"
}'
```

The API will return whether the specified entity is authorised under the given authority for the requested action and resource.

To query Trust Registry using DIDComm, refer to the [Trust Registry Authorization Query](https://github.com/affinidi/affinidi-trust-registry-rs/blob/main/DIDCOMM_PROTOCOLS.md#query-authorization) protocol.

### Request validation and errors

Both REST endpoints validate the query before looking it up, as TRQP v2.0
requires:

- `entity_id`, `authority_id`, `action` and `resource` must each be a non-empty
  RFC 3986 URI reference (DIDs, URLs and plain tokens such as `issue` all
  qualify; spaces, `<`, `>` and other characters RFC 3986 forbids do not).
- `context`, when present, must be a JSON object, and `context.time`, when
  present, an RFC 3339 date-time.

A query that fails these checks gets `400` with title `invalid_request`. An
unparseable body or a missing field gets `400` `bad_request`, and a valid query
with no matching record gets `404` `not_found`.

Errors are RFC 9457 Problem Details, served as `application/problem+json`:

```json
{ "type": "about:blank", "title": "invalid_request", "status": 400,
  "detail": "`action` must not be empty", "code": 400 }
```

`code` repeats `status` for clients written against earlier releases.

`time_requested` echoes `context.time` when one is sent; otherwise it is the
time the request arrived. `time_evaluated` is the server time the answer was
produced at. The answer is judged as of `context.time` (or now) against the
record's [validity window](#record-validity-windows): outside it, the response
is `200` with `authorized` / `recognized` `false` and a `message` saying why. A
record that does not exist is still `404`.

**Testing Tips:**

- Add more records to `./sample-data/data.csv` to expand test coverage.
- Test with both defined and undefined IDs to ensure the system correctly handles invalid or missing identifiers.
- In a request, `context` is a JSON object. Only the CSV storage file holds it Base64-encoded (its `context` column). Invalid or malformed data should trigger appropriate error responses.

## Manage Trust Records

**Note:** This section applies only when DIDComm is enabled. See [Run with DIDComm Enabled](#run-with-didcomm-enabled) for setup instructions.

You can manage trust records stored in the Trust Registry using DIDComm by sending messages to the Trust Registry's DID. DIDComm provides a secure, interoperable way to exchange messages between an administrator and the Trust Registry, making it ideal for trust record operations such as creating, updating, or querying records.

For a working reference, see the [test-client implementation](https://github.com/affinidi/affinidi-trust-registry-rs/tree/main/test-client), which demonstrates how to build a DIDComm client and send admin operation messages.

See [Trust Registry Administration](https://github.com/affinidi/affinidi-trust-registry-rs/blob/main/DIDCOMM_PROTOCOLS.md#trust-registry-administration) section for more details.

## Embedding the Trust Registry

The Trust Registry runs two ways from the same code: as its own service, or as a
component inside a host application — a VTC, say — that already has an axum
server, a tokio runtime, storage and a mediator connection. Both are supported
first-class; embedding is not a test-only mode.

Everything below is in `trust-registry/examples/embedded_axum.rs`, which is a
complete host application you can run:

```bash
cargo run -p trust-registry --example embedded_axum --no-default-features
```

### Mounting into an existing axum app

```rust
use std::sync::Arc;
use trust_registry::{TrustRegistry, configs::TrustRegistryConfig};
use trust_registry::capabilities::MemoryCapabilityStore;

let registry = TrustRegistry::builder(TrustRegistryConfig::embedded("/srv/app/registry"))
    .repository(my_repository)            // any TrustRecordAdminRepository
    .capability_store(Box::new(MemoryCapabilityStore::default()))
    .dedup_store(my_durable_dedup)        // see the note below
    .shutdown(host_shutdown_token)
    .build()
    .await?;

let app = host_router.nest("/registry", registry.router());
```

`router()` carries the TRQP endpoints, the Trust Tasks HTTPS binding and
`/.well-known/did.json`. It deliberately ships **no CORS layer and no
`/health`** — both belong to the host, and applying ours would override or
collide with theirs. Use `registry.health()` to fold the registry's health into
the host's own endpoint, or `registry.health_router()` for a ready-made one.

The routes are unauthenticated. `router()` applies the request body limit
(`server_config.http_limits.max_body_bytes`); the host must bound request time,
requests in flight and connections itself, as the standalone service does
(`trust_registry::http::limits` has the pieces it uses).

`/.well-known/did.json` is only meaningful at the server root, so a host nesting
under a prefix should serve the registry's DID document itself, or mount at `/`.

### Driving it from your own transport

A host that already speaks DIDComm, or anything else, can skip HTTP entirely:

```rust
// A decoded Trust Task from a transport you authenticated yourself.
let outcome = registry.task_handler().handle(doc, Some(sender_did)).await;

// Or, for a DIDComm envelope, letting the registry do the decode and
// §4.8.1 party resolution:
let outcome = registry.route_didcomm_envelope(message.body, &sender_did).await;
```

Pass `None` for the sender when the caller is unauthenticated; writes are then
denied on the admin ACL.

### DIDComm: who owns the socket

The mediator permits **one websocket per DID**. `DidCommSource` says which side
holds it:

| Source                        | Who opens the socket | Use when                                                            |
| ----------------------------- | -------------------- | ------------------------------------------------------------------- |
| `Managed` (default)           | the registry         | the registry's DID is not already connected anywhere else            |
| `SharedAtm { atm, profile }`  | the host, lent over  | the host holds the connection but does not need to keep reading it   |
| `HostDriven`                  | the host, kept       | the host drains the stream itself and routes documents in            |

```rust
let registry = TrustRegistry::builder(config)
    .repository(repo)
    .didcomm_source(DidCommSource::SharedAtm { atm, profile })
    .build()
    .await?;
```

Under `SharedAtm` the host must not still be draining that profile's live
stream — frames go to whichever reader takes them first, so two readers split
the traffic silently. If the host needs to keep reading, use `HostDriven`.

With TSP enabled, a `SharedAtm` registry receives through the SDK's
`DidCommTransport` over the lent connection, so inbound TSP relationship
requests are recorded (Rev 3 §7.2.2). They are recorded in the **host's** ATM
relationship store — the registry cannot replace a lent ATM's store — so give
that ATM a durable, bounded store (`ATMConfigBuilder::with_relationship_store`);
the SDK's default keeps relationships in memory, without a bound. The
profile's websocket must be enabled before the registry starts.

### A lean dependency tree

The standalone service's backends are all default-on. An embedded registry
should turn them off and add back only what it uses:

```toml
[dependencies]
trust-registry = { version = "0.32", default-features = false, features = ["storage-fjall"] }
```

That drops the AWS SDKs, Redis, `serde_dynamo`, `dotenvy`, `crossterm` and
`vti-secrets` — roughly 750 crates down to 620. (`csv` and `clap` still appear,
but transitively via `affinidi-tdk`, not as the registry's own dependencies.)
The example above builds with **no features at all**, using the
dependency-free in-memory `LocalStorage`.

`vti-secrets` in particular is worth leaving off when you can: it is a
workspace member of `verifiable-trust-infrastructure`, so a VTC that enables a
`secrets-*` feature ends up with both its own path copy and a crates.io copy of
that crate (and of `vti-common` beneath it). With no `secrets-*` feature the
registry has no secret store, which is the right shape when the host supplies
the identity — and every shared crate then resolves to exactly one copy.

### What the registry never does to its host

Nothing in the embedded path touches process-global state: it does not read
environment variables (only `configs::Configs::load`, which embedding bypasses,
ever does), install a tracing subscriber, load a `.env` file, or call
`std::process::exit`. Those all live behind the `standalone` feature. Only
`TrustRegistry::serve()` binds a socket, and only when you ask for it.

One default is worth changing deliberately: `dedup_store` falls back to an
in-memory store, which forgets across a restart, so a redelivered mutation could
be applied twice (R1.4). It is the one injection point that changes a
correctness property rather than a convenience — a host with durable storage
should supply its own.

## Trust Tasks, Transports & Identity

Beyond the core REST/DIDComm server, the Trust Registry ships a set of **optional,
feature-gated** capabilities that let Verifiable Trust Communities (VTC/OpenVTC)
and verifiers interact with it as a first-class [Trust Tasks](https://trusttasks.org)
participant, and let it delegate its own identity and secret custody.

The `registry/*` Trust Tasks themselves, over `POST /trust-tasks` and the DIDComm
Trust Task envelope, are always compiled in. The Cargo features below choose
storage backends, config loaders, the standalone entrypoint, the TSP binding, VTA
identity and secret-store backends. The standalone service's backends are on by
default (the first six rows); everything else is opt-in.

### Cargo feature flags

| Feature          | Default | Enables                                                                                                                       |
| ---------------- | :-----: | ----------------------------------------------------------------------------------------------------------------------------- |
| `secrets-config` |   ✅    | Inline / plaintext-file secret store for the profile bundle. Pulls `vti-secrets`; with no `secrets-*` feature the registry has no secret store at all. |
| `standalone`     |   ✅    | `server::start()` — the process-owning entrypoint (`.env`, global tracing, `process::exit`). Required by the `trust-registry` binary; an embedded registry does not need it. |
| `storage-csv`    |   ✅    | CSV file storage backend (`TR_STORAGE_BACKEND=csv`, the standalone default).                                                  |
| `storage-ddb`    |   ✅    | DynamoDB storage backend (`TR_STORAGE_BACKEND=dynamodb`, or `ddb`).                                                           |
| `storage-redis`  |   ✅    | Redis storage backend (`TR_STORAGE_BACKEND=redis`).                                                                           |
| `loaders-aws`    |   ✅    | `aws_secrets://` and `aws_parameter_store://` config-loader URI schemes.                                                      |
| `tsp`            |         | [TSP](https://trustoverip.github.io/tswg-tsp-specification/) transport binding for the `registry/*` Trust Tasks.              |
| `vta`            |         | Fetch the Trust Registry DID + keys from a Verifiable Trust Agent at startup; enables the `registry/did/rotate` admin task.   |
| `storage-fjall`  |         | Embedded fjall LSM storage backend for trust records (`TR_STORAGE_BACKEND=fjall`).                                            |
| `secrets-aws`    |         | AWS Secrets Manager backend for the identity secret store.                                                                    |
| `secrets-gcp`    |         | GCP Secret Manager backend.                                                                                                   |
| `secrets-azure`  |         | Azure Key Vault backend.                                                                                                      |
| `secrets-vault`  |         | HashiCorp Vault backend.                                                                                                      |
| `secrets-k8s`    |         | Kubernetes Secret backend.                                                                                                    |
| `secrets-keyring`|         | OS keyring backend.                                                                                                           |
| `secrets-all`    |         | All of the `secrets-*` backends at once.                                                                                      |

Selecting a storage backend that was not compiled in is a startup error naming
the missing feature, never a silent fallback to a different store. The
in-memory `LocalStorage` needs no feature and is always available.

```bash
# Example: build the server with VTA identity, the TSP binding and the AWS secret store
cargo run --bin trust-registry --features "vta,tsp,secrets-aws"
```

### Trust Task protocol surface

Each Trust Registry operation is a versioned Trust Task in the `registry/*` family.
The **same** typed payloads are served over every transport (DIDComm always-on;
HTTP; TSP behind the `tsp` feature), so a VTC can talk to the registry with one
message shape regardless of carrier.

| Trust Task (`slug`)                                   | Kind  | Auth                          |
| ----------------------------------------------------- | ----- | ----------------------------- |
| `registry/recognition/{0.1,0.2}`                      | read  | none (TRQP recognition query) |
| `registry/authorization/{0.1,0.2}`                    | read  | none (TRQP authorization query)|
| `registry/record/query/{0.1,0.3}`                     | read  | admin DID + proof + authority |
| `registry/record/put/{0.1,0.3}`                       | write | admin DID + proof + authority |
| `registry/record/delete/{0.1,0.2}`                    | write | admin DID + proof + authority |
| `registry/did/rotate/{0.1,0.2}`                       | write | admin DID + proof + the registry's DID as authority (`vta` only) |
| `git-trust/{grant,revoke}/0.1`                        | write | admin DID + proof + authority |
| `governance/capability/{enable,disable}/0.1`          | write | admin DID + proof + authority |

The newer version of each `registry/*` task spells its members in
lowerCamelCase (`entityId`, `authorityId`, `recordType`, `evaluatedAt`, `asOf`)
and carries records' validity window. The older version keeps its snake_case
form and is still served, so peers can move when they are ready. The plain TRQP
endpoints (`POST /authorization`, `POST /recognition`) keep TRQP's own
snake_case names.

#### Record validity windows

A record may carry `validFrom` (inclusive) and `validUntil` (exclusive), as RFC
3339 instants, set with `registry/record/put/0.3`. Either may be omitted, which
leaves that side open, so a record with neither holds at every instant: every
record written before windows existed keeps answering as it did.

Every recognition and authorization query, on every transport, is judged as of
`context.time`, or the registry's clock when none is sent:

- inside the window, the answer is the record's own `recognized` /
  `authorized`;
- outside it, the answer is `false`, and `message` says whether the statement
  has not started or has ended;
- when judging at its own clock, the registry treats a record as started up to
  60 seconds before its `validFrom`, to absorb clock skew with the writer. It
  never extends `validUntil`, and an explicit `context.time` is judged exactly.

A record whose window has ended stays stored until it is replaced or deleted, so
a query about an instant inside the window still finds it. The registry keeps
current records, not their history. `registry/record/query/0.3` returns the
window; `0.1` cannot carry it, so leaves it out. A `put/0.1` replaces the
record, window included. The CSV backend reads optional `valid_from` and
`valid_until` columns.

**Writes** are operational messages. Each one requires:

- an in-band `issuer` that is the sender the transport authenticated;
- the registry's DID as `recipient`, an `issuedAt` inside the five-minute
  acceptance window, and an `id` not already accepted on any binding;
- a Data-Integrity proof with `proofPurpose` `authentication`, made with a key
  the issuer's DID document lists under `authentication`, that verifies;
- the issuer to be in `ADMIN_DIDS`.

Writes are further bound to the authority they act under, which must be the
issuer's DID or an authority listed for that issuer in `ADMIN_AUTHORITIES`: a
record's `authority_id`, the authority git-trust was enabled for (for
`git-trust/grant` and `revoke`), or the authority a capability's config names
(for `governance/capability/enable` and `disable`). The authenticated sender on
its own authorises nothing.

A did:scid reference is one identity with or without its `?src=` locator, so the
registry stores, keys and compares every `entity_id`/`authority_id`, capability
authority and replay-record issuer without it, and accepts a write addressed to
its own did:scid with one. A record an earlier release stored with a locator
keeps its old key: queries, fetches and deletes that spell the locator the way
it was stored still reach it, and filtered `registry/record/query` enumerations
list it under either spelling, but a query by the bare DID does not find it.
Re-put it (stored under the bare DID) and delete the old spelling to migrate.

Capabilities are enabled **per authority**. Each community enables, for
example, `git-trust` under its own authority (`config.authority`), and several
may do so side by side. A grant, revoke or disable acts on the enablement of
the authority the issuer may act for; an admin listed for several authorities
that have all enabled the capability names the one it means in the request's
`ext`: `{"com.affinidi.trust-registry": {"authority": "did:..."}}`.
`governance/capability/list` returns one entry per enablement, and its
response's `ext."com.affinidi.trust-registry".entries[i]` names the capability
and authority of `capabilities[i]`. `enable` accepts only the version of the
registry's built-in manifest, and refuses `delegate` (the registry has no
delegation mechanism) and a `manifest` that is not the built-in one. The
`reason` of a `disable` or `git-trust/revoke` is kept in its audit entry. The
enablement state file (`TR_CAPABILITY_STATE`) of earlier releases, one slot per
capability, is read and migrated, and written in the per-authority format on
the next change.

Refusals carry the codes the task specifications declare: `registry/record/put:alreadyExists`
and `:notFound` (a strict put), `registry/record/delete:notFound`,
`registry/record/query:notFound` (a fully keyed query),
`governance/capability/enable:unknownCapability`, `:alreadyEnabled`,
`:configInvalid`, `governance/capability/disable:notEnabled`,
`git-trust/grant:alreadyGranted` and `git-trust/revoke:notGranted`. A
`git-trust/grant` after a revoke authorizes the retained record again.

A write that acts on the registry itself acts under **the registry's own DID**:
`registry/did/rotate`, enabling or disabling a capability whose config names no
authority, and the tasks of a capability that writes no records. Only an admin
that `ADMIN_AUTHORITIES` lists for the registry's DID may make one, e.g.
`{"did:web:ops.example": ["<the registry's DID>"]}`. With no such entry no admin
can, so in a registry shared by several communities one community's admin
cannot rotate the registry's keys. A write task with no authority rule is
refused, and a task in the registry's own `registry/` or `governance/`
families that it does not describe is answered as an unsupported type, never
served as a read.

A capability's tasks are writes unless the capability declares them as reads
(`CapabilityDefinition::register_reads`): every task its `register` adds needs
an admin, a proof and an authority, is executed at most once and is audited,
and is served only over the authenticated transports. Only declared reads are
served on the read-only HTTP surface. A capability set that declares one of the
registry's writes as a read, registers a task the registry itself serves, or
shares a task with another capability is refused when the registry is built.

`registry/record/query` returns whole records, `context` included, so it is
held to the same rules and answered only for an admin, under an
`authority_id` the query names. The public surface is the TRQP recognition and
authorization queries.

Every write and record query, accepted or refused, is recorded in the audit log
(`AUDIT_LOG_FORMAT`, JSON by default): the operation and task type, the proven
issuer (or, for one refused before its proof was checked, the DID it claimed),
the authority and record key or capability, the result and reason, the
document `id`, the thread and the time. Each write's entry also carries
`document_digest`, the SHA-256 (hex) of the canonical JSON of the whole signed
document, proof included, so an archived copy of the document can be matched
to its entry and its proof checked again; once the proof has verified, it
names the key that approved the write (`verification_method`) and the proof's
`created` time (`proof_created`). Record contents and proof values are not
logged. Every value is capped at 256 characters, and control characters, the
line and paragraph separators and Unicode format characters (bidi overrides,
zero-width characters) are escaped, in both formats, so an entry is always one
line that reads as written. Each entry carries `seq`, its position in the
process's audit sequence (from 1 at start-up, assigned before the entry
reaches the logger, including a host's own), so a missing entry shows as a
gap, and `authenticated_sender` when the transport authenticated the sender
(DIDComm, TSP) even though the document's proof was not verified. A reason or
verification method is capped at 1024 characters, every other value at 256.

An entry's `role` is `ADMIN` only when its `actor` is a proven admin (the
document's proof verified and its issuer is on the admin list); every other
entry, including a refusal of an unknown or anonymous caller, has `role`
`UNPROVEN` and an empty `actor`. `status` is `SUCCESS`, `FAILURE` (with
`error`), `UNAUTHORIZED` (with `reason`), `REPLAYED` or `DUPLICATE_IN_FLIGHT`.
The last two mark a duplicate of a document that was executed once: `REPLAYED`
when it was answered from the record of accepted documents after the original
finished, `DUPLICATE_IN_FLIGHT` when it arrived while the original was still
running and was told to retry. Nothing was executed for either; the entry of
the execution, with the same `document_id` and `document_digest`, records the
outcome. An `error` or `reason` reads `<code>: <message>`, the code being the
Trust Task error code.

Refusals of documents whose issuer was never proven are recorded individually
within per-minute budgets: 60 for unauthenticated callers (the HTTP surface)
together; 16 for each transport-authenticated sender, for up to 64 senders a
minute, with the senders beyond those sharing one further 16; and at most 600
for all authenticated senders together, since new DIDs cost nothing to make.
Beyond a budget the refusals are counted, and each source's count is recorded
as one entry every minute and at shutdown, with its reason codes, task types
and the first few claimed issuers. Such a summary has the operation `SUMMARY`
(status `UNAUTHORIZED`, role `UNPROVEN`), so it is not counted among the
refused operations on the registry. Anonymous HTTP traffic cannot use up the
entries that refusals over DIDComm or TSP need, and however many identities a
sender uses, unproven refusals add at most 660 individual entries and 66
summaries a minute. A flood of authenticated identities can still use up the
shared authenticated budget, after which a genuine peer's refusals in that
minute are counted rather than recorded individually.

Audit entries are written to the `tracing` target `audit` at `INFO`. The
standalone service gives that target an output layer of its own that is always
on, so `RUST_LOG` (which still controls every other log line) cannot switch
the audit trail off. A host embedding the registry must keep the `audit`
target enabled at `INFO` in its subscriber, or pass its own logger with
`TrustRegistryBuilder::audit_logger`. When neither holds, `build()` reports it
to the log and to stderr, or, with `TrustRegistryBuilder::require_audit_sink`,
refuses to build.

The record of accepted document identifiers is shared by the DIDComm and TSP
bindings within one process. It keeps an identifier for seven minutes (the
acceptance window, the skew and a minute of margin); an older document is
refused on its time of issue. Record queries have a separate, smaller record,
so queries cannot use up the capacity writes need. Both are held in memory, so
replicas of one registry do not share them.

The legacy `tr-admin/1.0` DIDComm protocol is no longer served; see
[DIDCOMM_PROTOCOLS.md](DIDCOMM_PROTOCOLS.md#removed-tr-admin10) for the
mapping onto these tasks. The reads map
verbatim onto the [TRQP v2.0](https://trustoverip.github.io/tswg-trust-registry-protocol/)
recognition/authorization field names, so the plain HTTP TRQP endpoints and the
Trust Task payloads share a single schema.

`registry/record/put` is create-or-replace at the record's four-part key (the
optional `expectedExisting` assertion recovers strict create-only / update-only
semantics); `registry/record/query` is an exact fetch when all four key parts
are supplied and a filtered, cursor-paginated enumeration otherwise. They
supersede the retired `registry/record/{create,update}/0.1` and
`registry/record/{read,list}/0.1` tasks, which this registry no longer accepts.

### Identity from a VTA (`vta`)

With `--features vta`, the Trust Registry authenticates to a Verifiable Trust Agent
at startup and pulls its DID and private keys from a VTA context (remote key
custody) instead of loading a local `PROFILE_CONFIG`. The bundle is cached through
the configured [secret-store backend](#secret-store-backends-secrets-) so the
service can still boot while the VTA is briefly unreachable.

The cache has a slot of its own, apart from any profile bundle in the same
store: the configured secret name (AWS, GCP, Azure, Kubernetes), Vault path or
keyring service with `-vta-cache` appended, or `<TR_SECRETS_DATA_DIR>/vta-cache/`
for the plaintext file. A `--features vta` build has no keyring, so **an offline
cache needs a configured backend** — or, for development only,
`TR_SECRETS_ALLOW_PLAINTEXT=true`. Without one, startup logs a warning naming
these variables, and the registry cannot start while the VTA is unreachable.
`TR_SECRETS_SEED` is read-only and cannot hold the cache.

The registry's DID is a VTA-managed `did:webvh`; its keys can be rotated in place
via the `registry/did/rotate` admin Trust Task (admin-DID + proof gated, by an
admin that `ADMIN_AUTHORITIES` lists for the registry's own DID).

The same build adds `trust-registry setup`, which provisions the registry at a
VTA headless, in two phases (`--setup-key-out`, then `--from <toml>`), the way
`vtc setup` does. [`VTA_SETUP.md`](VTA_SETUP.md#headless-setup-automated) covers
it, along with the manual `pnm` and offline `vta` paths.

| Variable            | Description                                                                                               | Required                    |
| ------------------- | -------------------------------------------------------------------------------------------------------- | --------------------------- |
| `TR_VTA_CREDENTIAL` | VTA `CredentialBundle` JSON, or a loader URI (`file://`, `aws_secrets://`, …) resolving to it. Its presence enables the VTA path. | Yes (`vta`)   |
| `TR_VTA_CONTEXT_ID` | The VTA context holding this service's DID + keys.                                                        | Yes (`vta`)                 |
| `TR_VTA_URL`        | VTA URL override (otherwise taken from the credential).                                                   | No                          |
| `TR_ALIAS`          | Profile alias. Default `Trust Registry`.                                                                  | No                          |

### Secret-store backends (`secrets-*`)

The `secrets-*` features select where the Trust Registry persists the identity it
custodies (the profile bundle, or — in VTA mode — the offline identity cache).
`secrets-config` (inline / plaintext file) is on by default; cloud, Vault, K8s and
keyring backends are opt-in. Non-interactive self-provisioning mirrors the
mediator-setup and did-hosting tooling, and every backend is configured through
the same shared `vti-secrets` crate the VTA uses — so the config field names line
up one-to-one with the VTA's `[secrets]` table.

**Backend selection.** `TR_SECRETS_BACKEND` names the backend outright:
`aws`, `gcp`, `azure`, `vault`, `kubernetes`, `config_seed`, `keyring` or
`plaintext` (any other value stops startup). Without it, the backend is the one
whose activating variable (below, in **bold**) is set; setting the activating
variables of more than one backend stops startup and asks you to name one with
`TR_SECRETS_BACKEND`. With none set, no secret store is used and the identity
comes from `PROFILE_CONFIG` (or a VTA). The selected backend is logged at
startup, and a backend selected on a binary built without its `secrets-*`
feature stops startup rather than falling through to another store.

A half-configured backend stops startup with the missing variable's name: Azure
needs both `TR_SECRETS_AZURE_VAULT_URL` and `TR_SECRETS_AZURE_SECRET_NAME`,
Vault both an address and `TR_SECRETS_VAULT_SECRET_PATH`, GCP both
`TR_SECRETS_GCP_PROJECT` and `TR_SECRETS_GCP_SECRET_NAME`.

The bundle is stored identically across every backend, so you can migrate by
copying the value between two vendor CLIs and swapping the `TR_SECRETS_*`
variables.

#### Config-seed / plaintext file (`secrets-config`, default)

| Variable                     | Description                                                                                   |
| ---------------------------- | --------------------------------------------------------------------------------------------- |
| **`TR_SECRETS_SEED`**        | The profile bundle JSON (`{"alias","did","secrets"}`), **hex-encoded**, read straight from the environment. Read-only: `setup-trust-registry` cannot provision into it, and it cannot hold the VTA offline cache. Activates the config-seed backend. |
| `TR_SECRETS_BACKEND`         | Names the backend explicitly (see above). `plaintext` is only reachable this way, or as the fallback on a build without `secrets-keyring`. |
| `TR_SECRETS_ALLOW_PLAINTEXT` | `true` to permit the plaintext-file backend (`<data dir>/seed.plaintext`, the bundle hex-encoded). `true` or `false`. **Dev/test only.** Default `false`. |
| `TR_SECRETS_DATA_DIR`        | On-disk directory for the file-backed backends, and the default parent of the TSP messaging store. Default `./.trust-registry`. |

#### AWS Secrets Manager (`secrets-aws`)

| Variable                       | Description                                                                                      |
| ------------------------------ | ------------------------------------------------------------------------------------------------ |
| **`TR_SECRETS_AWS_SECRET_NAME`** | Secrets Manager secret name/ARN. Activates the backend. Credentials from the standard SDK chain. |
| `TR_SECRETS_AWS_REGION`        | Region override. Falls back to `AWS_REGION` / IMDS.                                               |

First-boot provisioning needs `secretsmanager:CreateSecret`; steady state needs only
`GetSecretValue` + `PutSecretValue`.

#### GCP Secret Manager (`secrets-gcp`)

| Variable                        | Description                                                              |
| ------------------------------- | ------------------------------------------------------------------------ |
| **`TR_SECRETS_GCP_SECRET_NAME`** | Secret Manager secret name. Activates the backend.                       |
| `TR_SECRETS_GCP_PROJECT`        | GCP project ID. Auth via Application Default Credentials / Workload Identity. |

#### Azure Key Vault (`secrets-azure`)

| Variable                          | Description                                                                      |
| --------------------------------- | -------------------------------------------------------------------------------- |
| **`TR_SECRETS_AZURE_VAULT_URL`**  | Key Vault URL, e.g. `https://my-vault.vault.azure.net`. Activates the backend.    |
| `TR_SECRETS_AZURE_SECRET_NAME`    | Secret name. Auth via the DefaultAzureCredential chain (Managed Identity, etc.).  |

#### HashiCorp Vault (`secrets-vault`)

Stores the seed as a field in a KV v2 secret. Designed for in-cluster Kubernetes but
works anywhere; the Vault token is auto-renewed in the background. Three auth methods,
chosen by `TR_SECRETS_VAULT_AUTH_METHOD` (**default `kubernetes`**). The canonical
`VAULT_ADDR` / `VAULT_NAMESPACE` / `VAULT_TOKEN` / `VAULT_SKIP_VERIFY` names are
honoured too (they take precedence over the `TR_SECRETS_VAULT_*` spelling), so the
same Vault env carries across services.

| Variable                            | Description                                                                                          |
| ----------------------------------- | ---------------------------------------------------------------------------------------------------- |
| `TR_SECRETS_VAULT_ADDR` (or `VAULT_ADDR`) | Vault server URL. **Required** with the secret path.                                         |
| **`TR_SECRETS_VAULT_SECRET_PATH`** | KV v2 path under the mount, e.g. `tr/master-seed`. Activates the backend; requires the address. |
| `TR_SECRETS_VAULT_KV_MOUNT`         | KV v2 mount. Default `secret`. (No `/data/` segment — vaultrs injects it.)                           |
| `TR_SECRETS_VAULT_SECRET_KEY`       | Field within the secret holding the hex seed. Default `seed`.                                        |
| `TR_SECRETS_VAULT_NAMESPACE` (or `VAULT_NAMESPACE`) | Vault Enterprise namespace, if any.                                                   |
| `TR_SECRETS_VAULT_AUTH_METHOD`      | `kubernetes` (default), `token`, or `approle`.                                                       |
| `TR_SECRETS_VAULT_K8S_ROLE`         | Kubernetes auth role. **Required for the `kubernetes` method** (the default — startup errors without it). |
| `TR_SECRETS_VAULT_K8S_MOUNT`        | Kubernetes auth mount. Default `kubernetes`.                                                         |
| `TR_SECRETS_VAULT_K8S_JWT_PATH`     | ServiceAccount JWT path. Default `/var/run/secrets/kubernetes.io/serviceaccount/token`.             |
| `VAULT_TOKEN` (or `TR_SECRETS_VAULT_TOKEN`) | Static token for the `token` method. Prefer the env var over config.                        |
| `TR_SECRETS_VAULT_APPROLE_ROLE_ID`  | AppRole `role_id` for the `approle` method.                                                          |
| `TR_SECRETS_VAULT_APPROLE_SECRET_ID`| AppRole `secret_id` for the `approle` method.                                                        |
| `TR_SECRETS_VAULT_APPROLE_MOUNT`    | AppRole mount. Default `approle`.                                                                    |
| `TR_SECRETS_VAULT_SKIP_VERIFY` (or `VAULT_SKIP_VERIFY`) | Disable TLS verification (`true`/`false`, `1`/`0`, `yes`/`no`). **Dev/test only.** |

Minimal in-cluster (Kubernetes auth) env — this is the common case, and the two that
were previously impossible to set from the environment are the auth method and role:

```bash
TR_SECRETS_VAULT_ADDR=https://vault.svc.cluster.local:8200
TR_SECRETS_VAULT_SECRET_PATH=tr/master-seed
TR_SECRETS_VAULT_AUTH_METHOD=kubernetes     # default; shown for clarity
TR_SECRETS_VAULT_K8S_ROLE=trust-registry    # required for kubernetes auth
```

Vault server side (one-time): enable the `kubernetes` auth method, write
`auth/kubernetes/config`, bind the registry's ServiceAccount to a policy granting
`read`/`create`/`update` on `secret/data/tr/master-seed`, and create the role named
above with matching `bound_service_account_names` / `bound_service_account_namespaces`.

#### Kubernetes `Secret` (`secrets-k8s`)

Native namespaced `Secret`, no extra infra. Credentials resolve from the pod's mounted
ServiceAccount in-cluster, or your kubeconfig when running `setup` out-of-cluster.

| Variable                       | Description                                                                                     |
| ------------------------------ | ----------------------------------------------------------------------------------------------- |
| **`TR_SECRETS_K8S_SECRET_NAME`** | `Secret` name holding the hex seed. Activates the backend.                                       |
| `TR_SECRETS_K8S_NAMESPACE`     | Namespace. Unset ⇒ the pod's own namespace in-cluster (inject via Downward API), else `default`. |
| `TR_SECRETS_K8S_SECRET_KEY`    | Key within the `Secret`'s `data`. Default `seed`.                                               |

RBAC: the ServiceAccount needs `get` (+ `create`/`update` for first-boot / re-key) on the
`Secret`. A bare `Secret` is only base64-encoded in etcd — enable encryption-at-rest (or
use Vault / a cloud manager) before treating this as production-grade.

#### OS keyring (`secrets-keyring`)

| Variable                     | Description                                                                          |
| ---------------------------- | ------------------------------------------------------------------------------------ |
| `TR_SECRETS_KEYRING_SERVICE` | OS-native credential-store service name. Set a distinct value per co-located instance. |

Interactive on macOS (Keychain unlock prompt) — use a different backend for headless / CI.

### DynamoDB storage (`storage-ddb`)

With `TR_STORAGE_BACKEND=dynamodb` (or `ddb`) trust records are kept in the
DynamoDB table `DDB_TABLE_NAME`. The registry does not create the table. It
needs a string partition key `PK` and a string sort key `SK`: every record has
`PK = "TR"` and `SK = "TR#<authority_id>#<action>#<resource>#<entity_id>"` (a `%` or `#`
inside an identifier is written `%25` or `%23`), so the whole registry lives
in one partition. Create it with, for example:

```bash
aws dynamodb create-table \
  --table-name trust-registry-records \
  --attribute-definitions AttributeName=PK,AttributeType=S AttributeName=SK,AttributeType=S \
  --key-schema AttributeName=PK,KeyType=HASH AttributeName=SK,KeyType=RANGE \
  --billing-mode PAY_PER_REQUEST
```

Credentials and region come from the AWS SDK's default chain (environment,
`AWS_PROFILE`, instance or task role); set `AWS_REGION` to pin the region. For
DynamoDB Local or LocalStack, set `DYNAMODB_ENDPOINT` and, if you have no real
credentials, `DDB_USE_TEST_CREDENTIALS=true`. The variables are listed under
[Trust record storage](#trust-record-storage).

### Embedded fjall storage (`storage-fjall`)

With `--features storage-fjall` and `TR_STORAGE_BACKEND=fjall`, trust records are
stored in an embedded [fjall](https://github.com/fjall-rs/fjall) LSM store — a
single-node, on-disk option that needs no external database.

| Variable         | Description                                                | Required                                       |
| ---------------- | ---------------------------------------------------------- | ---------------------------------------------- |
| `TR_FJALL_PATH`  | Directory for the embedded fjall keyspace.                 | default: `./trust_records.fjall`               |

Each create, update or delete is `fsync`ed (fjall `PersistMode::SyncAll`) before
it is acknowledged, so an acknowledged write survives a host crash or power
loss, not only a process crash. Records use the shared
[storage key layout](#storage-key-layout).

### CSV file storage

The CSV backend (`TR_STORAGE_BACKEND=csv`, the default) keeps the records in
memory and rewrites `FILE_STORAGE_PATH` on every create, update or delete:

- Writes are serialised, and each one goes to a temporary file in the same
  directory that is `fsync`ed and renamed over the file, so a crash leaves the
  old file or the new one, never a truncated one. The change is applied in
  memory only after the file write succeeds.
- The file is re-read every `FILE_STORAGE_UPDATE_INTERVAL_SEC` seconds and
  before every write, and compared by content with what the registry last read
  or wrote. An operator's edit is loaded, not overwritten. An edit that does
  not parse (including a context cell that is not base64 of JSON) is neither
  loaded nor overwritten: writes fail until it is fixed, and queries keep
  answering from the last good contents. An emptied file is treated the same
  way.
- Rows are written sorted by storage key, always with the header row.

The file has one writer: do not point two registry processes at the same file.
Use Redis, DynamoDB or fjall for that. Hand edits are best effort too:

- An edit saved while the registry is writing can be lost. The registry reads
  the file, applies its change and renames its new copy into place; an edit
  that lands between the read and the rename is replaced. Edit while no writes
  are arriving, or make changes through the Trust Task API.
- An editor that truncates the file and rewrites it in place can be caught
  half-way by a reload. A half-written file that does not parse (or is empty)
  is refused and the current records are kept, but one cut at a row boundary
  parses and is loaded as it stands; a registry write at that moment saves the
  shortened file and the rest of the edit is lost. Save by writing a new file
  and renaming it over the old one where your editor allows.

Because the file is replaced by renaming a new file over it:

- The directory holding the file must be writable by the registry, not only
  the file (the temporary file is created there). The Docker image creates
  `/app/sample-data` owned by its `trustregistry` user.
- Mount the directory into a container, never the file alone: renaming over a
  single-file bind mount fails (`EBUSY`), so every write would fail.
- A `FILE_STORAGE_PATH` that is a symbolic link is replaced by a regular file
  on the first write; the link's target is left unchanged.
- The file gets a new inode on every write. Its permissions are carried over.

### Storage key layout

The Redis, DynamoDB and fjall backends store each record under the key

```text
TR#<authority_id>#<action>#<resource>#<entity_id>
```

with `%` in an identifier written as `%25` and `#` as `%23`, so that distinct
records never share a key; an identifier containing neither is used as is.
DynamoDB puts this in the sort key `SK` under the partition key `PK = TR`.
Records written by releases before the escaping was introduced may still be
stored under the unescaped form; they are read from there and moved to the
escaped key on their next update.

## Environment Variables

Every variable the `trust-registry` server reads is listed here, grouped by
what it configures. A value that does not parse — an unknown backend name, a
non-numeric or zero interval, a boolean other than `true`/`false`, a loader URI
with an unknown scheme — stops startup with an error naming the variable; it
is never replaced by a default. An unset or empty variable takes its default.

The standalone binary also loads a `.env` file from the working directory
(values already in the environment win). A host [embedding the
registry](#embedding-the-trust-registry) builds `TrustRegistryConfig` itself and
none of these variables reach it.

`RUST_LOG` sets the diagnostic log filter (`tracing_subscriber`'s
`EnvFilter`); audit entries are written whatever it says.

#### HTTP server

| Variable | Description | Required / default |
| -------- | ----------- | ------------------ |
| `LISTEN_ADDRESS` | Socket address the REST/TRQP HTTP server (and `/health`) binds to. Ignored when `ENABLE_REST=false`. | default: `0.0.0.0:3232` |
| `CORS_ALLOWED_ORIGINS` | Origins allowed to call the HTTP API from a browser: a comma-separated list of origins exactly as browsers send them (`https://app.example.com`, `http://localhost:3000`; no path or trailing `/`), or `*` for any origin. Unset or empty: no cross-origin access (same-origin only). An entry that is not an origin stops startup. With a list, `GET`, `POST` and `OPTIONS` and the `content-type` header are allowed. | default: none (same-origin only) |
| `TR_CAPABILITY_STATE` | File capability enablement state is persisted in. Relative paths are relative to the working directory. | default: `./.trust-registry/capabilities.json` |
| `TR_HTTP_REQUEST_TIMEOUT_SECS` | The longest an HTTP request body may take to arrive (else `408`), and then the longest its answer may take (else `503` with `Retry-After`). | default: `10` |
| `TR_HTTP_HEADER_TIMEOUT_SECS` | A request's headers must be complete within this long of the connection opening, or of the next request's first byte on a kept-alive connection; the deadline does not move as bytes arrive. | default: `15` |
| `TR_HTTP_MAX_CONNECTION_AGE_SECS` | Past this age an HTTP connection is closed while it waits for a request; a request already being answered may finish, up to twice the request timeout later. Must be longer than the request timeout. | default: `300` |
| `TR_HTTP_IDLE_TIMEOUT_SECS` | An HTTP connection that sends and receives nothing for this long is closed. Must be longer than the request timeout. | default: `30` |
| `TR_HTTP_MAX_BODY_BYTES` | The largest HTTP request body accepted; a larger one is answered `413` (a problem document on the TRQP routes, `{"code": "malformedRequest", …}` on `/trust-tasks`). Also applied by `TrustRegistry::router()`. | default: `65536` |
| `TR_HTTP_MAX_CONCURRENT_REQUESTS` | The most HTTP requests answered at once; beyond it a request is answered `503` with `Retry-After` at once. A request's body is read before it takes a slot, and `/health` does not use one. | default: `256` |
| `TR_HTTP_MAX_CONNECTIONS` | The most HTTP connections held open; beyond it new connections wait until one closes. | default: `1024` |

#### Trust record storage

| Variable | Description | Required / default |
| -------- | ----------- | ------------------ |
| `TR_STORAGE_BACKEND` | Storage backend for trust records: `csv`, `dynamodb` (or `ddb`), `redis`, or `fjall` (with the `storage-fjall` feature). Matched case-insensitively. Any other value stops startup; it never falls back to CSV. The selected backend and its location are logged at startup. | default: `csv` |
| `FILE_STORAGE_PATH` | CSV file the `csv` backend reads. | default: `trust_records.csv` (relative to the working directory) |
| `FILE_STORAGE_UPDATE_INTERVAL_SEC` | How often, in seconds, the `csv` backend checks the file for changes and reloads it. A positive whole number. | default: `60` |
| `DDB_TABLE_NAME` | DynamoDB table (see [DynamoDB storage](#dynamodb-storage-storage-ddb) for its schema). | **Required** when `TR_STORAGE_BACKEND=dynamodb` |
| `AWS_REGION` | Region of the DynamoDB table. Unset: the AWS SDK resolves it (`AWS_DEFAULT_REGION`, the selected profile, instance metadata). | default: SDK resolution |
| `AWS_PROFILE` | Named AWS profile the DynamoDB client loads credentials and region from. | default: SDK default chain |
| `DYNAMODB_ENDPOINT` | DynamoDB endpoint URL, for DynamoDB Local, LocalStack or a VPC endpoint. `AWS_ENDPOINT` is the deprecated spelling (still read, with a warning); both set to different values stops startup. | default: the AWS endpoint for the region |
| `DDB_USE_TEST_CREDENTIALS` | `true` to use the SDK's static test credentials, for DynamoDB Local / LocalStack only. Never inferred from the endpoint. | default: `false` |
| `REDIS_URL` | Redis connection URL. Format: `redis://host:port` or `redis://username:password@host:port/db`. | **Required** when `TR_STORAGE_BACKEND=redis` |
| `TR_FJALL_PATH` | Directory for the embedded fjall keyspace. | default: `./trust_records.fjall` |

#### DIDComm, TSP and the registry's DID

Read only when `ENABLE_DIDCOMM=true` (the default), except the three
`ENABLE_*` flags, which are always read.

| Variable | Description | Required / default |
| -------- | ----------- | ------------------ |
| `ENABLE_REST` | Serve TRQP over REST and advertise `TRQPRest` (needs `TR_PUBLIC_URL` to be advertised). `true` or `false`. | default: `true` |
| `ENABLE_DIDCOMM` | Run the DIDComm listener and advertise `DIDCommMessaging`. `true` or `false`. | default: `true` |
| `ENABLE_TSP` | Route multiplexed TSP frames and advertise `TSPTransport`. Requires `ENABLE_DIDCOMM=true` and a binary built with `--features tsp`. `true` or `false`. | default: `false` |
| `MEDIATOR_DID` | DID of the DIDComm mediator the registry connects through. | **Required** when DIDComm is enabled |
| `PROFILE_CONFIG` | The registry's DID and private keys, as a [loader value](#profile-config-options). **_Sensitive information, do not share._** Not read when the identity comes from a VTA (`TR_VTA_CREDENTIAL`) or from a configured secret store that holds a profile bundle. | **Required** when DIDComm is enabled and neither of those supplies the identity |
| `DID_DOCUMENT` | A [loader value](#profile-config-options) holding a DID document JSON to publish instead of the generated one. Must be JSON. | default: generated from the profile |
| `TR_PUBLIC_URL` | Externally reachable base URL of the REST/TRQP surface (e.g. `https://registry.example.org`). When set, the generated DID document advertises a `TRQPRest` service entry so peers can discover the REST endpoint by resolving the registry's DID. Must be `https://` (loopback `http://` allowed for local dev). Unset ⇒ REST is still served, but not advertised. | default: unset |
| `ADMIN_DIDS` | Comma-separated DIDs that may send record-mutating Trust Tasks. Empty entries are ignored. Unset or empty: no admin (a warning is logged). | default: none |
| `ADMIN_AUTHORITIES` | JSON object mapping an admin DID to the authority DIDs it may write records under **in addition to its own DID**, e.g. `{"did:web:ops.example": ["did:web:a.example", "did:web:b.example"]}`. Every key must be in `ADMIN_DIDS`; a malformed value stops startup. Unset ⇒ each admin writes only under its own DID. List the registry's own DID for an admin to let it rotate the registry's DID and enable or disable capabilities that have no authority. | default: none |
| `ACL_MODE` | Mediator ACL mode: `ExplicitDeny` (public) or `ExplicitAllow` (private). Matched case-insensitively; any other value stops startup. | default: `ExplicitDeny` |
| `AUDIT_LOG_FORMAT` | Audit log format: `json` or `text` (`audit.<key>="<escaped value>"` pairs). Any other value stops startup. With DIDComm disabled the format is `json`. | default: `json` |
| `DID_CHECK_MAX_ATTEMPTS` | For a `did:web` registry, how many times its DID document URL is fetched before the listener starts; if none succeeds the listener does not start. A positive whole number. | default: `10` |
| `DID_CHECK_INITIAL_DELAY_SECS` | First delay between those checks, doubling each time. A positive whole number. | default: `2` |
| `DID_CHECK_MAX_DELAY_SECS` | Cap on that delay. A positive whole number, at least `DID_CHECK_INITIAL_DELAY_SECS`. | default: `20` |
| `TR_MESSAGING_STORE_PATH` | Directory of the TSP messaging store (TSP relationships, fjall); a subdirectory named after the profile alias is used. | default: `messaging` under `TR_SECRETS_DATA_DIR`, else `./.trust-registry/messaging` |
| `TR_TSP_MAX_RELATIONSHIPS` | The most TSP relationships with non-admin peers the registry keeps. When the store is full, a new peer may only displace a relationship that never completed, or one idle for a quarter of `TR_TSP_RELATIONSHIP_IDLE_SECS` (at least an hour); otherwise it is refused. `/health` reports `"tspRelationships": "full"` (status `degraded`) while the store is at its limit. Relationships with `ADMIN_DIDS` are not counted and never displaced. A value that is not a positive whole number stops startup. | default: `10000` |
| `TR_TSP_MAX_NEW_RELATIONSHIPS_PER_MINUTE` | The most TSP relationships with new non-admin peers recorded per minute; beyond it an invite is not recorded. | default: `60` |
| `TR_TSP_RELATIONSHIP_IDLE_SECS` | How long a TSP relationship with no activity (no accepted invite, no application message) is kept before it is evicted. At least `60`. | default: `604800` (7 days) |

The identity variables of the `vta` feature (`TR_VTA_*`, `TR_ALIAS`) are listed
under [Identity from a VTA](#identity-from-a-vta-vta), and the secret-store
variables (`TR_SECRETS_*`, `VAULT_*`) under [Secret-store
backends](#secret-store-backends-secrets-).

#### Read by the development tools only

| Variable | Read by | Description |
| -------- | ------- | ----------- |
| `MEDIATOR_URL`, `MEDIATOR_DID`, `IN_PIPELINE` | `generate-secrets` | Mediator to generate test identities against; `IN_PIPELINE=true` for CI. |
| `TR_PUBLIC_URL`, `ENABLE_REST`, `ENABLE_DIDCOMM`, `ENABLE_TSP`, `TR_SECRETS_*` | `setup-trust-registry` | As above: the DID document it generates and the secret store it provisions follow the same settings as the server. |
| `TRUST_REGISTRY_DID`, `CLIENT_DID`, `CLIENT_SECRETS` | integration tests | Written to `.env.test` by `setup-trust-registry`; not read by the server. |

### Transport selection

`ENABLE_REST`, `ENABLE_DIDCOMM` and `ENABLE_TSP` each govern **both** halves of a
transport: whether it is served, and whether the DID document advertises it. A
single flag per protocol is deliberate — a registry that advertises a service
entry nothing answers sends clients to a dead endpoint, and `trql-client`
refuses to silently downgrade to another transport when the selected one fails.

Rules enforced at startup (and by `setup_trust_registry` when generating the
DID document, which reads the same flags):

- **At least one transport must be enabled.** All three `false` is refused.
- **`ENABLE_TSP=true` requires `ENABLE_DIDCOMM=true`.** TSP frames are
  multiplexed onto the DIDComm mediator socket — the mediator permits one
  websocket per DID — so there is no TSP-only receive loop.
- **`ENABLE_TSP=true` requires `--features tsp`.** A runtime flag cannot enable
  a compiled-out binding; the build fails startup rather than advertise TSP.
- **A TSP relationship is formed with any sender TSP authenticates**; what a
  sender may do is decided per Trust Task. The relationship store is therefore
  bounded (`TR_TSP_MAX_RELATIONSHIPS`, `TR_TSP_MAX_NEW_RELATIONSHIPS_PER_MINUTE`;
  a new peer never displaces a relationship in use, nor an admin's) and evicts
  relationships idle for `TR_TSP_RELATIONSHIP_IDLE_SECS`. With `ACL_MODE=ExplicitAllow` the mediator's
  allow list also limits who can reach the registry.
- **`ENABLE_REST=false` binds no socket at all.** There is no HTTP listener —
  no TRQP routes and no `/health` — so `LISTEN_ADDRESS` is ignored and cannot
  conflict with another process. Monitor a DIDComm-only registry by other
  means (process supervision, logs, a DIDComm round-trip).
- **`ENABLE_REST=true` without `TR_PUBLIC_URL`** serves REST but does not
  advertise it, and warns at startup. The bind address in `LISTEN_ADDRESS` is
  not a fallback: it is frequently `0.0.0.0`.

The DIDComm and TSP service endpoints both carry the **mediator DID**, not a
URL — the transport URL lives in the mediator's own DID document. REST carries
its URL directly.

> **Note:** with `ENABLE_DIDCOMM=false` no DID document is built at all, since
> the registry's DID profile is loaded on the DIDComm path. A REST-only registry
> is reached by URL rather than by resolving its DID.

The document served at `/.well-known/did.json` is the one set in `DID_DOCUMENT`
(a loader URI, like `PROFILE_CONFIG`), or else built from the profile by the
same builder `setup-trust-registry` uses for a did:web / did:webvh: one
`Multikey` verification method per secret, under the secret's own id, with
signing keys (Ed25519, P-256, secp256k1) under `authentication` and
`assertionMethod` and X25519 keys under `keyAgreement`. A profile with no
X25519 key (one generated before the move to Curve25519) lists its P-256 /
secp256k1 keys under `keyAgreement` too. A secret that cannot be published this
way stops startup.

### Profile Config Options

The `PROFILE_CONFIG` environment variable uses a URI-based loader that supports multiple configuration options. The loader allows you to store DID and DID secrets securely according to your deployment requirements.

| Scheme              | Format                                                    | Description                                                                                                               |
| ------------------- | --------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------- |
| Direct Value        | `PROFILE_CONFIG='<JSON_STRING>'`                          | Store the configuration directly as an inline JSON string in the environment variable. Recommended for local development. |
| String Protocol     | `PROFILE_CONFIG='string://<JSON_STRING>'`                 | Explicitly specify the value as a string literal. Same functionality as the direct value option.                          |
| File System         | `PROFILE_CONFIG='file:///path/to/config.json'`            | Load configuration from a JSON file on the local filesystem. The path must be accessible by the application.              |
| AWS Secrets Manager | `PROFILE_CONFIG='aws_secrets://<SECRET_NAME>'`            | Retrieve configuration from AWS Secrets Manager. The secret value must be stored in plaintext format as a JSON string.    |
| AWS Parameter Store | `PROFILE_CONFIG='aws_parameter_store://<PARAMETER_NAME>'` | Load configuration from AWS Systems Manager Parameter Store. The parameter value must be a JSON string.                   |

**Expected Value:**

All options must provide the Trust Registry DID and DID secrets in the following JSON structure:

```json
{
  "alias": "Trust Registry",
  "did": "did:peer:2.VzDna...",
  "secrets": [
    {
      "id": "did:peer:2.VzDna...#key-1",
      "privateKeyJwk": {
        "crv": "Ed25519",
        "d": "...",
        "kty": "OKP",
        "x": "Vd8C1RjQ4Ow..."
      },
      "type": "JsonWebKey2020"
    },
    {
      "id": "did:peer:2.VzDna...#key-2",
      "privateKeyJwk": {
        "crv": "X25519",
        "d": "...",
        "kty": "OKP",
        "x": "3xG7j0dbVvo..."
      },
      "type": "JsonWebKey2020"
    }
  ]
}
```

**Examples:**

```bash
# Direct value (local development)
PROFILE_CONFIG='{"alias":"Trust Registry","did":"did:peer:2.VzDna...","secrets":[...]}'

# File-based configuration
PROFILE_CONFIG='file:///etc/trust-registry/config.json'

# AWS Secrets Manager
PROFILE_CONFIG='aws_secrets://prod/trust-registry/profile'

# AWS Parameter Store
PROFILE_CONFIG='aws_parameter_store:///trust-registry/profile'
```

**Note:** A value with no URI scheme (inline JSON) is used as it is. A value
that starts like a URI (`<scheme>:`) with any scheme other than the four above —
a typo such as `aws_secret://`, `File:///` or `file:/etc/…` — stops startup with
an error naming the variable; it is never used as a literal. The same loader,
and the same rule, apply to `DID_DOCUMENT` and `TR_VTA_CREDENTIAL`.

## Additional Resources

- [DIDComm Protocols Used](https://github.com/affinidi/affinidi-trust-registry-rs/blob/main/DIDCOMM_PROTOCOLS.md)
- [Trust Registry Setup Guide](https://github.com/affinidi/affinidi-trust-registry-rs/blob/main/SETUP_COMMAND_REFERENCES.md)

## Support & feedback

If you face any issues or have suggestions, please don't hesitate to contact us using [this link](https://share.hsforms.com/1i-4HKZRXSsmENzXtPdIG4g8oa2v).

### Reporting technical issues

If you have a technical issue with the project's codebase, you can also create an issue directly in GitHub.

1. Ensure the bug was not already reported by searching on GitHub under
   [Issues](https://github.com/affinidi/affinidi-trust-registry-rs/issues).

2. If you're unable to find an open issue addressing the problem,
   [open a new one](https://github.com/affinidi/affinidi-trust-registry-rs/issues/new).
   Be sure to include a **title and clear description**, as much relevant information as possible,
   and a **code sample** or an **executable test case** demonstrating the expected behaviour that is not occurring.

## Contributing

Want to contribute?

Head over to our [CONTRIBUTING](https://github.com/affinidi/affinidi-trust-registry-rs/blob/main/CONTRIBUTING.md) guidelines.

## Changelog

See [CHANGELOG](./CHANGELOG.md) for release notes.
