# Affinidi Trust Registry

[![License: Apache](https://img.shields.io/badge/license-Apache%202.0-blue)](LICENSE)

A high-performance, Rust-based implementation of a Trust Registry, fully compliant with the [Trust Registry Query Protocol (TRQP) v2.0](https://trustoverip.github.io/tswg-trust-registry-protocol/) specification. Built for scalability and reliability, it enables secure, standards-based verification of trusted entities within decentralised identity ecosystems.

## Table of Contents

- [Quickstart](#quickstart)
- [What is Trust Registry](#what-is-trust-registry)
  - [Why a Trust Registry Matters](#why-a-trust-registry-matters)
  - [Sample Use Cases](#sample-use-cases)
- [Key Components](#key-components)
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
- [Trust Tasks, Transports & Identity](#trust-tasks-transports--identity)
  - [Cargo feature flags](#cargo-feature-flags)
  - [Trust Task protocol surface](#trust-task-protocol-surface)
  - [Identity from a VTA (`vta`)](#identity-from-a-vta-vta)
  - [Secret-store backends (`secrets-*`)](#secret-store-backends-secrets-)
  - [Embedded fjall storage (`storage-fjall`)](#embedded-fjall-storage-storage-fjall)
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

2. Start the Trust Registry server.

```bash
ENABLE_DIDCOMM=false RUST_LOG=info cargo run --bin trust-registry
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

- **`trust-registry`**: Unified server providing both RESTful API (TRQP endpoints for recognition and authorisation queries) and optional DIDComm messaging interface for CRUD admin operations.

- **Storage backends**: Stores authoritative records about the entities for querying. It supports the following storage types:
  - CSV file storage
  - AWS DynamoDB
  - Redis
  - Embedded [fjall](https://github.com/fjall-rs/fjall) LSM store (behind the `storage-fjall` feature)

- **Trust Tasks & transports** _(optional)_: Every Trust Registry operation is also modelled as a versioned [Trust Task](https://trusttasks.org) (`registry/*`) that verifiers and communities (VTC/OpenVTC) can invoke over DIDComm, HTTP, or TSP. See [Trust Tasks, Transports & Identity](#trust-tasks-transports--identity).

- **VTA identity** _(optional)_: The Trust Registry can source its DID and keys from a [Verifiable Trust Agent](https://docs.affinidi.com) instead of a local `PROFILE_CONFIG` (behind the `vta` feature).

## Requirements

1. Install Rust on your machine.

- **Rust**: 1.88.0 or higher
- **Edition**: 2024
- **Cargo**: Latest version bundled with Rust

Verify that your Rust installation meets the requirements.

```bash
rustc --version
cargo --version
```

2. **Required for DIDComm-enabled.** DIDComm mediator instance is required if you want to enable DIDComm for secure trust record management and querying.

To deploy and run a DIDComm mediator, see the [deployment options](https://docs.affinidi.com/products/affinidi-messaging/didcomm-mediator/deployment-options/) page in the documentation.

## Set up Trust Registry

Configure the environment to run Trust Registry. The setup command creates the `.env` file with default configurations. For testing environments, it generates `.env.test` or `.env.pipeline` files with the appropriate test configurations.

### Run with DIDComm Enabled

**Prerequisites:** You must have a running and accessible DIDComm mediator instance before proceeding. The mediator provides the messaging layer for secure communication between administrators, verifiers, and the Trust Registry.

If you don't have a mediator yet, see [deployment options](https://docs.affinidi.com/products/affinidi-messaging/didcomm-mediator/deployment-options/).

To enable DIDComm for managing and querying trust records, run the following command with your mediator's DID:

```bash
cargo run --bin setup-trust-registry --features="dev-tools" -- \
 --mediator-did=<MEDIATOR_DID>
```

The command generates the following:

- Creates a Decentralised Identifier (DID) for the Trust Registry using the **did:peer** method.
- Creates Decentralised Identifiers (DIDs) for test users (Trust Registry and Admin) using the did:peer method.
- Configures the appropriate DIDComm mediator ACLs for the Trust Registry and test user DIDs.
- Populates the environment variables with default values, such as Storage Backend (`csv`) and audit log format (`json`).

### Run with DIDComm Enabled In Private Mode

By default, the Trust Registry runs in **public mode** (`ACL_MODE=ExplicitDeny`), which accepts messages from any DID. To enable **private mode** where only pre-authorized DIDs can send messages to the Trust Registry, use the `--acl-mode=ExplicitAllow` option:

```bash
cargo run --bin setup-trust-registry --features="dev-tools" -- \
 --mediator-did=<MEDIATOR_DID> \
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
- Sets DIDComm-related environment variables to empty values.

After successful setup, it displays the command to run the Trust Registry.

```bash
ENABLE_DIDCOMM=false RUST_LOG=info cargo run --bin trust-registry
```

For more details on setting up the Trust Registry, refer to the [setup guide](https://github.com/affinidi/affinidi-trust-registry-rs/blob/main/SETUP_COMMAND_REFERENCES.md) document.

## Run Trust Registry on Docker

After setting up the Trust Registry, review the Docker settings in `./docker-compose.yaml`. Start the containers using the following command:

```bash
docker compose up --build
```

The Trust Registry will be available at `http://localhost:3232`.

**Note:** The `sample-data` folder is mounted as a volume to synchronise the changes from data.csv to the container automatically. If you have configured a different path for the data using CSV as the storage backend, configure the Docker settings accordingly.

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
- **Data Structure**: Trust records are stored as JSON strings with keys formatted as `entity_id|authority_id|action|resource`

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
    command: redis-server --requirepass your_password --appendonly yes
    ports:
      - "6379:6379"
    volumes:
      - redis-data:/data
    restart: unless-stopped

  trust-registry:
    build: .
    environment:
      - TR_STORAGE_BACKEND=redis
      - REDIS_URL=redis://:your_password@redis:6379
      - ENABLE_DIDCOMM=false
      - CORS_ALLOWED_ORIGINS=http://localhost:3000
      - AUDIT_LOG_FORMAT=json
    ports:
      - "3232:3232"
    depends_on:
      - redis
    restart: unless-stopped

volumes:
  redis-data:
```

### Migrating from CSV/DynamoDB to Redis

To migrate existing trust records to Redis:

1. Export records from your current storage backend
2. Use the DIDComm admin API to create records in Redis
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
# List all keys
redis-cli KEYS "*|*|*|*"

# Get a specific record
redis-cli GET "did:example:entity1|did:example:authority1|action1|resource1"
```

**Clear all test data:**
```bash
redis-cli FLUSHDB
```

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

**Testing Tips:**

- Add more records to `./sample-data/data.csv` to expand test coverage.
- Test with both defined and undefined IDs to ensure the system correctly handles invalid or missing identifiers.
- Ensure the `context` field contains a valid JSON object encoded in Base64. Invalid or malformed data should trigger appropriate error responses.

## Manage Trust Records

**Note:** This section applies only when DIDComm is enabled. See [Run with DIDComm Enabled](#run-with-didcomm-enabled) for setup instructions.

You can manage trust records stored in the Trust Registry using DIDComm by sending messages to the Trust Registry's DID. DIDComm provides a secure, interoperable way to exchange messages between an administrator and the Trust Registry, making it ideal for trust record operations such as creating, updating, or querying records.

For a working reference, see the [test-client implementation](https://github.com/affinidi/affinidi-trust-registry-rs/tree/main/test-client), which demonstrates how to build a DIDComm client and send admin operation messages.

See [Trust Registry Administration](https://github.com/affinidi/affinidi-trust-registry-rs/blob/main/DIDCOMM_PROTOCOLS.md#trust-registry-administration) section for more details.

## Trust Tasks, Transports & Identity

Beyond the core REST/DIDComm server, the Trust Registry ships a set of **optional,
feature-gated** capabilities that let Verifiable Trust Communities (VTC/OpenVTC)
and verifiers interact with it as a first-class [Trust Tasks](https://trusttasks.org)
participant, and let it delegate its own identity and secret custody. All of these
are **off by default** — the default build is the REST + DIDComm server described
above.

### Cargo feature flags

| Feature          | Default | Enables                                                                                                                       |
| ---------------- | :-----: | ----------------------------------------------------------------------------------------------------------------------------- |
| `secrets-config` |   ✅    | Inline / plaintext-file secret store for the profile bundle (no extra dependencies).                                          |
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
| `registry/recognition/0.1`                            | read  | none (TRQP recognition query) |
| `registry/authorization/0.1`                          | read  | none (TRQP authorization query)|
| `registry/record/read/0.1`, `registry/record/list/0.1`| read  | none                          |
| `registry/record/create/0.1`                          | write | admin DID + proof             |
| `registry/record/update/0.1`                          | write | admin DID + proof             |
| `registry/record/delete/0.1`                          | write | admin DID + proof             |
| `registry/did/rotate/0.1`                             | write | admin DID + proof (`vta` only)|

**Writes** (record mutations and DID rotation) require the sender DID to be in
`ADMIN_DIDS` **and** the Trust Task to carry a Data-Integrity proof. The reads map
verbatim onto the [TRQP v2.0](https://trustoverip.github.io/tswg-trust-registry-protocol/)
recognition/authorization field names, so the plain HTTP TRQP endpoints and the
Trust Task payloads share a single schema.

### Identity from a VTA (`vta`)

With `--features vta`, the Trust Registry authenticates to a Verifiable Trust Agent
at startup and pulls its DID and private keys from a VTA context (remote key
custody) instead of loading a local `PROFILE_CONFIG`. The bundle is cached through
the configured [secret-store backend](#secret-store-backends-secrets-) so the
service can still boot while the VTA is briefly unreachable.

The registry's DID is a VTA-managed `did:webvh`; its keys can be rotated in place
via the `registry/did/rotate/0.1` admin Trust Task (admin-DID + proof gated).

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
mediator-setup and did-hosting tooling.

| Variable                                                                              | Backend                       |
| ------------------------------------------------------------------------------------- | ----------------------------- |
| `TR_SECRETS_SEED`, `TR_SECRETS_ALLOW_PLAINTEXT`, `TR_SECRETS_DATA_DIR`                 | config / plaintext file       |
| `TR_SECRETS_AWS_REGION`, `TR_SECRETS_AWS_SECRET_NAME`                                  | AWS Secrets Manager           |
| `TR_SECRETS_GCP_PROJECT`, `TR_SECRETS_GCP_SECRET_NAME`                                 | GCP Secret Manager            |
| `TR_SECRETS_AZURE_VAULT_URL`, `TR_SECRETS_AZURE_SECRET_NAME`                           | Azure Key Vault               |
| `TR_SECRETS_VAULT_ADDR`, `TR_SECRETS_VAULT_TOKEN`, `TR_SECRETS_VAULT_NAMESPACE`, `TR_SECRETS_VAULT_SECRET_PATH` | HashiCorp Vault  |
| `TR_SECRETS_KEYRING_SERVICE`                                                           | OS keyring                    |

### Embedded fjall storage (`storage-fjall`)

With `--features storage-fjall` and `TR_STORAGE_BACKEND=fjall`, trust records are
stored in an embedded [fjall](https://github.com/fjall-rs/fjall) LSM store — a
single-node, on-disk option that needs no external database.

| Variable         | Description                                                | Required                                       |
| ---------------- | ---------------------------------------------------------- | ---------------------------------------------- |
| `TR_FJALL_PATH`  | Directory for the embedded fjall keyspace.                 | Required when `TR_STORAGE_BACKEND` = `fjall`   |

## Environment Variables

See the list of environment variables and their usage.

| Variable Name           | Description                                                                                                                                                                               | Required                                     |
| ----------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------- |
| `TR_STORAGE_BACKEND`    | Storage backend for trust records. Options: `csv`, `ddb`, `redis`, and `fjall` (with the `storage-fjall` feature).                                                                        | Yes                                          |
| `FILE_STORAGE_PATH`     | Path to the CSV file when using CSV as the storage backend.                                                                                                                               | Required when `TR_STORAGE_BACKEND` = `csv`   |
| `DDB_TABLE_NAME`        | DynamoDB table name for storing trust records when using DDB as the storage backend.                                                                                                      | Required when `TR_STORAGE_BACKEND` = `ddb`   |
| `REDIS_URL`             | Redis connection URL when using Redis as the storage backend. Format: `redis://host:port` or `redis://username:password@host:port/db`.                                                    | Required when `TR_STORAGE_BACKEND` = `redis` |
| `CORS_ALLOWED_ORIGINS`  | Comma-separated list of allowed URLs for CORS.                                                                                                                                            | Yes                                          |
| `AUDIT_LOG_FORMAT`      | Output format for audit logs. Options: `text`, `json`.                                                                                                                                    | Yes                                          |
| `MEDIATOR_DID`          | Decentralised Identifier (DID) of the DIDComm mediator used as a transport layer for managing trust records.                                                                              | Required when DIDComm is enabled             |
| `ADMIN_DIDS`            | Comma-separated list of DIDs authorised to manage trust records in the Trust Registry.                                                                                                    | Required when DIDComm is enabled             |
| `PROFILE_CONFIG`        | Trust Registry DID and DID secrets for DIDComm communication. See [Profile Config Options](#profile-config-options) for configuration formats. **_Sensitive information, do not share._** | Required when DIDComm is enabled             |
| `ACL_MODE` | ACL Mode for Trust Registry when DIDComm is enabled. ExplicitDeny - public mode, ExplicitAllow - private mode                                                                                                          | default: `ExplicitDeny`                             |

### Profile Config Options

The `PROFILE_CONFIG` environment variable uses a URI-based loader that supports multiple configuration options. The loader allows you to store DID and DID secrets securely according to your deployment requirements.

| Scheme              | Format                                                    | Description                                                                                                               |
| ------------------- | --------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------- |
| Direct Value        | `PROFILE_CONFIG='<JSON_STRING>'`                          | Store the configuration directly as an inline JSON string in the environment variable. Recommended for local development. |
| String Protocol     | `PROFILE_CONFIG='string://<JSON_STRING>'`                 | Explicitly specify the value as a string literal. Same functionality as the direct value option.                          |
| File System         | `PROFILE_CONFIG='file://path/to/config.json'`             | Load configuration from a JSON file on the local filesystem. The path must be accessible by the application.              |
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
        "crv": "P-256",
        "kty": "EC",
        "x": "RgvVBx01Mva...",
        "y": "U5pT2A5WdIkD..."
      },
      "type": "JsonWebKey2020"
    },
    {
      "id": "did:peer:2.VzDna...#key-2",
      "privateKeyJwk": {
        "crv": "secp256k1",
        "d": "...",
        "kty": "EC",
        "x": "O9pWQXY...",
        "y": "TQk8LY_BcY..."
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

**Note:** If no URI scheme is specified, the loader parses the value as a direct string literal by default.

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
