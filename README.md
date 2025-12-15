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
  - [Run with DIDComm Disabled](#run-with-didcomm-disabled)
- [Run Trust Registry on Docker](#run-trust-registry-on-docker)
- [Test the API](#test-the-api)
  - [Recognition Query](#recognition-query)
  - [Authorization Query](#authorization-query)
- [Manage Trust Records](#manage-trust-records)
- [Environment Variables](#environment-variables)
  - [Profile Config Options](#profile-config-options)
- [Additional Resources](#additional-resources)
- [Support \& feedback](#support--feedback)
  - [Reporting technical issues](#reporting-technical-issues)
- [Contributing](#contributing)

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

To enable DIDComm for managing and querying trust records, run the following command with your mediator's DID and URL:

```bash
cargo run --bin setup-trust-registry --features="dev-tools" -- --mediator-did=<MEDIATOR_DID> --mediator-url=<MEDIATOR_URL>
```

The command generates the following:

- Creates a Decentralised Identifier (DID) for the Trust Registry using the **did:peer** method.
- Creates Decentralised Identifiers (DIDs) for test users (Trust Registry and Admin) using the did:peer method.
- Configures the appropriate DIDComm mediator ACLs for the Trust Registry and test user DIDs.
- Populates the environment variables with default values, such as Storage Backend (`csv`) and audit log format (`json`).

### Run with Didcomm Enabled Only for Admin Operations

This command performs the same setup as the previous one, but with an additional flag:

`--only-admin-operations=true`

This flag ensures that the Trust Registry (TR) does **not** switch to _Explicit Deny_ on start. Instead, it will start in **Explicit Allow** mode. In this mode, only the admin DIDs specified will be explicitly allowed to perform operations.

Example:

```bash
cargo run --bin setup-trust-registry --features="dev-tools" -- \
  --mediator-did=<MEDIATOR_DID> \
  --mediator-url=<MEDIATOR_URL> \
  --only-admin-operations=true
```

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

For reference, see the [test-client implementation](https://github.com/affinidi/affinidi-trust-registry-rs/tree/main/test-client), which demonstrates how to build DIDComm clients and send these messages.

To run the sample client and interact with the Trust Registry:

```bash
MEDIATOR_DID="<TRUST_REGISTRY_MEDIATOR_DID>" TRUST_REGISTRY_DID="<TRUST_REGISTRY_DID>" cargo run --bin test-client
```

See [Trust Registry Administration](https://github.com/affinidi/affinidi-trust-registry-rs/blob/main/DIDCOMM_PROTOCOLS.md#trust-registry-administration) section for more details.

## Environment Variables

See the list of environment variables and their usage.

| Variable Name          | Description                                                                                                                                                                               | Required                                   |
| ---------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------ |
| `TR_STORAGE_BACKEND`   | Storage backend for trust records. Options: `csv`, `ddb`.                                                                                                                                 | Yes                                        |
| `FILE_STORAGE_PATH`    | Path to the CSV file when using CSV as the storage backend.                                                                                                                               | Required when `TR_STORAGE_BACKEND` = `csv` |
| `DDB_TABLE_NAME`       | DynamoDB table name for storing trust records when using DDB as the storage backend.                                                                                                      | Required when `TR_STORAGE_BACKEND` = `ddb` |
| `CORS_ALLOWED_ORIGINS` | Comma-separated list of allowed URLs for CORS.                                                                                                                                            | Yes                                        |
| `AUDIT_LOG_FORMAT`     | Output format for audit logs. Options: `text`, `json`.                                                                                                                                    | Yes                                        |
| `MEDIATOR_DID`         | Decentralised Identifier (DID) of the DIDComm mediator used as a transport layer for managing trust records.                                                                              | Required when DIDComm is enabled           |
| `ADMIN_DIDS`           | Comma-separated list of DIDs authorised to manage trust records in the Trust Registry.                                                                                                    | Required when DIDComm is enabled           |
| `PROFILE_CONFIG`       | Trust Registry DID and DID secrets for DIDComm communication. See [Profile Config Options](#profile-config-options) for configuration formats. **_Sensitive information, do not share._** | Required when DIDComm is enabled           |
| `ONLY_ADMIN_OPS`       | Trust Registry use DIDComm communication only for admin operations and not TRQP.                                                                                                          | default: `false`                           |

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
