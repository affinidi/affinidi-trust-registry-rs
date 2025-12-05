# Affinidi Trust Registry

[![Licence: Apache](https://img.shields.io/badge/licence-Apache%202.0-blue)](LICENCE)

A high-performance, Rust-based implementation of a Trust Registry, fully compliant with the [Trust Registry Query Protocol (TRQP) v2.0](https://trustoverip.github.io/tswg-trust-registry-protocol/) specification. Built for scalability and reliability, it enables secure, standards-based verification of trusted entities within decentralised identity ecosystems.

## Table of Contents

- [What is Trust Registry](#what-is-trust-registry)
  - [Why a Trust Registry Matters](#why-a-trust-registry-matters)
  - [Sample Use Cases](#sample-use-cases)
- [Key Components](#key-components)
- [Requirements](#requirements)
- [Set up Environment](#set-up-environment)
- [Start the Server](#start-the-server)
  - [Run on Local Machine](#run-on-local-machine)
  - [Run on Docker](#run-on-docker)
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

## What is Trust Registry

A **Trust Registry** is a system that maintains and provides authoritative information about which entities, such as organisations, issuers, verifiers, are authorised to perform specific actions on defined resources within a trust framework. Each entity is identified by its Decentralised Identifier (DID), ensuring cryptographic integrity and interoperability across decentralised identity ecosystems.

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

  Ensure that all participants in a digital trust ecosystem, such as issuers, verifiers, and relying parties, are recognised and approved by the appropriate governance authorities.

## Key Components

- **`trust-registry`**: Unified server providing both RESTful API (TRQP endpoints for recognition and authorisation queries) and optional DIDComm messaging interface for CRUD admin operations.

- **Storage backends**: Storing authoritative records about the entities for querying. It supports the following storage types:
  - CSV file storage
  - AWS DynamoDB

## Requirements

Install Rust on your machine.

- **Rust**: 1.88.0 or higher
- **Edition**: 2024
- **Cargo**: Latest version bundled with Rust

Verify that your Rust installation meets the requirements.

```bash
rustc --version
cargo --version
```

## Set up Environment

Generate the required DIDs and keys for local deployment. The command will populate the secrets to the `.env` and `.env.test`.

```bash
MEDIATOR_URL="https://your-mediator-url.io" MEDIATOR_DID="did:web:your-mediator-did.io" cargo run --bin generate-secrets --features dev-tools
```

Replace the `MEDIATOR_URL` and `MEDIATOR_DID` with your own mediator instance.

For more information on running your own DIDComm mediator, refer to the [deployment options](https://docs.affinidi.com/products/affinidi-messaging/didcomm-mediator/deployment-options/) page in the documentation.

The command generates:

- **3 DIDs** and their corresponding keys.
- DIDComm server environment variables:
  - `PROFILE_CONFIG`
- Testing environment variables:
  - `PROFILE_CONFIG`
  - `TRUST_REGISTRY_DID`
  - `CLIENT_DID`
  - `CLIENT_SECRETS`
  - `ADMIN_DIDS`

## Start the Server

### Run on Local Machine

To start the Trust Registry HTTP and DIDComm servers, run the following command from the root directory of the repository:

```bash
RUST_LOG=info cargo run --bin trust-registry
```

The command will launch the service with logging enabled at the info level.

To run Trust Registry without DIDComm functionality:

```bash
ENABLE_DIDCOMM=false RUST_LOG=info cargo run --bin trust-registry
```

### Run on Docker

Review environment variables in `./docker-compose.yaml` and start the containers:

```bash
docker compose up --build
```

**Note:** The `sample-data` folder is mounted as a volume to synchronise the changes from data.csv to the container automatically.

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

**Testing Tips:**

- Add more records to `./sample-data/data.csv` to expand test coverage.
- Test with both defined and undefined IDs to ensure the system correctly handles invalid or missing identifiers.
- Ensure the `context` field contains a valid JSON object encoded in Base64. Invalid or malformed data should trigger appropriate error responses.

## Manage Trust Records

You can manage trust records stored in the Trust Registry using DIDComm by sending messages to the Trust Registry’s DID. DIDComm provides a secure, interoperable way to exchange messages between administrator and Trust Registry, making it ideal for trust record operations such as creating, updating, or querying records.

For reference, see the [test-client implementation](./test-client/), which demonstrates how to build DIDComm clients and send these messages.

To run the sample client and interact with the Trust Registry:

```bash
MEDIATOR_DID="<TRUST_REGISTRY_MEDIATOR_DID>" TRUST_REGISTRY_DID="<TRUST_REGISTRY_DID>" cargo run --bin test-client
```

See [DIDComm Protocols](./DIDCOMM_PROTOCOLS.md) for more details.

## Environment Variables

See the list of environment variables and their usage.

Variable Name | Description | Required |
--------------|-------------|----------|
`TR_STORAGE_BACKEND` | Storage to use to store trust records. Options: `csv`, `ddb`. | Yes |
`FILE_STORAGE_PATH` | Path to the file if using CSV as the storage. | Only when `TR_STORAGE_BACKEND` = 'csv' |
`DDB_TABLE_NAME` | Table name to store the trust records if using DDB as the storage. | Only when `TR_STORAGE_BACKEND` = 'ddb' |
`CORS_ALLOWED_ORIGINS` | List of URLs separated by comma to allow for CORS. | Yes |
`AUDIT_LOG_FORMAT` | Format to store the audit logs. Options: `text`, `json`. | Yes |
`MEDIATOR_DID` | Decentralised Identifier (DID) of the mediator. If DIDComm is enabled, managing trust records uses DIDComm mediator as a transport layer to send payloads. | Only when DIDComm is enabled. |
`ADMIN_DIDS` | List of DIDs authorised to manage the trust records of the Trust Registry. | Only when DIDComm is enabled. |
`PROFILE_CONFIG` | DID and DID secret of the Trust Registry for DIDComm communication. ***Sensitive information, do not share.*** | Only when DIDComm is enabled. |

### Profile Config Options

The `PROFILE_CONFIG` environment variable uses a URI-based loader that supports multiple configuration options. The loader allows you to store DID and DID secrets securely according to your deployment requirements.


| Scheme | Format | Description |
|--------|--------|-------------|
| Direct Value | `PROFILE_CONFIG='<JSON_STRING>'` | Store the configuration directly as an inline JSON string in the environment variable. Recommended for local development. |
| String Protocol | `PROFILE_CONFIG='string://<JSON_STRING>'` | Explicitly specify the value as a string literal. Same functionality as the direct value option. |
| File System | `PROFILE_CONFIG='file:///absolute/path/to/config.json'` | Load configuration from a JSON file on the local filesystem. The path must be absolute and accessible by the application. |
| AWS Secrets Manager | `PROFILE_CONFIG='aws_secrets://<SECRET_NAME>'` | Retrieve configuration from AWS Secrets Manager. The secret value must be stored in plaintext format as a JSON string. |
| AWS Parameter Store | `PROFILE_CONFIG='aws_parameter_store://<PARAMETER_NAME>'` | Load configuration from AWS Systems Manager Parameter Store. The parameter value must be a JSON string. |

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

- [DIDComm Protocols Used](./DIDCOMM_PROTOCOLS.md)

## Support & feedback

If you face any issues or have suggestions, please don't hesitate to contact us using [this link](https://share.hsforms.com/1i-4HKZRXSsmENzXtPdIG4g8oa2v).

### Reporting technical issues

If you have a technical issue with the project's codebase, you can also create an issue directly in GitHub.

1. Ensure the bug was not already reported by searching on GitHub under
   [Issues](https://github.com/affinidi/trust-registry-rs/issues).

2. If you're unable to find an open issue addressing the problem,
   [open a new one](https://github.com/affinidi/trust-registry-rs/issues/new).
   Be sure to include a **title and clear description**, as much relevant information as possible,
   and a **code sample** or an **executable test case** demonstrating the expected behaviour that is not occurring.

## Contributing

Want to contribute?

Head over to our [CONTRIBUTING](CONTRIBUTING.md) guidelines.
