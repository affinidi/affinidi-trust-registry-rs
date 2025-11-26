# Affinidi Trust Registry

[![Licence: Apache](https://img.shields.io/badge/licence-Apache%202.0-blue)](LICENCE)

> A high-performance, specification-compliant Trust Registry implementation in Rust, supporting the Trust Registry Query Protocol (TRQP) v2.0.

## Table of Contents

- [Overview](#overview)
  - [What Problem Does It Solve?](#what-problem-does-it-solve)
  - [Key Use Cases](#key-use-cases)
- [Getting Started](#getting-started)
  - [Requirements](#requirements)
  - [Installation](#installation)
- [Usage](#usage)
  - [Run Locally](#run-locally)
  - [Run in Docker](#run-in-docker)
- [Testing](#testing)
- [Contributing](#contributing)
- [Support & feedback](#support--feedback)

## Overview

A **Trust Registry** is a decentralised system that maintains authoritative records about which entities (identified by DIDs - Decentralised Identifiers) are authorised to perform specific actions on specific resources within a trust framework. This project provides a production-ready implementation that enables verification of trust relationships in decentralised identity ecosystems.

### What Problem Does It Solve?

In decentralised identity systems, verifiers need to answer critical questions like:

- "Is this issuer authorised to issue driver's licences?"
- "Is this credential verifier recognised by the appropriate authority?"
- "Can this entity perform a specific action within this trust framework?"

Authorisation Queries: “Has Authority A authorised Entity B to take Action X on Resource Y?”

Recognition Queries: "Does Authority X recognise Entity B as an authority to authorise taking Action X on Resource Y?”

The Trust Registry provides a standardised, queryable database that answers these questions by maintaining trust records that link:

- **Entity IDs** (who) - DIDs representing issuers, verifiers, or other participants
- **Authority IDs** (governed by whom) - DIDs of governing authorities
- **Actions** (what) - Operations like "issue", "verify", "revoke"
- **Resources** (on what) - Credential types like "driverlicence", "diploma"
- **Context** - Additional metadata for authorisation decisions

### Key Use Cases

1. **Credential Issuance Verification**: Verify that an issuer is authorised by a government or regulatory body to issue specific credential types
2. **Trust Framework Compliance**: Ensure participants in a digital trust ecosystem are recognised by the appropriate governance authorities

### Components

- **`http-server`**: RESTful API server implementing TRQP endpoints for recognition and authorisation queries
- **`didcomm-server`**: Secure, encrypted messaging interface using DIDComm protocol for CRUD admin operations
- **`app`**: Core domain logic and storage abstractions
- **Storage backends**:
  - CSV file storage
  - AWS DynamoDB

## Getting Started

### Requirements

- **Rust**: 1.88.0 or higher
- **Edition**: 2024
- **Cargo**: Latest version bundled with Rust

### Installation

Install rust or validate that it is installed.

```bash
rustc --version
cargo --version
```

## Usage

### Run locally

Clone env:

```bash
cp .env.example .env
```

Run http-server:

```bash
RUST_LOG=info cargo run --bin http-server
```

Run didcomm-server:

```bash
RUST_LOG=info cargo run --bin didcomm-server
```

Note: run from root of repo.

Query data that is stored in `./sample-data/data.csv`

```bash
curl --location 'http://localhost:3232/recognition' \
--header 'Content-Type: application/json' \
--data '{
    "authority_id": "did:example:authority1",
    "entity_id": "did:example:entity1",
    "action": "action1",
    "resource" : "resource1"
}'
```

```bash
curl --location 'http://localhost:3232/authorization' \
--header 'Content-Type: application/json' \
--data '{
    "authority_id": "did:example:authority1",
    "entity_id": "did:example:entity1",
    "action": "action1",
    "resource" : "resource1"
}'
```

Test with defined and non-defined ids.  
Add more records to `./sample-data/data.csv` (context is base64 encoded VALID JSON).

### Run in docker

#### docker compose

Clone env:

```bash
cp .env.example .env
```

Review env vars in ./docker-compose.yaml and run:

```bash
docker compose up --build
```

In that scenario, sample-data folder is linked as an volume for container, data.csv changes is synced by the container.

## Testing

This project includes comprehensive unit and integration tests with support for multiple storage backends.

For detailed testing instructions, see [TESTING](testing/README.md).

## Contributing

Want to contribute?

Head over to our [CONTRIBUTING](CONTRIBUTING.md) guidelines.

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
