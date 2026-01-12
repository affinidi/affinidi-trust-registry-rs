# Trust Registry Setup Command Reference

This document provides a comprehensive reference for the `setup-trust-registry` command and its options.

<!-- omit from toc -->
## Table of Contents

- [Command Overview](#command-overview)
- [Basic Usage](#basic-usage)
- [Command Options](#command-options)
  - [DIDComm Mediator Configuration](#didcomm-mediator-configuration)
  - [DID Method Configuration](#did-method-configuration)
  - [Profile Configuration](#profile-configuration)
  - [Storage Backend Configuration](#storage-backend-configuration)
  - [Admin Configuration](#admin-configuration)
  - [Existing DID Configuration](#existing-did-configuration)
  - [Additional Configuration](#additional-configuration)
- [Common Usage Examples](#common-usage-examples)
  - [1. Quick Setup (No DIDComm)](#1-quick-setup-no-didcomm)
  - [2. Setup with DIDComm Enabled](#2-setup-with-didcomm-enabled)
  - [3. Setup with Existing DID and Secrets](#3-setup-with-existing-did-and-secrets)
  - [4. Setup with DynamoDB Storage](#4-setup-with-dynamodb-storage)
  - [5. Setup with Redis Storage](#5-setup-with-redis-storage)
  - [6. Setup with Custom Admin DIDs](#6-setup-with-custom-admin-dids)
  - [7. Setup with did:web Method](#7-setup-with-didweb-method)
  - [8. Setup with Existing Profile](#8-setup-with-existing-profile)
- [Environment Variables Configured](#environment-variables-configured)
- [Test Environment Files](#test-environment-files)
- [Additional Resources](#additional-resources)


## Command Overview

The `setup-trust-registry` command is a configuration tool that helps you set up the Trust Registry environment. It generates necessary DIDs, and configures environment variables.

## Basic Usage

```bash
cargo run --bin setup-trust-registry --features="dev-tools" -- [OPTIONS]
```

## Command Options

### DIDComm Mediator Configuration

#### `--mediator-did`, `-d`

Mediator DID to connect the Trust Registry.

**Expected Value:** `did:web:mediator.goodcompany.com` or `did:peer:2.Vz6Mk...`

**Note:** When provided, this enables DIDComm functionality. The mediator service endpoint is resolved from the DID document.

### DID Method Configuration

#### `--did-method`, `-m`

DID method to use for Trust Registry. When specified, generates a new DID using the selected method.

**Expected Values:** `peer` | `web` | `webvh`  
**Default:** `peer`

#### `--didweb-url`, `-w`

URL to host the DID document for `did:web` or `did:webvh` methods.

**Expected Value:** `https://example.com`  
**Required when:** `--did-method` is `web` or `webvh`

### Profile Configuration

#### `--profile`, `-p`

Profile configuration location using URI schemes. This option serves dual purposes:
- When `--did-method` is used: Specifies where to save the generated profile
- When `--did-method` is not used: Specifies where to load an existing profile

**Expected Values:**
- Direct value: `'{"alias":"Trust Registry","did":"did:peer:2.VzDna...","secrets":[...]}'`
- String protocol: `'string://{"alias":"Trust Registry","did":"did:peer:2.VzDna...","secrets":[...]}'`
- File system: `'file:///path/to/config.json'`
- AWS Secrets Manager: `'aws_secrets://my-secret-name'`
- AWS Parameter Store: `'aws_parameter_store:///my-parameter-name'`

**Default:** Configures the Trust Registry profile in the `.env` file as direct value.

### Storage Backend Configuration

#### `--storage-backend`, `-s`

Storage backend for trust records.

**Expected Values:** `csv` | `ddb` | `redis`  
**Default:** `csv`

#### `--file-storage-path`, `-f`

Path to CSV file for storing trust records.

**Expected Value:** `./sample-data/data.csv`  
**Default:** `./sample-data/data.csv`  
**Required when:** `--storage-backend` is `csv`

#### `--ddb-table-name`, `-t`

DynamoDB table name for storing trust records.

**Expected Value:** `trust-registry-records`  
**Default:** `test`  
**Required when:** `--storage-backend` is `ddb`

#### `--redis-url`, `-u`

Redis connection URL for storing trust records.

**Expected Value:** `redis://localhost:6379` or `redis://username:password@host:port/db`  
**Default:** `redis://localhost:6379`  
**Required when:** `--storage-backend` is `redis`

### Admin Configuration

#### `--admin-dids`, `-a`

Admin DIDs that can manage Trust Registry records. Multiple DIDs should be comma-separated.

**Expected Value:** `did:peer:2.Vz6Mk...,did:peer:2.Vz6Mn...`

### Existing DID Configuration

#### `--tr-did`, `-r`

Trust Registry DID. It is used to set an existing DID instead of generating a new one.

**Expected Value:** `did:peer:2.Vz6Mk...`

#### `--tr-did-secret`, `-e`

Trust Registry DID secret. It is used with `--tr-did` to set existing DID credentials.

**Expected Value:** `'[{"id":..., "privateKeyJwk":{...}}]'`

### Additional Configuration

#### `--test-in-pipeline`, `-l`

Enable test configuration for CI/CD pipeline environments.

**Expected Value:** `true` | `false`  
**Default:** `false`

#### `--audit-log-format`, `-o`

Trust Registry audit log output format.

**Expected Value:** `json` | `text`  
**Default:** `json`

#### `--only-admin-operations`, `-x`

Enable only admin operations via DIDComm. When enabled, the Trust Registry will only accept admin operations and skip general DIDComm message handling.

**Expected Value:** `true` | `false`  
**Default:** `false`

## Common Usage Examples

### 1. Quick Setup (No DIDComm)

Set up Trust Registry with default settings and no DIDComm integration:

```bash
cargo run --bin setup-trust-registry --features="dev-tools"
```

**The script does the following:**
- Uses CSV storage with default path.
- Generates environment variables.
- DIDComm is disabled.
- Creates `.env` file.

### 2. Setup with DIDComm Enabled

Set up Trust Registry with DIDComm mediator integration:

```bash
cargo run --bin setup-trust-registry --features="dev-tools" -- \
  --mediator-did=did:web:mediator.goodcompany.com
```

**The script does the following:**
- Generates Trust Registry DID using `did:peer`.
- Generates test user DIDs (Trust Registry and Admin).
- Configures ACLs on the mediator.
- Sets up environment variables for DIDComm.
- Creates `.env` file.

### 3. Setup with Existing DID and Secrets

Set up Trust Registry using an existing DID and its secrets instead of generating new ones:

```bash
cargo run --bin setup-trust-registry --features="dev-tools" -- \
  --tr-did=did:peer:2.Vz6Mk... \
  --tr-did-secret='[{"id":"did:peer:2.Vz6Mk...#key-1","privateKeyJwk":{"crv":"P-256","kty":"EC","x":"...","y":"..."},"type":"JsonWebKey2020"}]' \
  --mediator-did=did:web:mediator.goodcompany.com \
  --admin-dids=did:peer:2.Admin...
```

**The script does the following:**
- Uses the provided Trust Registry DID instead of generating a new one.
- Configures the provided DID secrets for authentication.
- Sets up DIDComm with the specified mediator.
- Configures ACLs on the mediator for the existing DID.
- Creates `.env` file with the existing DID configuration.

### 4. Setup with DynamoDB Storage

Set up Trust Registry using DynamoDB as the storage backend:

```bash
cargo run --bin setup-trust-registry --features="dev-tools" -- \
  --storage-backend=ddb \
  --ddb-table-name=trust-registry-prod
```

### 5. Setup with Redis Storage

Set up Trust Registry using Redis as the storage backend:

```bash
cargo run --bin setup-trust-registry --features="dev-tools" -- \
  --storage-backend=redis \
  --redis-url=redis://localhost:6379
```

### 6. Setup with Custom Admin DIDs

Set up Trust Registry with specific admin DIDs:

```bash
cargo run --bin setup-trust-registry --features="dev-tools" -- \
  --mediator-did=did:web:mediator.goodcompany.com \
  --admin-dids=did:peer:2.Admin1...,did:peer:2.Admin2...
```

### 7. Setup with did:web Method

Set up Trust Registry using did:web method:

```bash
cargo run --bin setup-trust-registry --features="dev-tools" -- \
  --did-method=web \
  --didweb-url=https://example.com/.well-known/did.json \
  --mediator-did=did:web:mediator.goodcompany.com
```

### 8. Setup with Existing Profile

Load an existing profile configuration from a file:

```bash
cargo run --bin setup-trust-registry --features="dev-tools" -- \
  --profile='file:///path/to/profile.json' \
  --mediator-did=did:web:mediator.goodcompany.com
```

## Environment Variables Configured

The setup command generates a `.env` file with the following variables:

| Variable | Description |
|----------|-------------|
| `TR_STORAGE_BACKEND` | Storage backend type (csv, ddb, redis). |
| `FILE_STORAGE_PATH` | Path to CSV file (when using csv backend). |
| `DDB_TABLE_NAME` | DynamoDB table name (when using ddb backend). |
| `REDIS_URL`  | Redis connection URL when using Redis as the storage backend. Format: `redis://host:port` or `redis://username:password@host:port/db`. |
| `CORS_ALLOWED_ORIGINS` | Allowed CORS origins. |
| `AUDIT_LOG_FORMAT` | Audit log output format. |
| `MEDIATOR_DID` | DIDComm mediator DID when DIDComm enabled. |
| `ADMIN_DIDS` | Authorized admin DIDs when DIDComm enabled. |
| `PROFILE_CONFIG` | Trust Registry profile configuration when DIDComm enabled. |
| `ACL_MODE` | ACL Mode for Trust Registry when DIDComm is enabled. ExplicitDeny - public mode, ExplicitAllow - private mode |

## Test Environment Files

For testing environments, the setup command also generates:
- `.env.test` - Test environment configuration
- `.env.pipeline` - CI/CD pipeline configuration

These files contain the same structure as `.env` but with test-specific values.

## Additional Resources

- [README.md](./README.md) - General Trust Registry documentation
- [DIDCOMM_PROTOCOLS.md](./DIDCOMM_PROTOCOLS.md) - DIDComm protocol specifications
- [Environment Variables](./README.md#environment-variables) - Detailed environment variable documentation
