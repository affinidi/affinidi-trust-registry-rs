# Trust Registry Setup Command Reference

This document is the reference for the `setup-trust-registry` command. It matches `setup-trust-registry --help`; when the two disagree, the help text is right and this file is a bug.

For provisioning the registry's identity through a VTA instead (where the VTA keeps the DID's update keys), see [VTA_SETUP.md](./VTA_SETUP.md) and `trust-registry setup`.

<!-- omit from toc -->
## Table of Contents

- [Command Overview](#command-overview)
- [Basic Usage](#basic-usage)
- [Identity Modes](#identity-modes)
- [Re-running Setup](#re-running-setup)
- [Command Options](#command-options)
  - [DIDComm Mediator Configuration](#didcomm-mediator-configuration)
  - [New DID](#new-did)
  - [Profile Location](#profile-location)
  - [Existing DID](#existing-did)
  - [Storage Backend Configuration](#storage-backend-configuration)
  - [Admin Configuration](#admin-configuration)
  - [Test Identities](#test-identities)
  - [Additional Configuration](#additional-configuration)
- [did:webvh Update Keys](#didwebvh-update-keys)
- [Common Usage Examples](#common-usage-examples)
  - [1. Quick Setup (No DIDComm)](#1-quick-setup-no-didcomm)
  - [2. Setup with DIDComm Enabled](#2-setup-with-didcomm-enabled)
  - [3. Setup with Existing DID and Secrets](#3-setup-with-existing-did-and-secrets)
  - [4. Setup with DynamoDB Storage](#4-setup-with-dynamodb-storage)
  - [5. Setup with Redis Storage](#5-setup-with-redis-storage)
  - [6. Setup with Custom Admin DIDs](#6-setup-with-custom-admin-dids)
  - [7. Setup with did:web, did:webvh or did:scid](#7-setup-with-didweb-didwebvh-or-didscid)
  - [8. Setup with Existing Profile](#8-setup-with-existing-profile)
  - [9. CI Pipeline](#9-ci-pipeline)
- [Environment Variables Written](#environment-variables-written)
- [Files Written](#files-written)
- [Additional Resources](#additional-resources)

## Command Overview

`setup-trust-registry` writes the Trust Registry's `.env` (storage backend, audit log format, transports) and, with `--mediator-did`, gives the registry a DIDComm identity. It edits only the `.env` lines it sets: comments, ordering and every other variable are kept, and the file is replaced atomically and is readable by its owner only (0600). It never prints private keys.

It exits non-zero on any failure, including a failed mediator call or secret-store write.

## Basic Usage

```bash
cargo run --bin setup-trust-registry --features="dev-tools" -- [OPTIONS]
```

## Identity Modes

Without `--mediator-did`, DIDComm is disabled: the command writes `ENABLE_DIDCOMM=false` and the registry serves REST only. The DIDComm options (`--did-method`, `--tr-did`, `--profile`, `--admin-dids`, `--operator-dids`, `--acl-mode`, `--with-test-identities`) are refused without it.

With `--mediator-did`, it writes `ENABLE_DIDCOMM=true` and `MEDIATOR_DID`, and needs exactly one of three identity modes:

| Mode | Options | What happens |
|------|---------|--------------|
| New DID | `--did-method <peer\|web\|webvh\|scid>` (optionally `--profile <URI>` for where it is to live) | Generates a DID with an Ed25519 signing key (`#key-1`) and an X25519 key-agreement key (`#key-2`). |
| Existing DID | `--tr-did <DID> --tr-did-secret-file <PATH>` | Uses the given DID and secrets. Both options are required together. |
| Existing profile | `--profile <URI>` without `--did-method` | Loads the profile from the location, checks it parses and that its keys can be published, and points `PROFILE_CONFIG` at it. No key is generated. |

`--did-method` has no default: `--mediator-did` alone is an error that lists the three modes.

## Re-running Setup

Running the command again is safe. It refuses, before changing anything, when the run would:

- replace a non-empty `PROFILE_CONFIG`, `MEDIATOR_DID`, `ADMIN_DIDS`, `ACL_MODE` or `ADMIN_AUTHORITIES` already in `.env` with a different value (or move `PROFILE_CONFIG` out of `.env` into a secret store);
- set `ENABLE_DIDCOMM=false` (no `--mediator-did`) over a `.env` that configures a DIDComm identity;
- replace a profile bundle already in the configured secret store (`TR_SECRETS_*`);
- replace `did.json`, `did.jsonl`, `did-update-keys.json` or the profile file in the working directory.

`--force` replaces them, after backing each one up owner-only: `.env` to `.env.backup-<UTC timestamp>`, files to `<name>.backup-<UTC timestamp>`, and the secret-store bundle to `./secret-store-profile.backup-<UTC timestamp>.json`.

The command never writes an empty value, and leaves out of `.env` any identity variable a run does not set (so no `ADMIN_DIDS=` line, which the registry would read as one empty DID). All checks, identity generation and mediator calls happen before the first file is written.

## Command Options

### DIDComm Mediator Configuration

#### `--mediator-did`, `-d`

Mediator DID the Trust Registry connects through. Enables DIDComm and requires one of the [identity modes](#identity-modes).

**Expected Value:** `did:web:mediator.goodcompany.com` or `did:peer:2.Vz6Mk...`

The mediator's service endpoint is resolved from its DID document.

### New DID

#### `--did-method`, `-m`

Generate a new Trust Registry DID with this method.

**Expected Values:** `peer` | `web` | `webvh` | `scid`
**Default:** none

- `peer`: a did:peer routed through the mediator. Nothing to host.
- `web`: a did:web; writes `did.json` to host.
- `webvh`: a did:webvh with key pre-rotation; writes `did.json`, the log `did.jsonl`, and the [update keys](#didwebvh-update-keys).
- `scid`: writes a did:webvh log and presents its `did:scid:vh:1` DID, which the same log verifies but which does not change if the log moves.

#### `--didweb-url`, `-w`

URL the DID is derived from and its document hosted under. Give the base URL, not the path of `did.json` / `did.jsonl`.

**Expected Value:** `https://example.com` or `https://example.com/tr`
**Required when:** `--did-method` is `web`, `webvh` or `scid`

#### `--no-scid-alias`

Do not list the `did:scid:vh:1` form of a new did:webvh in its `alsoKnownAs`. Listed by default, so peers can recognise the Trust Registry under either form. Not allowed with `--did-method scid`, whose identity is that form.

The DID document written for `web`, `webvh` and `scid` comes from the same builder the registry uses at runtime: one `Multikey` verification method per key under the key's own id, the Ed25519 key under `authentication` and `assertionMethod`, the X25519 key under `keyAgreement`, and the service entries the registry's `ENABLE_*` flags and `TR_PUBLIC_URL` call for (read from the environment of the setup run; DIDComm is always on here).

### Profile Location

#### `--profile`, `-p`

Profile location, as a `PROFILE_CONFIG` loader URI that names where the profile is.

**Expected Values:**
- File system: `'file:///path/to/profile.json'`
- AWS Secrets Manager: `'aws_secrets://my-secret-name'`
- AWS Parameter Store: `'aws_parameter_store://my-parameter-name'`

An inline JSON value or `string://<JSON>` is refused, without repeating it: it is the profile itself, private keys included, on the command line where shell history and the process list keep it. Save the profile to an owner-only file and pass its `file://` location, or pass the DID and keys with `--tr-did` and `--tr-did-secret-file`. (The registry's `PROFILE_CONFIG` still accepts the inline forms; only this option refuses them.)

**With `--did-method`:** where the generated profile is to live. A `file://` location is written; any other location gets the profile in `./trust-registry-profile.json` for you to store there and then delete. Either file is created readable by its owner only and is never overwritten (without `--force`). `.env` points at the location. Without `--profile`, the profile is written inline to `.env`.

**Without `--did-method`:** existing-profile mode, see [Identity Modes](#identity-modes).

When a secret-store backend is configured (`TR_SECRETS_*`, or `TR_SECRETS_BACKEND`), the profile is written to the backend and left out of `.env`; if that write fails, the command stops with an error. `TR_SECRETS_SEED` selects a read-only store that must already hold the hex-encoded bundle, so the command refuses to provision into it.

### Existing DID

#### `--tr-did`, `-r`

Existing Trust Registry DID. Requires `--tr-did-secret-file`.

**Expected Value:** `did:peer:2.Vz6Mk...`

#### `--tr-did-secret-file`, `-e`

File holding the existing DID's secrets as a JSON array. Requires `--tr-did`. `-` reads the secrets from standard input. The secrets are read from a file so they stay out of shell history and the process list.

**Expected Value:** a path, e.g. `./tr-secrets.json`, whose content is `[{"id":"<DID>#key-1", "type":"JsonWebKey2020", "privateKeyJwk":{...}}, ...]`

### Storage Backend Configuration

#### `--storage-backend`, `-s`

Storage backend for trust records. Written as `TR_STORAGE_BACKEND`.

**Expected Values:** `csv` | `ddb` | `redis` | `fjall`
**Default:** `csv`

#### `--file-storage-path`, `-f`

Path to the CSV file of trust records (csv backend). Written as `FILE_STORAGE_PATH`.

**Default:** `./sample-data/data.csv`

#### `--ddb-table-name`, `-t`

DynamoDB table name. Written as `DDB_TABLE_NAME`.

**Expected Value:** `trust-registry-records`
**Required when:** `--storage-backend` is `ddb` (no default)

#### `--redis-url`, `-u`

Redis URL (redis backend). Written as `REDIS_URL`; credentials in it are redacted in the command's output.

**Expected Value:** `redis://localhost:6379` or `redis://username:password@host:port/db`
**Default:** `redis://localhost:6379`

#### `--fjall-path`

Directory of the fjall database (fjall backend). Written as `TR_FJALL_PATH`.

**Default:** `./trust_records.fjall`

### Admin Configuration

#### `--admin-dids`, `-a`

Admin DIDs that can manage Trust Registry records, comma-separated. Written as `ADMIN_DIDS`; left out of `.env` when not given.

**Expected Value:** `did:peer:2.Vz6Mk...,did:peer:2.Vz6Mn...`

#### `--operator-dids`

Admin DIDs (each also in `--admin-dids`, comma-separated) that may act on the registry itself: rotate the registry's DID and enable or disable capabilities that have no authority. The command writes `ADMIN_AUTHORITIES` mapping each of them to the registry's DID. Without such an entry no admin can rotate the registry's DID.

**Expected Value:** `did:peer:2.Vz6Mk...`

#### `--acl-mode`, `-x`

Mediator ACL mode for the registry's DID. Written as `ACL_MODE`; when not given, `.env` keeps what it has (the registry's default is `ExplicitDeny`).

**Expected Values:**
- `ExplicitDeny` - public mode: anyone may send to the registry through its mediator.
- `ExplicitAllow` - private mode: only DIDs on the mediator's allow list for the registry may.

### Test Identities

#### `--with-test-identities`

Also create a test Trust Registry DID and a test client DID, open mediator accounts for both (making each public, `ExplicitDeny`, if the mediator created it private), and write them with their private keys to `./.env.test` (from `testing/.env.test.example`). For development and CI only; a production setup never needs it. A failed mediator call stops the command with an error, before `.env` is written.

#### `--test-in-pipeline`, `-l`

Build `./.env.test` for the CI pipeline from the tracked `.env.pipeline` template instead (the template is not modified). Implies `--with-test-identities`. A switch: `--test-in-pipeline` and `--test-in-pipeline=true` are the same.

### Additional Configuration

#### `--audit-log-format`, `-o`

Audit log output format. Written as `AUDIT_LOG_FORMAT`.

**Expected Values:** `json` | `text`
**Default:** `json`

#### `--non-interactive`

Run without prompts (CI / container provisioning). Skips the "press any key after hosting the DID document" pause for `web`, `webvh` and `scid`; host the document before starting the registry.

#### `--force`

Replace what [re-running](#re-running-setup) would otherwise refuse to, backing each item up first.

## did:webvh Update Keys

A did:webvh (`--did-method webvh` or `scid`) can only be changed by a new log entry signed with a key the previous entry authorised. The command creates the first entry with key pre-rotation and writes both keys to `./did-update-keys.json`, owner-only:

- `updateKey`: signed entry 1 and is listed in its `updateKeys`.
- `nextUpdateKey`: its hash is committed in entry 1's `nextKeyHashes`. Entry 2 must list this key in `updateKeys`, be signed by it, and commit the hash of a new next key.

Without this file the DID can never be updated: no key rotation after a compromise, no new service endpoints, no deactivation. Keep it offline and backed up, not on the registry host. To produce the next entry, load `did.jsonl` and these keys with [didwebvh-rs](https://crates.io/crates/didwebvh-rs) (or any did:webvh 1.0 implementation), and publish the extended `did.jsonl`.

If you would rather not hold these keys yourself, provision the registry through a VTA (`trust-registry setup`, see [VTA_SETUP.md](./VTA_SETUP.md)), which keeps them.

## Common Usage Examples

### 1. Quick Setup (No DIDComm)

```bash
cargo run --bin setup-trust-registry --features="dev-tools"
```

- Uses CSV storage with the default path.
- Writes `ENABLE_DIDCOMM=false`; the registry serves REST only.
- Creates or updates `.env` (from `.env.example` on a first run).

Start the registry with `RUST_LOG=info cargo run --bin trust-registry`, or with Docker (`docker compose up --build`) from the same `.env`.

### 2. Setup with DIDComm Enabled

```bash
cargo run --bin setup-trust-registry --features="dev-tools" -- \
  --mediator-did=did:web:mediator.goodcompany.com \
  --did-method=peer
```

- Generates the Trust Registry's DID using `did:peer`.
- Writes `ENABLE_DIDCOMM=true`, `MEDIATOR_DID` and `PROFILE_CONFIG` to `.env`.

Add `--with-test-identities` to also create test DIDs on the mediator and `.env.test` for the test suite.

### 3. Setup with Existing DID and Secrets

```bash
cargo run --bin setup-trust-registry --features="dev-tools" -- \
  --tr-did=did:peer:2.Vz6Mk... \
  --tr-did-secret-file=./tr-secrets.json \
  --mediator-did=did:web:mediator.goodcompany.com \
  --admin-dids=did:peer:2.Admin...
```

- Uses the provided DID and secrets (checked to be publishable) instead of generating new ones.
- Writes them to `.env` as `PROFILE_CONFIG` (or to the secret store).

### 4. Setup with DynamoDB Storage

```bash
cargo run --bin setup-trust-registry --features="dev-tools" -- \
  --storage-backend=ddb \
  --ddb-table-name=trust-registry-prod
```

### 5. Setup with Redis Storage

```bash
cargo run --bin setup-trust-registry --features="dev-tools" -- \
  --storage-backend=redis \
  --redis-url=redis://localhost:6379
```

### 6. Setup with Custom Admin DIDs

```bash
cargo run --bin setup-trust-registry --features="dev-tools" -- \
  --mediator-did=did:web:mediator.goodcompany.com \
  --did-method=peer \
  --admin-dids=did:peer:2.Admin1...,did:peer:2.Admin2... \
  --operator-dids=did:peer:2.Admin1...
```

### 7. Setup with did:web, did:webvh or did:scid

```bash
cargo run --bin setup-trust-registry --features="dev-tools" -- \
  --did-method=webvh \
  --didweb-url=https://example.com \
  --mediator-did=did:web:mediator.goodcompany.com \
  --non-interactive
```

- Writes `did.json` (and for `webvh` / `scid`, `did.jsonl` and `did-update-keys.json`) to the working directory. Host the document under the URL before starting the registry.
- Use `--did-method=web` for a did:web, or `--did-method=scid` for a did:scid presented from the did:webvh log.
- Set `TR_PUBLIC_URL` (and any `ENABLE_*` flags) in the environment of the setup run for the document to advertise them.

### 8. Setup with Existing Profile

```bash
cargo run --bin setup-trust-registry --features="dev-tools" -- \
  --profile='file:///path/to/profile.json' \
  --mediator-did=did:web:mediator.goodcompany.com
```

- Loads and validates the profile; generates no key.
- Points `PROFILE_CONFIG` at the location.

### 9. CI Pipeline

```bash
cargo run --bin setup-trust-registry --features dev-tools -p trust-registry -- \
  --mediator-did="$MEDIATOR_DID" \
  --did-method=peer \
  --with-test-identities \
  --test-in-pipeline \
  --non-interactive \
  --file-storage-path=trust-registry/tests/tmp/data.csv
```

## Environment Variables Written

The command writes the following variables to `.env` (starting from `.env.example` when there is no `.env` yet), editing only these lines. It never writes an empty value, and a variable it does not write keeps whatever `.env` has. Every variable the server reads, with its default, is listed in the README's [Environment Variables](./README.md#environment-variables) section.

| Variable | Written | Value |
|----------|---------|-------|
| `ENABLE_DIDCOMM` | always | `true` when `--mediator-did` is given, else `false`. |
| `TR_STORAGE_BACKEND` | always | `--storage-backend`: `csv`, `ddb`, `redis` or `fjall` (the server also accepts `dynamodb` for `ddb`). |
| `FILE_STORAGE_PATH` | `csv` | `--file-storage-path`. |
| `DDB_TABLE_NAME` | `ddb` | `--ddb-table-name`. |
| `REDIS_URL` | `redis` | `--redis-url`. Format: `redis://host:port` or `redis://username:password@host:port/db`. |
| `TR_FJALL_PATH` | `fjall` | `--fjall-path`. |
| `AUDIT_LOG_FORMAT` | always | `--audit-log-format`: `json` or `text`. |
| `MEDIATOR_DID` | `--mediator-did` | The mediator DID. |
| `PROFILE_CONFIG` | `--mediator-did`, unless a secret store is configured | The registry's DID and keys inline, or the `--profile` location. With a `TR_SECRETS_*` backend selected the profile is written there instead and `PROFILE_CONFIG` is left out. `TR_SECRETS_SEED` is read-only, so selecting it stops the command before anything is written. |
| `ADMIN_DIDS` | `--admin-dids` | Comma-separated admin DIDs. |
| `ADMIN_AUTHORITIES` | `--operator-dids` | JSON object: admin DID → extra authority DIDs it may write records under (default: its own DID only). |
| `ACL_MODE` | `--acl-mode` | `ExplicitDeny` (public) or `ExplicitAllow` (private). |

The command itself reads `TR_PUBLIC_URL`, `ENABLE_REST` and `ENABLE_TSP` (to build the DID document it generates, as the server would; DIDComm is always on for that document) and the `TR_SECRETS_*` variables (to choose the secret store it provisions).

## Files Written

| File | When | Permissions |
|------|------|-------------|
| `.env` | Always (from `.env.example` on a first run) | 0600 |
| `.env.test` | `--with-test-identities` / `--test-in-pipeline` | 0600 |
| `did.json` | `--did-method` `web`, `webvh`, `scid` | default (a public document) |
| `did.jsonl` | `--did-method` `webvh`, `scid` | default (a public document) |
| `did-update-keys.json` | `--did-method` `webvh`, `scid` | 0600 |
| profile file | `--did-method` with `--profile` | 0600 |
| `*.backup-<timestamp>` | `--force` | 0600 |

## Additional Resources

- [README.md](./README.md) - General Trust Registry documentation
- [VTA_SETUP.md](./VTA_SETUP.md) - Provisioning the registry through a VTA
- [DIDCOMM_PROTOCOLS.md](./DIDCOMM_PROTOCOLS.md) - DIDComm protocol specifications
- [Environment Variables](./README.md#environment-variables) - Environment variable reference
