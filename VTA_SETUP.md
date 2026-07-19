# Trust Registry + VTA — Setup Guide

This guide walks through configuring the Trust Registry to obtain its identity
(DID + keys) from a **Verifiable Trust Agent (VTA)** instead of holding private
keys inline via `PROFILE_CONFIG`.

## How it fits together

In VTA mode the Trust Registry holds **no private keys of its own**. At startup
it authenticates to a VTA, pulls its DID + keys for a named **context**, and uses
them to connect to the DIDComm mediator. Provisioning that context and minting
the registry's credentials is done with the [`pnm`](https://github.com/) CLI
("Personal Network Manager" — the single-VTA admin client).

There are two roles. They can be the same person:

| Role | Does | Tool |
|---|---|---|
| **VTA operator** | Provisions the context, creates the registry's `did:webvh`, mints a sealed credential bundle | `pnm` |
| **TR operator** | Generates a recipient request, opens the sealed bundle, configures the registry | `pnm` + TR `.env` |

The transfer uses **sealed HPKE bundles**: the TR operator generates a keypair
locally, the VTA operator seals the credential to that public key, and only the
TR operator can open it. Private keys never cross the wire.

## Prerequisites

- A running VTA service reachable over HTTPS.
- The `pnm` CLI installed (`~/.cargo/bin/pnm`).
- A WebVH DID-hosting server the VTA can create the registry's `did:webvh` on.
- The Trust Registry built **with the `vta` feature** (it is not in the default
  build or the Docker image).

Point `pnm` at your VTA (per command with `--url`, or persist it in the
environment):

```bash
export VTA_URL=https://vta.example.com
pnm health          # sanity check the VTA is reachable
```

---

## Part A — VTA side (PNM commands)

### Step 1 — TR operator: generate a recipient request

Run this **on the machine that will run the Trust Registry** (it writes a secret
to `~/.config/pnm/bootstrap-secrets/`):

```bash
pnm bootstrap request \
  --out tr-request.json \
  --label "trust-registry"
```

`tr-request.json` contains only a public key + nonce. Send it to the VTA
operator (out of band). Keep the local secret file — you need it in Step 3.

### Step 2 — VTA operator: provision the context + registry DID

This creates the context, mints the registry's admin credential, creates its
`did:webvh`, and seals everything to the request from Step 1:

```bash
pnm contexts provision \
  --id trust-registry \
  --name "Trust Registry" \
  --server https://webvh.example.com \
  --mediator-service \
  --recipient tr-request.json
```

- `--id trust-registry` → this slug becomes **`TR_VTA_CONTEXT_ID`**. Remember it.
- `--server` creates the registry's `did:webvh` on that hosting server. Use
  `--did-url` instead if self-hosting.
- `--mediator-service` adds a mediator service endpoint to the DID — include it
  since the registry connects via DIDComm.
- Optional: `--pre-rotation <N>` to pre-generate rotation keys, `--portable`
  (default on) for a portable DID.

The command prints an **armored sealed bundle**
(`-----BEGIN VTA SEALED BUNDLE-----`) and a **SHA-256 digest**. Save the bundle
to a file (e.g. `tr-sealed.txt`) and send both the file **and the digest**
(digest out-of-band) back to the TR operator.

> **Single-operator note:** if you run both roles on one machine, Steps 1–3
> happen locally back-to-back — same commands, no transfer.

### Step 3 — TR operator: open the sealed bundle

```bash
pnm bootstrap open \
  --bundle tr-sealed.txt \
  --expect-digest <sha256-hex-from-step-2> \
  --out /etc/trust-registry/vta-credential.json
```

The digest check is **mandatory** by default (there is no silent
trust-on-first-use; `--no-verify-digest` exists for testing only).

`--out` writes the **credential bundle** as JSON, created `0600`:

```json
{
  "did": "did:key:z6Mk...",
  "privateKeyMultibase": "z...",
  "vtaDid": "did:webvh:...:vta.example.com:...",
  "vtaUrl": "https://vta.example.com"
}
```

**That file is `TR_VTA_CREDENTIAL`.**

> **Do not omit `--out`.** Without it, `bootstrap open` only *inspects* the
> bundle: it prints a payload summary and writes nothing. It never prints
> `privateKeyMultibase`, so there is no way to recover the credential from the
> terminal output afterwards.
>
> Opening also **consumes the single-use bootstrap secret** at
> `~/.config/pnm/bootstrap-secrets/<bundle-id>.key`. A second `open` on the same
> file fails — recovering from a missed `--out` means starting over from Step 1
> with a fresh `pnm bootstrap request` *and* a fresh `pnm contexts provision`.

`--out` requires `pnm` built from a revision that carries it. On an older
build the flag is rejected by the argument parser; there is no file-writing
path in `pnm` before it, so upgrade rather than working around it.

---

## Part B — Configure the Trust Registry

### Step 4 — Build with the `vta` feature

```bash
# add a secrets backend feature (e.g. secrets-aws) if you want the offline
# cache stored in a cloud backend rather than on local disk
cargo build --release --bin trust-registry --features vta
```

### Step 5 — Set the environment (`.env`)

VTA startup only runs inside the DIDComm path, so the mediator vars are required
too. See [`.env.vta.example`](.env.vta.example) for a fill-in-the-blanks
template.

```dotenv
# --- DIDComm (required for VTA) ---
ENABLE_DIDCOMM=true                 # default; VTA is skipped entirely if not "true"
MEDIATOR_DID=did:web:mediator.example

# --- VTA identity ---
TR_VTA_CREDENTIAL=file:///etc/trust-registry/vta-credential.json
TR_VTA_CONTEXT_ID=trust-registry    # the --id slug from Step 2
# TR_VTA_URL=https://vta.example.com  # optional; overrides vtaUrl in the credential
# TR_ALIAS=Trust Registry             # optional; default "Trust Registry"

# --- offline cache location (optional; see Step 6) ---
# TR_SECRETS_AWS_SECRET_NAME=trust-registry/vta-cache
# TR_SECRETS_AWS_REGION=ap-southeast-1

# --- server ---
LISTEN_ADDRESS=0.0.0.0:3232
RUST_LOG=info
```

`TR_VTA_CREDENTIAL` goes through the URI loader, so instead of `file://` you can
use `aws_secrets://<name>`, `aws_parameter_store://<name>`, or inline the JSON as
`string://{...}`.

> **Do not set `PROFILE_CONFIG`** — VTA takes precedence and it will not be read.

### Step 6 — Offline cache (recommended)

If the VTA is unreachable at boot, the registry falls back to a cached copy of
the last bundle, stored in whichever `TR_SECRETS_*` backend you configure
(default: local dir `./.trust-registry`; build the matching `secrets-*` feature
for cloud backends).

> **Caveat:** if the VTA is down **and** the cache is empty, startup fails —
> there is no fallback to `PROFILE_CONFIG`.

### Step 7 — Run and verify

```bash
RUST_LOG=info ./target/release/trust-registry

# in another shell:
curl http://localhost:3232/health                 # -> {"status":"OK"}
curl http://localhost:3232/.well-known/did.json    # should serve the VTA-managed DID
```

On success the logs show the registry fetching its bundle from the VTA and
authenticating to the mediator.

---

## Optional — DID key rotation

Building with `vta` also enables the `registry/did/rotate/0.1` admin Trust Task.
Rotation requires the registry DID to be a `did:webvh` (which the
`contexts provision --server` flow gives you); pre-rotation keys help. It is
driven as an admin DIDComm task, not a `pnm` command.

---

## Quick command reference

| Purpose | Command |
|---|---|
| Point PNM at a VTA | `export VTA_URL=https://vta.example.com` |
| TR operator: make recipient request | `pnm bootstrap request --out tr-request.json --label trust-registry` |
| VTA operator: provision context + DID | `pnm contexts provision --id <ctx> --name "Trust Registry" --server <webvh> --mediator-service --recipient tr-request.json` |
| TR operator: open sealed bundle | `pnm bootstrap open --bundle tr-sealed.txt --expect-digest <hex> --out <path>` |
| Lighter admin-only credential (no DID) | `pnm contexts bootstrap --id <ctx> --name … --recipient tr-request.json` |
| Re-mint bundle for existing context | `pnm contexts reprovision …` |

**Mapping to TR config:** `--id` slug → `TR_VTA_CONTEXT_ID` · recovered bundle
JSON → `TR_VTA_CREDENTIAL` · `vtaUrl` in the bundle (or `TR_VTA_URL`) → the VTA
endpoint.

## Related docs

- [`README.md`](README.md) — "Identity from a VTA (`vta`)" section and full
  environment-variable reference.
- [`SETUP_COMMAND_REFERENCES.md`](SETUP_COMMAND_REFERENCES.md) — the
  `setup-trust-registry` CLI (non-VTA provisioning).
- [`DIDCOMM_PROTOCOLS.md`](DIDCOMM_PROTOCOLS.md) — DIDComm transport details.
