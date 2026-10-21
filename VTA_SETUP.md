# Trust Registry + VTA — Setup Guide

This guide walks through configuring the Trust Registry to obtain its identity
(DID + keys) from a **Verifiable Trust Agent (VTA)** instead of holding private
keys inline via `PROFILE_CONFIG`.

## How it fits together

In VTA mode the Trust Registry holds **no private keys of its own**. At startup
it authenticates to a VTA, pulls its DID + keys for a named **context**, and uses
them to connect to the DIDComm mediator.

There are three ways to provision that context and the registry's credential:

| Path | Use it when | Driven by |
|---|---|---|
| [**Headless setup**](#headless-setup-automated) | Provisioning is scripted, e.g. a VTA farm's full-stack pipeline. Same two-phase flow as `vtc setup`, `mediator-setup` and `did-hosting-daemon setup` | `trust-registry setup` + one VTA grant |
| [**Part A — `pnm`**](#part-a--vta-side-pnm-commands) | A VTA operator and a TR operator hand off by hand, with a sealed bundle | `pnm` |
| [**Part A — native `vta`**](#part-a-alternative--native-vta-commands-no-pnm) | Everything happens on the VTA host with the daemon stopped, and the DID is self-hosted | offline `vta` |

All three end in the same place: a credential file (`TR_VTA_CREDENTIAL`) and a
context id (`TR_VTA_CONTEXT_ID`), configured as in [Part B](#part-b--configure-the-trust-registry).

For the `pnm` path there are two roles. They can be the same person:

| Role | Does | Tool |
|---|---|---|
| **VTA operator** | Provisions the context, creates the registry's `did:webvh`, mints a sealed credential bundle | `pnm` |
| **TR operator** | Generates a recipient request, opens the sealed bundle, configures the registry | `pnm` + TR `.env` |

The transfer uses **sealed HPKE bundles**: the TR operator generates a keypair
locally, the VTA operator seals the credential to that public key, and only the
TR operator can open it. Private keys never cross the wire.

## Prerequisites

- A running VTA service reachable over HTTPS.
- The `pnm` CLI installed (`~/.cargo/bin/pnm`), for the `pnm` path.
- A WebVH DID-hosting server the VTA can create the registry's `did:webvh` on.
- The Trust Registry built **with the `vta` feature**. It is not in the default
  build; for the Docker image pass it as a build arg:
  `docker build -f trust-registry/Dockerfile --build-arg FEATURES="vta secrets-vault" .`
  (add `tsp` to serve TSP, and the `secrets-*` backend you cache in).

Point `pnm` at your VTA (per command with `--url`, or persist it in the
environment):

```bash
export VTA_URL=https://vta.example.com
pnm health          # sanity check the VTA is reachable
```

---

## Headless setup (automated)

`trust-registry setup` provisions the registry at a VTA without a TTY, in the
same two phases the VTC, the mediator and the did-hosting daemon use. An
automated pipeline can therefore run the registry as one more set of Jobs.

What the VTA does in phase 2, in one round trip:

- mints the registry's `did:webvh` from the built-in **`trust-registry`** DID
  template;
- publishes it to the DID-hosting server you name;
- keeps its keys in the context, where the registry pulls them at every boot;
- rolls the setup key over to a VTA-minted long-term admin, which becomes
  `TR_VTA_CREDENTIAL`.

The DID document advertises exactly the transports you list, built by the same
code the running registry uses, so the two cannot disagree.

**Needs** a VTA built from a revision with the `trust-registry` template
([verifiable-trust-infrastructure#2252](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/2252)),
and the DID-hosting server registered at the VTA
(`vta did-mgmt servers add` / `pnm did-mgmt servers add`).

### H1 — Registry: mint a setup key (no VTA call)

```bash
trust-registry setup --setup-key-out setup-key.json --context trust-registry
```

It writes the key (0600) and prints, on stderr, the setup DID on the line after
`Setup DID (ephemeral):`. The printed `pnm contexts create …` line is the grant
for step H2.

### H2 — VTA: grant the setup key admin in a new context

Offline, with the VTA daemon stopped:

```bash
vta contexts create --id trust-registry --name "Trust Registry" \
  --admin-did <setup DID> --admin-expires 1h --admin-handoff
```

Online, the same flags work with `pnm contexts create`.

- **`--admin-handoff` is required.** It lets the setup DID roll over once to the
  VTA-minted admin; without it phase 2 is refused (VTI-ACL-053), and the marker
  cannot be added to the entry later.
- The context must not already have a DID. To provision again, create a fresh
  context or delete this one.

### H3 — Registry: provision (VTA running)

Write the phase-2 file. A commented copy is in
[`trust-registry/examples/vta-setup.example.toml`](trust-registry/examples/vta-setup.example.toml):

```toml
vta_did         = "did:webvh:…:dids.example.com:vta"
context         = "trust-registry"            # as granted in H2
setup_key_file  = "setup-key.json"            # from H1
credential_out  = "vta-credential.json"       # TR_VTA_CREDENTIAL, written 0600
env_out         = "vta.env"                   # optional
transports      = ["rest", "didcomm"]         # "didcomm" required; "tsp" optional
public_url      = "https://trust-registry.example.com"   # required for "rest"
mediator_did    = "did:webvh:…:dids.example.com:mediator"

[webvh]
server_id = "did-hosting-daemon"              # registered at the VTA
path      = "trust-registry"                  # optional
```

```bash
trust-registry setup --from vta-setup.toml
```

The file is validated before anything reaches the VTA, by the same rules the
registry applies at startup. It refuses to run if `credential_out` already
exists, because provisioning again mints a second DID and admin. On success it
prints a block to parse on stdout:

```text
Trust Registry setup complete.
registry_did=did:webvh:…:dids.example.com:trust-registry
admin_did=did:key:z6Mk…
vta_did=did:webvh:…:vta
context_id=trust-registry
credential_path=/work/tr/vta-credential.json
env_path=vta.env
```

`env_out` holds the environment the registry needs to run as provisioned:
`TR_VTA_CREDENTIAL`, `TR_VTA_CONTEXT_ID`, the `ENABLE_*` flags matching
`transports`, `MEDIATOR_DID` and `TR_PUBLIC_URL`. Neither phase prints a
private key.

### H4 — Start the registry

Load `vta.env` (or set the same variables) and start `trust-registry`. Part B
covers the remaining options, such as the offline cache.

### In a VTA farm pipeline

| Step | Job | Parse |
|---|---|---|
| `step_tr_setup_key` | registry image: `trust-registry setup --setup-key-out setup-key.json --context <ctx>` | `Setup DID \(ephemeral\):\s+(did:\S+)` |
| `step_tr_acl_grant` | VTA image, before `deploy_vta`: `vta contexts create --id <ctx> --name "Trust Registry" --admin-did <did> --admin-expires 1h --admin-handoff` | nothing |
| `step_tr_setup` | registry image, after `deploy_vta` is Ready: `trust-registry setup --from /config/tr-setup.toml` | `(?m)^registry_did=(.+)$` and the other `key=value` lines |
| `deploy_tr` | registry Deployment with the `vta.env` variables | `/health` |

Run `step_tr_setup` before the VTC's setup, and put `registry_did` in the VTC
setup file's `registry_did`. The community's DID then refers clients to the
registry.

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

## Part A (alternative) — native `vta` commands, no `pnm`

Use this when Part A has to happen entirely on the VTA host with the daemon
stopped. For a scripted deployment, prefer the
[headless setup](#headless-setup-automated): it needs only one offline VTA
command, and the VTA publishes the DID. The native `vta` subcommands below are
**offline**: they open the VTA's local keystore directly, so:

- **Stop the VTA daemon first.** The keystore holds an exclusive lock; restart
  the daemon afterwards so it picks up the new context, keys and ACL entry.
- They are **not available in TEE deployments** (the enclave's store is not
  reachable from the parent). Use Part A with `pnm` against the live VTA there.

There is no sealed hand-off in this path: the VTA operator's automation writes
the credential file directly. That is fine when the same automation, on the
same trust boundary, deploys the registry. If the credential has to cross to a
different operator, use the sealed `pnm` flow in Part A instead (`vta bootstrap
open` has no `--out`, so a sealed bundle can only be opened into a credential
file with `pnm bootstrap open --out`).

### A1 — Create the context

```bash
vta contexts create --id trust-registry --name "Trust Registry"
```

`--id` becomes **`TR_VTA_CONTEXT_ID`**.

### A2 — Create the registry's `did:webvh`

```bash
vta create-did-webvh \
  --context trust-registry \
  --url https://dids.example.com/trust-registry \
  --did-log-file trust-registry.did.jsonl
```

- Passing `--url` makes the command non-interactive. The DID is minted with one
  pre-rotation key and as portable, and it becomes the context's DID.
- The mediator service endpoint is added automatically when the VTA config has
  a `[messaging]` section, which a DIDComm-connected VTA has.
- The command does **not** publish the DID. Upload `trust-registry.did.jsonl`
  so it is served at `https://dids.example.com/trust-registry/did.jsonl`
  (the command prints the exact URL).

> **Publishing to a registered DID-hosting server offline** with
> `vta did-mgmt dids create --server <id> --path <path> --mediator-service`
> works only on a VTA built with
> [verifiable-trust-infrastructure#2251](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/2251).
> Every document sent to the hosting server carries the VTA's proof, and before
> that fix the offline CLI had no signer loaded. On an older VTA the command
> fails with `could not sign the DID-management task with this VTA's
> operational key`, however the VTA is configured. There, either self-host the
> log as above, or run the same command as `pnm did-mgmt dids create …` against
> the **running** VTA. The fixed offline command reaches the hosting server over
> HTTPS, so the server must advertise an HTTPS endpoint (`TrustTaskHTTPS` or
> `WebVHHosting`).
>
> For a scripted deployment, the [headless setup](#headless-setup-automated)
> does all of this with the VTA running, and needs neither.

### A3 — Mint the registry's admin credential

```bash
vta create-did-key --context trust-registry --admin --label trust-registry \
  | base64 -d > /etc/trust-registry/vta-credential.json
chmod 600 /etc/trust-registry/vta-credential.json
```

`--admin` creates an admin ACL entry scoped to `trust-registry` and prints the
credential to stdout as base64. The registry reads the decoded JSON, which is
why the output is piped through `base64 -d`. That file is **`TR_VTA_CREDENTIAL`**,
in the same `{did, privateKeyMultibase, vtaDid, vtaUrl}` shape that Step 3
produces.

`vtaUrl` is filled in only when the VTA config sets `public_url`. If the file has
no `vtaUrl`, set **`TR_VTA_URL`** in the registry's `.env`.

### A4 — Restart the VTA, then continue with Part B

Start the VTA daemon again so the registry can authenticate with the new
credential.

---

## Part B — Configure the Trust Registry

### Step 4 — Build with the `vta` feature

```bash
# add a secrets backend feature (e.g. secrets-aws) if you want the offline
# cache stored in a cloud backend rather than on local disk
cargo build --release --bin trust-registry --features vta
```

The same binary runs `trust-registry setup` (see
[Headless setup](#headless-setup-automated)). In Docker, pass the features as
`--build-arg FEATURES="vta …"`.

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
| Headless, phase 1: setup key | `trust-registry setup --setup-key-out setup-key.json --context <ctx>` |
| Headless, VTA grant (offline) | `vta contexts create --id <ctx> --name "Trust Registry" --admin-did <setup DID> --admin-expires 1h --admin-handoff` |
| Headless, phase 2: provision | `trust-registry setup --from vta-setup.toml` |
| Point PNM at a VTA | `export VTA_URL=https://vta.example.com` |
| TR operator: make recipient request | `pnm bootstrap request --out tr-request.json --label trust-registry` |
| VTA operator: provision context + DID | `pnm contexts provision --id <ctx> --name "Trust Registry" --server <webvh> --mediator-service --recipient tr-request.json` |
| TR operator: open sealed bundle | `pnm bootstrap open --bundle tr-sealed.txt --expect-digest <hex> --out <path>` |
| Lighter admin-only credential (no DID) | `pnm contexts bootstrap --id <ctx> --name … --recipient tr-request.json` |
| Re-mint bundle for existing context | `pnm contexts reprovision …` |
| Native, offline (daemon stopped): context | `vta contexts create --id <ctx> --name "Trust Registry"` |
| Native, offline: registry DID (self-hosted log) | `vta create-did-webvh --context <ctx> --url <hosting-url> --did-log-file <file>` |
| Native, offline: admin credential | `vta create-did-key --context <ctx> --admin \| base64 -d > <path>` |

**Mapping to TR config:** `--id` slug → `TR_VTA_CONTEXT_ID` · recovered bundle
JSON → `TR_VTA_CREDENTIAL` · `vtaUrl` in the bundle (or `TR_VTA_URL`) → the VTA
endpoint.

## Related docs

- [`README.md`](README.md) — "Identity from a VTA (`vta`)" section and full
  environment-variable reference.
- [`SETUP_COMMAND_REFERENCES.md`](SETUP_COMMAND_REFERENCES.md) — the
  `setup-trust-registry` CLI (non-VTA provisioning).
- [`DIDCOMM_PROTOCOLS.md`](DIDCOMM_PROTOCOLS.md) — DIDComm transport details.
