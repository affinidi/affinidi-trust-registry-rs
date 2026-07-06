# Design: VTA-managed keys/DIDs, TSP + DIDComm transports, and Trust Tasks messaging

Status: **Draft / investigation** — for maintainer review.
Branch: `feat/vta-tsp-didcomm-trust-tasks` (design only; implementation lands as a stack of small PRs — see §8).
Author: contributor (not maintainer) — reviews requested per-PR.

---

## 1. Goal

Three related capabilities for `affinidi-trust-registry-rs`:

1. **VTA integration** — have the Trust Registry (TR) obtain and manage its own signing/key-agreement keys and its DID through the **Verifiable Trust Agent (VTA)**, instead of loading raw secrets from AWS/env, so DID hosting and mediator setup delegate key custody to the VTA.
2. **TSP + DIDComm support** — expose the TR over both **DIDComm v2** (already present) and the **Trust Spanning Protocol (TSP)** so a **VTC** (Verifiable Trust Community) can reach it over either transport.
3. **Trust Tasks for all protocol messages** — carry all TR protocol operations (recognition, authorization, admin record writes) as versioned **Trust Task** documents, matching the convention already used across VTA/VTC/OpenVTC, so VTC/OpenVTC clients speak one framework to the registry.

---

## 2. Terminology (as verified in `~/devel`)

| Term | Meaning | Repo |
|------|---------|------|
| **VTA** | **Verifiable Trust Agent** — a service that custodies keys/DIDs/ACL for one identity (BIP-32 seed → derived keys; did:key/peer/webvh; pluggable `SeedStore`). | `verifiable-trust-infrastructure` (`vta-service`, `vta-sdk`, `vti-secrets`, `vti-common`) |
| **VTC** | **Verifiable Trust *Community*** — server (`vtc-service`) running a community on top of a VTA. **This is the client of our Trust Registry.** | `verifiable-trust-infrastructure/vtc-service` |
| **OpenVTC** | Member-side CLI/TUI client; talks to VTA/VTC, not directly to the TR. | `openvtc` |
| **VTI** | **Verifiable Trust Infrastructure** — the umbrella workspace (VTA + VTC). | `verifiable-trust-infrastructure` |
| **TSP** | **Trust Spanning Protocol** (ToIP / OWF Labs) — CESR/HPKE messaging between VIDs. *Not* DIDComm; a lower "spanning" layer. | `tsp-sdk` (crate `tsp_sdk` 0.9) |
| **Trust Tasks** | ToIP DTGWG framework: transport-agnostic JSON task documents (`TrustTask<P>`) with DIDComm + HTTPS bindings and a per-spec JSON-Schema registry. | `dtgwg-trust-tasks-tf` (crates `trust-tasks-rs`, `trust-tasks-didcomm`, `trust-tasks-https`) |
| **TRQP** | Trust Registry Query Protocol v2.0 — the read queries (recognition/authorization). | this repo + `trust-tasks` specs |
| **Mediator** | Affinidi DIDComm v2 **and TSP** relay/mailbox. | `affinidi-tdk-rs/crates/messaging` |

---

## 3. Current state of the Trust Registry (baseline)

Workspace: `trust-registry`, `trqp` (stub), `trql-client`, `test-client`. Uses `affinidi-tdk = "0.4"`.

**Messaging (DIDComm, present today):**
- Connects to a mediator via `TDK`/`ATM`/`ATMProfile` (`didcomm/mod.rs::prepare_atm_and_profile`, `didcomm/listener/`).
- `ProtocolHandler` trait is the extension point (`didcomm/handlers/mod.rs`): each handler declares `get_supported_inbound_message_types()` and `handle()`. `BaseHandler` dispatches inbound messages by `message.type_`.
- Registered handlers:
  - **TRQP** (`handlers/trqp/`): `.../trqp/1.0/query-authorization`, `query-recognition` (+ `/response`).
  - **tr-admin** (`handlers/admin/`): `.../tr-admin/1.0/{create,update,delete,read,list}-record` (+ `/response`). **Already implemented server-side.**
  - **ProblemReport**.
- Responses are packed with `atm.pack_encrypted(...)` and `forward_and_send_message(...)` back through the mediator.

**HTTP (present today):** `POST /authorization`, `POST /recognition`, `GET /.well-known/did.json` (`http/handlers/`). These already match what `vtc-service` calls.

**Secrets / keys (present today):** URI-scheme loader (`configs/loaders/mod.rs`): `string://`, `file://`, `aws_secrets://`, `aws_parameter_store://`. Keys are generated locally by `bin/generate_secrets.rs` (P-256 / secp256k1) and supplied as `Secret`s in profile JSON / env / AWS. **No VTA, no Vault.**

**DID methods:** `did:peer` (profiles) and `did:web` (well-known availability check in `listener/mod.rs`).

### What this means
The message-type **contract** the VTC expects already largely exists here:
- VTC reads (`recognise`/`health`) → our HTTP `POST /recognition` + `GET /.well-known/did.json` — **aligned & live.**
- VTC writes (`publish_member`/`delete_member`) → our DIDComm `tr-admin/1.0/*` — **server implemented; VTC client side is still scaffolded** (returns `Permanent`).

So the three asks are **additive layers** over a working base, not a rewrite.

---

## 4. Findings per subsystem

### 4.1 VTA — key & DID management (`verifiable-trust-infrastructure`)
- Custodies a BIP-32 seed via `SeedStore` (`vti-common/src/seed_store.rs`); backends via `vti-secrets::create_seed_store`: **AWS / GCP / Azure / HashiCorp Vault / K8s / keyring / TEE(KMS-Nitro) / plaintext(dev)**. Keys are derived on demand; only `KeyRecord` metadata persisted.
- DID methods: `did:key`, `did:peer:2`, and hosted/rotatable **`did:webvh`** (full lifecycle incl. `ROTATE_DID_WEBVH_KEYS`, promote to server-hosted).
- **Integration seam (the important part):** `vta_sdk::integration::startup(config, cache) -> StartupResult { did, DidSecretsBundle, source, client: Option<VtaClient> }` (`vta-sdk/src/integration/mod.rs`). It authenticates to a VTA (DIDComm-preferred, REST fallback), fetches the service's DID + private keys as a `DidSecretsBundle`, caches them via a **`SecretCache` trait you implement** (`vta-sdk/src/integration/cache.rs`), and falls back to cache if the VTA is offline.
- `DidSecretsBundle`/`SecretEntry` carry `private_key_multibase`, consumable via `Secret::from_multibase(...)` — i.e. directly usable by our existing DIDComm/`ATMProfile` path.
- `VtaClient` also exposes `sign`, `create_key`, `get_key_secret`, `fetch_did_secrets_bundle`, and webvh DID ops (create/rotate/register-with-server).

### 4.2 DID hosting (`affinidi-webvh-service`, `didwebvh-rs`)
- `didwebvh-rs` (v0.5, `prelude`) is the reusable `did:webvh` library: `create_did`/`update_did`, `DIDWebVHState` (`update_document`, `rotate_keys`, `deactivate`, `resolve`).
- **Signing is pluggable via a `Signer` trait** (`affinidi-data-integrity`), so a VTA/KMS-backed signer drops in without exposing private keys.
- The hosting service itself supports a **"VTA-managed" mode where a parent VTA provisions its keys** — confirming "service delegates DID/keys to VTA" is the intended pattern. Its own server keys sit behind a `SecretStore` with the same cloud/Vault backends.
- End-user/DID keys are **client-side**; the host serves `did.jsonl` read-only. A service can either self-host `.well-known/did.jsonl` or publish to a hosting server via `did-hosting-client` (`register_did_atomic`, `publish_did`).

### 4.3 Mediator (`affinidi-tdk-rs/crates/messaging`)
- One relay supports **both DIDComm v2 and TSP** (shared `/inbound`); mediator **advertises a `TSPTransport` service** in its DID document (`#tsp`) for TSP routing; for did:web it's added at startup, for did:peer/webvh it must be baked into the DID doc.
- Client connects via `ATM` + `ATMProfile::from_tdk_profile(&TDKProfile{ did, mediator, secrets })`; **endpoints (REST + WS) are resolved from the mediator DID document service block**, not hand-configured.
- ACL model: `explicit_deny`/`explicit_allow` + `global_acl_default`; account materialised on first authenticate. Mediator account management itself now uses **Trust Tasks** (`messaging/account/*`), confirming the direction.

### 4.4 TSP (`tsp_sdk` 0.9)
- CESR-encoded, HPKE-Auth confidential + Ed25519-signed; **no DIDComm code** — a separate pipeline. Coexists with DIDComm in one tokio process (shares runtime + DID resolution).
- High-level API: `AsyncSecureStore` (`Clone`/`Send`/`Sync`, good for axum state): `add_private_vid`, `verify_vid`, `send(sender, receiver, nonconfidential, msg)`, `receive(vid) -> TSPStream`, `seal_message`/`open_message`.
- **Pluggable persistence** via `SecureStorage` trait (default `AskarSecureStorage`); or drive `export`/`import` of `Vec<ExportVid>` to back it with our own store/KMS.
- VID/DID methods: `did:web`, `did:peer`, `did:webvh`. DID docs use a `TSPTransport` service entry. Transports: tcp/tls/quic/http(+ws).

### 4.5 Trust Tasks (`dtgwg-trust-tasks-tf`)
- `TrustTask<P>` JSON envelope (`id`, `type` = `https://trusttasks.org/spec/<slug>/<MAJOR.MINOR>`, `issuer`/`recipient` VIDs, `threadId`, `payload`, optional `proof`). `#response`/`#request` fragments; standard `trust-task-error` type + error codes.
- Server ergonomics:
  - **`Dispatcher`** (`trust-tasks-rs/src/dispatcher.rs`): `.on::<Payload, _>(handler)`, routes by canonical Type URI, `dispatch_or_reject` builds error responses.
  - **`consume_inbound(handler, proof_policy, doc, my_vid, now, id_factory, async_handler) -> ConsumeOutcome` (`consume.rs`)** — runs the §7.2 consumer pipeline (expiry, recipient, identity cross-check, proof).
  - Bindings: **`trust-tasks-didcomm`** (`pack_trust_task`/`unpack_trust_task`, wraps `TrustTask<P>` as the body of a DIDComm message with envelope type `https://trusttasks.org/binding/didcomm/0.1/envelope`; authcrypt sender → `issuer`) and **`trust-tasks-https`** (Axum `POST /trust-tasks`).
- There are already **`specs/vta/*`** tasks; VTC/OpenVTC already model **every wire op as a Trust Task** dual-bound to REST + DIDComm (+ TSP for VTA ops).

### 4.6 What the VTC expects from us (`vtc-service/src/registry/`)
- Trait `TrustRegistryClient`: `recognise`, `read_member`, `health` (reads, **live over HTTP TRQP**), `publish_member`, `delete_member` (writes, **DIDComm `tr-admin/1.0/*`, scaffolded**).
- Wire shapes it already sends: `POST /recognition` `{entity_id, authority_id, action:"recognise", resource:"trust-graph"}` → `{recognized: bool}` (`404` ⇒ `Ok(false)`); `GET /.well-known/did.json`; https required for non-loopback.
- Convention it wants us to match: **each registry op = versioned Trust Task type URI, dual REST+DIDComm transport**, optionally TSP; TR advertises its DID + service endpoints (mediator, `#tsp`) in its DID document.

---

## 5. Target architecture

```
                       ┌────────────────────────────────────────────┐
                       │            Trust Registry (this repo)       │
   VTA (keys/DID) ◄────┤  vta-sdk::integration::startup()            │
   did:webvh host ◄────┤  → DID + DidSecretsBundle (cached locally)  │
                       │                                             │
   VTC / OpenVTC       │  Transports:                                │
   ───HTTP TRQP───────►│   • HTTP  (axum)      reads + trust-tasks   │
   ───DIDComm─────────►│   • DIDComm (ATM/mediator)  ProtocolHandler │
   ───TSP─────────────►│   • TSP   (AsyncSecureStore) TSP pipeline   │
                       │                                             │
                       │  One protocol model: Trust Tasks            │
                       │   Dispatcher.on::<Recognise>()              │
                       │              .on::<Authorization>()         │
                       │              .on::<{Create,Update,Delete}Record>()
                       └────────────────────────────────────────────┘
```

Key principle: **one protocol model (Trust Tasks), three transports (HTTP / DIDComm / TSP), keys/DID from VTA.** Each transport binding decodes to the same `TrustTask<P>` and feeds a single `Dispatcher`.

---

## 6. Gap analysis

| Capability | Exists today | Needed |
|---|---|---|
| DIDComm transport + mediator | ✅ `ATM`/listener/`ProtocolHandler` | Reuse as-is |
| HTTP reads (`/recognition`,`/authorization`,`/.well-known/did.json`) | ✅ | Reuse; add Trust Tasks `POST /trust-tasks` alongside |
| `tr-admin/1.0/*` DIDComm write handler | ✅ (server) | Reuse; re-expose as Trust Tasks |
| Keys/DID from **VTA** | ❌ (AWS/env only) | `SecretCache` + `vta_sdk::integration::startup()` |
| `did:webvh` self-DID + rotation | ❌ (did:peer/web) | `didwebvh-rs` + VTA `Signer`, or VTA webvh ops via `VtaClient` |
| **TSP** transport | ❌ | `tsp_sdk::AsyncSecureStore` pipeline + `#tsp` service in DID doc |
| **Trust Tasks** envelope for TR ops | ❌ (bespoke PIURIs) | `trust-tasks-rs` `Dispatcher` + `trust-tasks-didcomm`/`-https` |
| TR Trust Task **specs** (recognition/authorization/records) | ❌ (only `specs/vta/*` exist) | Author `specs/trust-registry/*` in `dtgwg-trust-tasks-tf` |

**Dependencies (resolved):** `affinidi-tdk`, `didwebvh-rs`, `tsp_sdk`, `trust-tasks-rs`/`-didcomm`/`-https`, and **`vta-sdk` are all published** and can be depended on as normal registry crates (like the existing `affinidi-tdk = "0.4"`). VTA integration is still kept behind an optional `--features vta` so the default OSS build has no runtime dependency on a VTA being reachable — but this is a build-ergonomics choice, not a dependency-availability constraint.

---

## 7. Design detail

### 7.1 VTA integration for key & DID management
- Add a new secrets **source** parallel to `configs/loaders/`: a `vta` source that, at startup, calls `vta_sdk::integration::startup(&VtaServiceConfig, &cache)` and returns `{ did, Vec<Secret> }` for the TR's `TDKProfile`.
- Implement `SecretCache` over the existing storage layer (DynamoDB/Redis are already deps) or a local encrypted file, so the TR keeps running if the VTA is briefly offline.
- Feature-gate behind `--features vta` so builds without access to `vta-sdk` still compile (keeps AWS/env path as default).
- DID hosting: prefer **VTA-managed** `did:webvh` — the TR's DID + rotation handled by the VTA (`VtaClient` webvh ops); the TR just serves/points to the resulting DID document. Alternative self-hosted path: `didwebvh-rs` with a VTA-backed `Signer`.
- Mediator setup: source the mediator-connection `Secret`s from the same `DidSecretsBundle`, so there is a single key custody path.

### 7.2 TSP + DIDComm support
- Keep DIDComm exactly as-is.
- Add a TSP pipeline: hold an `AsyncSecureStore` in shared state; register the TR's VID (same `did:webvh`/`did:peer` identity); run a background `receive(vid)` loop that decodes inbound TSP → `TrustTask<P>` → the shared `Dispatcher`; send responses via `store.send(...)`.
- Advertise a `TSPTransport` service (`#tsp`) in the TR's DID document so VTCs/mediators can route TSP to it (mirrors the mediator's own advertisement).
- Feature-gate behind `--features tsp`.

### 7.3 Trust Tasks for all protocol messages
- Introduce a single `Dispatcher` mapping Trust Task payload types → the TR's existing repository logic:
  - recognition, authorization (reads) → `TrustRecordRepository::find_by_query`
  - create/update/delete/read/list record → existing admin repository ops.
- Wire three bindings into that one dispatcher:
  - **DIDComm**: a new `ProtocolHandler` that matches the Trust Tasks envelope type and calls `unpack_trust_task` → `consume_inbound` → dispatcher (keep the legacy `trqp/1.0` + `tr-admin/1.0` handlers during a deprecation window).
  - **HTTP**: mount `trust-tasks-https` `POST /trust-tasks` beside the existing REST routes (existing routes stay for TRQP back-comp).
  - **TSP**: the §7.2 receive loop.
- Author the TR task specs (`recognition`, `authorization`, `record-create/update/delete`) in `dtgwg-trust-tasks-tf` under `specs/trust-registry/*`, generate typed payloads, and depend on them.

---

## 8. PR stack (small, individually reviewable; each targets the previous)

Bottom of stack merges to `main` first; contributor prepares, maintainers approve per-PR.

**Track A — messaging model (independent of VTA):**
- **A1 `feat/trust-tasks-core`** — add `trust-tasks-rs` dep; introduce a `Dispatcher` wrapping existing repository logic; no transport change yet (unit-tested in isolation). *Base: `main`.*
- **A2 `feat/trust-tasks-didcomm`** — new `ProtocolHandler` decoding the Trust Tasks DIDComm envelope into the A1 dispatcher; legacy `trqp/1.0`+`tr-admin/1.0` handlers retained. *Base: A1.*
- **A3 `feat/trust-tasks-http`** — mount `POST /trust-tasks` alongside existing REST. *Base: A1.*
- **A4 `feat/tsp-support`** — TSP `AsyncSecureStore` pipeline + `#tsp` DID-doc advertisement, feeding the A1 dispatcher; `--features tsp`. *Base: A2.*
- **A5 `feat/trust-registry-task-specs`** — (in `dtgwg-trust-tasks-tf`) author `specs/trust-registry/*`; separate repo PR that A1 depends on. *Sequenced first if specs must be published.*

**Track B — VTA key/DID (independent of Track A):**
- **B1 `feat/vta-secret-source`** — `SecretCache` impl + `vta_sdk::integration::startup()` as a new secrets source; `--features vta`; AWS/env remains default. *Base: `main`.*
- **B2 `feat/vta-didwebvh`** — TR self-DID as VTA-managed `did:webvh`; serve/point to the DID document. *Base: B1.*
- **B3 `feat/mediator-keys-from-vta`** — mediator-connection secrets sourced from the VTA `DidSecretsBundle`. *Base: B2.*

Tracks A and B are independent and can progress in parallel; a final small PR flips defaults once maintainers are comfortable.

---

## 9. Risks / open questions (for maintainers)

1. ~~`vta-sdk` availability~~ **Resolved:** `vta-sdk` is published and used as a normal registry crate; VTA integration is feature-gated (`--features vta`) purely for build ergonomics, not availability.
2. **Trust Task spec ownership** — do the TR task specs belong in `dtgwg-trust-tasks-tf` (`specs/trust-registry/*`) or vendored here? Need a published crate for typed payloads.
3. **Back-compat window** — how long to keep legacy `trqp/1.0` and `tr-admin/1.0` PIURIs alongside the Trust Tasks envelope? VTC reads are HTTP today, so no rush to remove HTTP TRQP.
4. **DID method for the TR identity** — move from `did:peer`/`did:web` to VTA-managed `did:webvh`? Affects mediator ACL and DID-doc service advertisement (`#tsp`).
5. **Proof policy** — do TR Trust Tasks require Data Integrity proofs (`trust-tasks-proof`) or rely on transport auth (authcrypt/TSP) only?
6. **VTC client gap** — `publish_member`/`delete_member` are scaffolded in `vtc-service`; server support here is ready — coordinate so both sides land together.

---

## 10. Appendix — key integration points (file references)

- TR extension point: `trust-registry/src/didcomm/handlers/mod.rs` (`ProtocolHandler`), `handlers/build.rs` (registration).
- TR admin protocol (already implemented): `trust-registry/src/didcomm/handlers/admin/mod.rs`.
- TR secrets loader: `trust-registry/src/configs/loaders/mod.rs`.
- VTA seam: `verifiable-trust-infrastructure/vta-sdk/src/integration/mod.rs`, `.../integration/cache.rs`.
- DID hosting: `didwebvh-rs` `prelude` (`create_did`, `DIDWebVHState`), `affinidi-data-integrity` `Signer`.
- Mediator client: `affinidi-tdk-rs/crates/messaging/affinidi-messaging-sdk` (`ATM`, `ATMProfile`).
- TSP: `tsp-sdk/src/async_store.rs` (`AsyncSecureStore`), `src/secure_storage.rs` (`SecureStorage`).
- Trust Tasks: `dtgwg-trust-tasks-tf/trust-tasks-rs/src/{dispatcher,consume,document}.rs`, `trust-tasks-didcomm/src/pack.rs`, `trust-tasks-https/src/server.rs`.
- VTC expectations: `verifiable-trust-infrastructure/vtc-service/src/registry/{client,upstream,mod}.rs`, `docs/03-vtc/trust-registry.md`.
