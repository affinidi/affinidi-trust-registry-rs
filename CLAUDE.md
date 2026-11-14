# CLAUDE.md — Affinidi Trust Registry

The registry of trust records (recognition/authorization 4-tuples,
membership) that VTCs publish to and query. It receives signed Trust-Task
mutations over DIDComm and TSP — including an offline-sync path that drains
the mediator queue — so its delivery semantics decide whether registry
writes are lost, duplicated, or applied exactly once.

## Cross-service networking & integration discipline

Read the ecosystem doc set in `../design-docs/` before changing the DIDComm
listener, sync, or record-serialization code:

- **`vti-stack-development-guide.md`** — binding rules (R-numbers below);
  paste its pre-merge checklist into PRs.
- **`vti-networking-remediation-plan.md`** — deliverable **D6** covers this
  repo (jointly with vtc-service's `registry/upstream.rs`).
- **`vti-architectural-direction.md`** — design-level rationale.

Rules that bite hardest here:

- **R1.6 — ack (and thereby delete from the mediator) only after durable
  handoff.** Both receive paths now ack a message only after its handler
  returns: the DIDComm pickup listener (`didcomm/listener/`, TSP disabled)
  and the delivery-layer loop (`messaging/service.rs`, TSP enabled, which
  drives the SDK's `DidCommTransport` itself — the delivery crate's
  `MessagingService` acks at broadcast handoff and is not used). The rules
  live in `didcomm/listener/delivery.rs`: poison is acked, a handler error,
  panic or timeout is not, a Trust Task refused as `retryable` (storage
  unavailable, internal error) is not, and a message that keeps failing is
  deleted (logged at `error`) only after 5 failures over at least 10
  minutes. In a `--features tsp` build, an offline-sync `(None, id)` frame
  (the SDK could not unpack it and does not say why) is treated as transient
  under that same bound. On shutdown the delivery-layer loop deletes what it
  handled directly (`delete_messages_direct`), because the SDK's background
  deletion queue dies with `graceful_shutdown`. Any new ack-first must be
  poison defense, said so in a comment at the call site.
  Still open: an unacked message on the delivery-layer path is offered again
  only when the mediator next pushes the inbox (a reconnect or restart), not
  every 30 s. And the SDK deletes some frames itself, before the registry
  sees them: its unpack deletes what it classifies as poison (a bad
  signature, bad encoding, a policy rejection — on the live stream and the
  DIDComm-only offline fetch), and `DidCommTransport` deletes a TSP frame
  whose unpack still fails after 3 in-process attempts, as well as padding,
  upper-layer control frames and control frames it refuses to record.
- **R1.4 — at-least-once redelivery needs message-id dedup.** Redelivery is
  real: the offline sync and the live stream drain the same queue, and the
  mediator pushes the stored inbox again on every reconnect. Both paths keep
  a `DeliveryLedger` keyed by mediator message id (a copy in flight is
  skipped, a handled copy is re-acked, not re-handled), and the
  `TaskHandler` dedups writes on the Trust Task id and replays the recorded
  outcome (`dedup/mod.rs`). Still open: both are in memory, so a restart (or
  a second replica) forgets them — durable dedup is #194. Registry mutations
  must stay idempotent on message id.
- **R3.4 — optional wire fields are a two-sided contract.** `recognized` is
  `Option` and `skip_serializing_if None` on the stored record
  (`domain/mod.rs`) and the `registry/record/*` payloads
  (`trust_tasks/payloads.rs`); a consumer (vtc-service) once required it and
  a parse failure became an infinite 503 on cross-community session mint.
  TRQP answers always carry `recognized`/`authorized`. Changing any record
  field's optionality means checking every consumer (R3.6), and consumers
  must treat absence restrictively, not as transport failure (R3.5).

## Releases

Branching, versioning and publishing follow `RELEASES.md` (nightly → cut
`release/<major.minor>` → rc/GA/patch preps). `main` publishes nothing and
never edits the workspace version; changelog entries go under
`## Unreleased`. To release, trigger the release workflows rather than
running the scripts:

- cut: `gh workflow run release-cut.yml --ref main -f name=0.42` (a dry run;
  add `-f dry-run=false` to cut);
- rc, GA or patch: `gh workflow run release-prep.yml --ref release/0.42 -f kind=rc`
  (or `ga`, `patch`);
- backport: label the merged PR `backport release/0.42`.

`scripts/cut-release.py` is a maintainer's local fallback only; it needs
Python ≥ 3.11 (`tomllib`).
