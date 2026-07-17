# CLAUDE.md — Affinidi Trust Registry

The registry of trust records (recognition/authorization 4-tuples,
membership) that VTCs publish to and query. It receives signed Trust-Task
mutations over DIDComm — including an offline-sync path that drains the
mediator queue on reconnect — so its delivery semantics decide whether
registry writes are lost, duplicated, or applied exactly once.

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
  handoff.** The TSP offline-sync path currently acks `(None, id)` frames
  whose unpack failed — a *transient* resolver hiccup permanently deletes a
  valid signed registry write. Distinguish poison (permanent) from transient
  before acking; if you deliberately ack-first as poison defense, say so in a
  comment at the call site.
- **R1.4 — at-least-once redelivery needs message-id dedup.** Offline sync
  dispatches handlers *before* acking; when the ack fails the same batch is
  re-fetched every 30s and re-dispatched with no dedup — duplicate record
  mutations and duplicate responses. Registry mutations must be idempotent on
  message id.
- **R3.4 — optional wire fields are a two-sided contract.** `recognized` is
  `skip_serializing_if None` here while a consumer (vtc-service) required it
  — parse failure became an infinite 503 on cross-community session mint.
  Changing any record field's optionality means checking every consumer
  (R3.6), and consumers must treat absence restrictively, not as transport
  failure (R3.5).
