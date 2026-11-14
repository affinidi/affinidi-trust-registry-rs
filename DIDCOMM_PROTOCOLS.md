# Trust Registry DIDComm Protocols

Trust Registry utilises DIDComm protocols to manage and query trust records securely and privately.

DIDComm offers a flexible messaging service that enables you to define higher-level protocols, allowing for workflow orchestration tailored to specific purposes.

<!-- omit from toc -->
## Table of Contents

- [Trust Registry Administration](#trust-registry-administration)
  - [Removed: `tr-admin/1.0`](#removed-tr-admin10)
- [Trust Registry Queries](#trust-registry-queries)
  - [Summary](#summary)
  - [Motivation](#motivation)
  - [Roles](#roles)
  - [Requirements](#requirements)
  - [Workflow](#workflow)
  - [Messages](#messages)
- [Problem Reporting](#problem-reporting)
- [Security Considerations](#security-considerations)
- [Implementation](#implementation)


## Trust Registry Administration

Trust records are managed with the `registry/record/*` Trust Tasks, carried in
the DIDComm Trust Task envelope
(`https://trusttasks.org/binding/didcomm/0.1/envelope`) or over TSP. The
current versions are `registry/record/put/0.3`, `registry/record/delete/0.2`
and `registry/record/query/0.3`; a record's validity window needs `put/0.3`.
The earlier versions are still accepted. The
[Trust Task protocol surface](README.md#trust-task-protocol-surface) table in
the README is the authoritative list of tasks and versions.

A write — and a `registry/record/query`, which returns whole records including
their `context` — is accepted only when all of the following hold:

- the document carries an in-band `issuer`, and that issuer is the sender the
  transport authenticated;
- the document names this registry as its `recipient`, carries an `issuedAt`
  no older than five minutes (and not more than a minute in the future), and
  its `id` has not been accepted before, on any binding;
- the document carries a Data Integrity proof with `proofPurpose`
  `authentication`, made with the issuer's operational key: a verification
  method of the issuer's own DID that the issuer's DID document lists under
  `authentication`. The proof must verify;
- the issuer is listed in `ADMIN_DIDS`;
- the write acts under an authority the issuer may act for: its own DID, or
  one listed for it in `ADMIN_AUTHORITIES`.

For a record put, delete or query the authority is the `authority_id` it names
(a query must name one). For
`git-trust/grant` and `git-trust/revoke` it is the authority of the git-trust
enablement the issuer may act for (enablement is per authority; an issuer that
may act for several enabled authorities names one in the payload's
`ext."com.affinidi.trust-registry".authority`), and for `governance/capability/enable` and `disable` it is the
authority the capability's config names. `registry/did/rotate`, and enabling or
disabling a capability whose config names no authority, act on the registry
itself, so their authority is the registry's own DID: only an admin listed for
that DID in `ADMIN_AUTHORITIES` may send them. Every write, accepted or refused,
is written to the audit log.

### Removed: `tr-admin/1.0`

The legacy `https://affinidi.com/didcomm/protocols/tr-admin/1.0` protocol
(`create-record`, `update-record`, `delete-record`, `read-record`,
`list-records`) is no longer served. Messages of those types are not
answered and change nothing. To migrate:

| `tr-admin/1.0` message | Trust Task |
| ---------------------- | ---------- |
| `create-record` | `registry/record/put/0.3` with `"expectedExisting": false` |
| `update-record` | `registry/record/put/0.3` with `"expectedExisting": true` |
| `delete-record` | `registry/record/delete/0.2` |
| `read-record` | `registry/record/query/0.3` naming all four key parts, signed |
| `list-records` | `registry/record/query/0.3` naming an `authority_id` (plus any other filter; paginated), signed |

Each of these must be signed and must name an authority the issuer may act
under, as above: `registry/record/query` is for admins, not the public. The
public surface is the TRQP recognition and authorization queries below. The `test-client` crate shows the full flow.

## Trust Registry Queries

### Summary

A protocol to query trust records from the Trust Registry using TRQP 2.0.

### Motivation

To provide a secure, end-to-end encrypted query messages between Verifiers and Trust Registry.

### Roles

There are two roles defined in querying trust records:

- **Verifier:** The DID that queries the Trust Registry to verify whether a particular DID is authorised or recognised by an authority based on governance framework.
- **Trust Registry:** The DID that processes the request to query trust records and return the result to the requester.

### Requirements

- DIDComm v2.1 protocol.
- An authenticated (authcrypt) message. The registry answers the sender the
  envelope proves; a message without one (anoncrypt or plaintext) is dropped
  without an answer — not even a problem report, since there is no proven
  sender to send one to. Use the REST TRQP endpoints for queries without a
  DIDComm identity.
- A `thid` on the request is recommended. Every reply (answer or problem
  report) carries the request's `thid`, or the request's `id` when it has
  none, so a client with several queries outstanding can tell the replies
  apart.

The registry sends exactly one reply per query. A query whose record does not
exist is answered, not refused: `recognized` (or `authorized`) is `false` and
`message` says that no such record exists. A query the registry cannot answer
gets a [problem report](#problem-reporting) instead. A message of a type the
registry does not serve is dropped without an answer.

### Workflow

When querying trust records, the user initiates the request by sending a query message to the Trust Registry's DID through the DIDComm mediator.

*Sample query flow.*

```mermaid
sequenceDiagram
    participant User as TR User
    participant DM as DIDComm Mediator
    participant TR as Trust Registry

    User->>DM: User sends a message containing the message type and payload. <br />Authorization query request [didcomm/protocols/trqp/1.0/query-authorization]
    Note over User, DM: User client starts listening to the response
    TR->>DM: Trust Registry fetches the messages
    TR->>TR: Processes the message with TRQP 2.0.
    TR->>DM: Sends a response containing the result of the request <br />  Authorization query response [didcomm/protocols/trqp/1.0/query-authorization/response]
    User->>DM: Fetches the response from the Trust Registry
    Note over User, DM: User client terminates the listener

```

### Messages

#### query-authorization

A query message to the Trust Registry if a given entity is authorized by a particular authority through its governance framework.

**Message Type URI:**

Action | Message Type |
-------|--------------|
Request | `https://affinidi.com/didcomm/protocols/trqp/1.0/query-authorization` |
Response | `https://affinidi.com/didcomm/protocols/trqp/1.0/query-authorization/response` |

**Message Fields:**

- **`authority_id` REQUIRED** - The DID of the authority who authorised the entity and publishes the governance framework.
- **`entity_id` REQUIRED** - The DID of the entity who is the subject of verification whether it is authorised by the authority.
- **`action` REQUIRED** - A published vocabulary of common actions that the entity is authorised to perform.
- **`resource` REQUIRED** - The resource identifier where the entity can perform the stated action.

**Additional Fields:**

- **`record_type`** - Part of the query response. The type of record requested by the verifier.
- **`time_requested`** - Part of the query response. The date and time the Trust Registry received the query. (`trqp/1.0` carries no `context`, so unlike the REST TRQP endpoints and the `registry/recognition` and `registry/authorization` Trust Tasks it cannot ask about another instant; use those for `context.time`.)
- **`time_evaluated`** - Part of the query response. The date and time the query is evaluated.
- **`message`** - Part of the query response. A human-readable message about the result of the query, including why the answer is `false` (no such record, or outside the record's validity window).

**Example:**

Request:

```json
{
    "id": "040d3b97-0be8-43f8-8a95-b3a926aadff1",
    "typ": "application/didcomm-plain+json",
    "type": "https://affinidi.com/didcomm/protocols/trqp/1.0/query-authorization",
    "body": {
      "action": "action_xyz",
      "authority_id": "did:example:authority456",
      "entity_id": "did:example:entity123",
      "resource": "resource_abc"
    },
    "from": "<VERIFIER_DID>",
    "to": [
        "<TRUST_REGISTRY_DID>"
    ],
    "thid": "6a627735-6743-4141-8cb7-1359d778936b"
}
```

Response:

```json
{
    "id": "040d3b97-0be8-43f8-8a95-b3a926aadff2",
    "typ": "application/didcomm-plain+json",
    "type": "https://affinidi.com/didcomm/protocols/trqp/1.0/query-authorization/response",
    "body": {
      "action": "action_xyz",
      "authority_id": "did:example:authority456",
      "authorized": true,
      "context": {
        "id": "https://governance.example.org/healthcare-framework",
        "type": "GovernanceFramework",
        "name": "Healthcare Trust Framework",
        "version": "2.0"
      },
      "entity_id": "did:example:entity123",
      "resource": "resource_abc",
      "record_type":"Authorization",
      "time_requested":"2025-12-09T05:33:52Z",
      "time_evaluated":"2025-12-09T05:33:52Z",
      "message": "did:example:entity123 authorized to action_xyz+resource_abc by did:example:authority456"
    },
    "from": "<TRUST_REGISTRY_DID>",
    "to": [
        "<VERIFIER_DID>"
    ],
    "thid": "6a627735-6743-4141-8cb7-1359d778936b"
}
```

#### query-recognition

A query message to the Trust Registry if a given entity is recognised by a particular authority through its governance framework.

**Message Type URI:**

Action | Message Type |
-------|--------------|
Request | `https://affinidi.com/didcomm/protocols/trqp/1.0/query-recognition` |
Response | `https://affinidi.com/didcomm/protocols/trqp/1.0/query-recognition/response` |

**Message Fields:**

- **`authority_id` REQUIRED** - The DID of the authority who recognised the entity and publishes the governance framework.
- **`entity_id` REQUIRED** - The DID of the entity who is the subject of verification whether it is recognised by the authority.
- **`action` REQUIRED** - A published vocabulary of common actions that the entity is recognised to perform.
- **`resource` REQUIRED** - The resource identifier where the entity can perform the stated action.

**Additional Fields:**

- **`record_type`** - Part of the query response. The type of record requested by the verifier.
- **`time_requested`** - Part of the query response. The date and time the Trust Registry received the query. (`trqp/1.0` carries no `context`, so unlike the REST TRQP endpoints and the `registry/recognition` and `registry/authorization` Trust Tasks it cannot ask about another instant; use those for `context.time`.)
- **`time_evaluated`** - Part of the query response. The date and time the query is evaluated.
- **`message`** - Part of the query response. A human-readable message about the result of the query, including why the answer is `false` (no such record, or outside the record's validity window).

**Example:**

Request:

```json
{
    "id": "040d3b97-0be8-43f8-8a95-b3a926aadff1",
    "typ": "application/didcomm-plain+json",
    "type": "https://affinidi.com/didcomm/protocols/trqp/1.0/query-recognition",
    "body": {
      "action": "action_xyz",
      "authority_id": "did:example:authority456",
      "entity_id": "did:example:entity123",
      "resource": "resource_abc"
    },
    "from": "<VERIFIER_DID>",
    "to": [
        "<TRUST_REGISTRY_DID>"
    ],
    "thid": "6a627735-6743-4141-8cb7-1359d778936b"
}
```

Response:

```json
{
    "id": "040d3b97-0be8-43f8-8a95-b3a926aadff2",
    "typ": "application/didcomm-plain+json",
    "type": "https://affinidi.com/didcomm/protocols/trqp/1.0/query-recognition/response",
    "body": {
      "action": "action_xyz",
      "authority_id": "did:example:authority456",
      "recognized": true,
      "context": {
        "id": "https://governance.example.org/healthcare-framework",
        "type": "GovernanceFramework",
        "name": "Healthcare Trust Framework",
        "version": "2.0"
      },
      "entity_id": "did:example:entity123",
      "resource": "resource_abc",
      "record_type":"Recognition",
      "time_requested":"2025-12-09T05:33:52Z",
      "time_evaluated":"2025-12-09T05:33:52Z",
      "message": "did:example:entity123 recognized by did:example:authority456"
    },
    "from": "<TRUST_REGISTRY_DID>",
    "to": [
        "<VERIFIER_DID>"
    ],
    "thid": "6a627735-6743-4141-8cb7-1359d778936b"
}
```

Response for a record the registry does not hold:

```json
{
    "id": "040d3b97-0be8-43f8-8a95-b3a926aadff3",
    "typ": "application/didcomm-plain+json",
    "type": "https://affinidi.com/didcomm/protocols/trqp/1.0/query-recognition/response",
    "body": {
      "action": "action_xyz",
      "authority_id": "did:example:authority456",
      "recognized": false,
      "entity_id": "did:example:entity123",
      "resource": "resource_abc",
      "time_requested":"2025-12-09T05:33:52Z",
      "time_evaluated":"2025-12-09T05:33:52Z",
      "message": "did:example:entity123 not recognized by did:example:authority456: no such record"
    },
    "from": "<TRUST_REGISTRY_DID>",
    "to": [
        "<VERIFIER_DID>"
    ],
    "thid": "6a627735-6743-4141-8cb7-1359d778936b"
}
```

## Problem Reporting

The registry answers a `trqp/1.0` query it cannot answer with a DIDComm v2.1
problem report, sent to the authenticated sender on the query's thread: `thid`
is the query's `thid` (or its `id`), and `pthid` names the same thread.

The [PIURI](https://identity.foundation/didcomm-messaging/spec/v2.1/#protocol-identifier-uri) for this protocol is `https://didcomm.org/report-problem/2.0`.

| Code | When the registry sends it |
| ---- | -------------------------- |
| `e.p.msg.bad-request` | The query body is not a `trqp/1.0` query (a missing or mistyped `entity_id`, `authority_id`, `action` or `resource`). |
| `e.p.msg.internal-error` | The registry could not complete the lookup (for example, its storage is unavailable). Retrying later may succeed. |

A missing record is **not** a problem: it is answered with `recognized` or
`authorized` set to `false` (see above). The codes `e.p.msg.unauthorized`,
`e.p.msg.not-found` and `e.p.msg.conflict` are defined in the code base but
the registry does not currently send them.

```json
{
  "id": "345e6789-e89b-12d3-a456-426614174222",
  "typ": "application/didcomm-plain+json",
  "type": "https://didcomm.org/report-problem/2.0/problem-report",
  "from": "<TRUST_REGISTRY_DID>",
  "to": [
    "<VERIFIER_DID>"
  ],
  "thid": "6a627735-6743-4141-8cb7-1359d778936b",
  "pthid": "6a627735-6743-4141-8cb7-1359d778936b",
  "body": {
    "code": "e.p.msg.bad-request",
    "comment": "Invalid trqp/1.0 query: missing field `resource`"
  }
}
```

Trust Tasks (`registry/*`) do not use problem reports: their errors are Trust
Task error documents in the same envelope as a success.

The mediator may also return its own problem reports, for example when its
Access Control Lists refuse a message.

For more information, visit the [Problem Reports](https://identity.foundation/didcomm-messaging/spec/v2.1/#problem-reports) section.


## Security Considerations

Every message to the Trust Registry over DIDComm — administration and queries
alike — **MUST** be encrypted and verifiable to ensure confidentiality,
integrity, and authenticity.

- Messages **MUST** use the `authcrypt` encryption envelope (e.g., `authcrypt(plaintext)`). The registry answers only the sender an authcrypt envelope proves. An anoncrypt or plaintext message is dropped unanswered, whatever its `from` header says, because nothing binds that header to the sender.

**Trust Registry Administration**

- The Trust Registry **MUST** assign an appropriate ACL to the Administrator's DID.

- The Trust Registry **MUST NOT** treat the authenticated DIDComm sender as sufficient to change a record. A change is authorised by the Data Integrity proof on the Trust Task, bound to the in-band `issuer`, which must also be the authenticated sender.

- An administrator **MUST** only be able to write records under an authority it is allowed to act for: its own DID, or one the operator lists for it in `ADMIN_AUTHORITIES`.

## Implementation

The DIDComm binding lives in [`trust-registry/src/didcomm`](trust-registry/src/didcomm) in this repository.