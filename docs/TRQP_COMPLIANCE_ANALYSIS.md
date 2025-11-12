# TRQP Specification — Compliance Analysis

This document summarizes differences between the current implementation in `trust-registry-rs` and the Trust Registry Query Protocol (TRQP) Specification v2.0.

Note: the TRQP specification has inconsistent examples between its JSON schemas (Sections 6 & 7) and the HTTPS examples (Sections 9 & 10). This analysis follows Sections 6 & 7 (see discussion: https://github.com/trustoverip/tswg-trust-registry-protocol/issues/149#issuecomment-3411337461).

---

## 1) Data model differences

Existing struct (current implementation)

```rust
pub struct TrustRecordIds {
    entity_id: EntityId,
    authority_id: AuthorityId,
    assertion_id: AssertionId,
}
```

Expected/Spec-aligned struct

```rust
pub struct TrustRecordIds {
    entity_id: EntityId,
    authority_id: AuthorityId,
    action: Action,
    resource: Resource,
}
```

Existing struct (current implementation)

```rust
pub struct TrustRecord {
    entity_id: EntityId,
    authority_id: AuthorityId,
    assertion_id: Action,
    #[serde(skip_serializing_if = "Option::is_none")]
    recognized: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    assertion_verified: Option<bool>,
    context: Context,
}
```

Expected/Spec-aligned struct

```rust
pub struct TrustRecord {
    entity_id: EntityId,
    authority_id: AuthorityId,
    action: Action,
    resource: Resource,
    #[serde(skip_serializing_if = "Option::is_none")]
    recognized: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    authorized: Option<bool>,
    context: Context,
}
```

"Is Entity X authorized to take Action Y on Resource Z under Context C?"

---

## 2) API differences (Authorization & Recognition)

Below are side-by-side examples showing the current and the spec-aligned request/response formats. The intent is to highlight which fields differ and to provide clear, minimal JSON examples.

### Authorization

Request (current implementation)

```http
POST /authorization HTTP/1.1
Content-Type: application/json
Authorization: Bearer <token>
X-Request-ID: d4f34c12-9b7a-4e3a-a5d1-7e4f8c2c9f10

{
  "entity_id":    "user-1234",
  "authority_id": "auth-service-A",
  "assertion_id": "role-admin",
  "context": {
    "time": "2025-06-19T11:30:00Z"
  }
}
```

Request (spec-aligned)

```http
POST /authorization
Content-Type: application/json

{
  "entity_id":    "user-1234",
  "authority_id": "auth-service-A",
  "action":       "issue",
  "resource":     "country:state:driverlicense",
  "context": {
    "time": "2025-06-19T11:30:00Z"
  }
}
```

Response (current implementation)

```http
HTTP/1.1 200 OK
Content-Type: application/json
X-Request-ID: d4f34c12-9b7a-4e3a-a5d1-7e4f8c2c9f10

{
  "entity_id":          "user-1234",
  "authority_id":       "auth-service-A",
  "assertion_id":       "role-admin",
  "assertion_verified": true,
  "time_requested":     "2025-06-19T11:30:00Z",
  "time_evaluated":     "2025-06-19T11:30:00Z",
  "message":            "User-1234 holds the admin role.",
  "context": {
    "time": "2025-06-19T11:30:00Z"
  }
}
```

Response (spec-aligned)

```http
HTTP/1.1 200 OK
Content-Type: application/json

{
  "entity_id":    "did:user-1234",
  "authority_id": "auth-service-A",
  "action":       "issue",
  "resource":     "country:state:driverlicense",
  "authorized":   true,
  "time":         "2025-06-19T11:30:00Z",
  "message":      "did:user-1234 is authorized for issue+country:state:driverlicense (action+resource) by auth-service-A."
}
```

### Recognition

Request (current implementation)

```http
POST /recognition HTTP/1.1
Content-Type: application/json
Authorization: Bearer <token>
X-Request-ID: bfe9eb29-ab87-4ca3-be83-a1d5d8305716

{
  "entity_id":    "service-42",
  "authority_id": "did:example",
  "assertion_id": "peer-recognition",
  "context": {
    "time": "2025-06-19T10:00:00Z"
  }
}
```

Request (spec-aligned)

```http
POST /recognition
Content-Type: application/json

{
  "entity_id":    "service-42",
  "authority_id": "did:example",
  "action":       "recognize",
  "resource":     "listed-registry",
  "context": {
    "time": "2025-06-19T10:00:00Z"
  }
}
```

Response (current implementation)

```http
HTTP/1.1 200 OK
Content-Type: application/json
X-Request-ID: bfe9eb29-ab87-4ca3-be83-a1d5d8305716

{
  "entity_id":      "service-42",
  "authority_id":   "did:example",
  "assertion_id":   "peer-recognition",
  "recognized":     true,
  "time_requested": "2025-06-19T10:00:00Z",
  "time_evaluated": "2025-06-19T10:00:00Z",
  "message":        "Service-42 is recognized by auth-master.",
  "context": {
    "time": "2025-06-19T10:00:00Z"
  }
}
```

Response (spec-aligned)

```http
HTTP/1.1 200 OK
Content-Type: application/json

{
  "entity_id":    "service-42",
  "authority_id": "did:example",
  "action":       "recognize",
  "resource":     "listed-registry",
  "recognized":   true,
  "message":      "Service-42 is recognized by did:example."
}
```

## 3) Errors

#### 404 Not Found

Current implementation:

```json
{ "code": 404, "title": "not_found", "type": "about:blank" }
```

Spec-aligned:

```json
{
  "code": 404,
  "title": "Assertion not found",
  "type": "https://example.com/problems/invalid-assertion",
  "detail": "Assertion \"role-admin\" is not defined for authority auth-service-A."
}
```
