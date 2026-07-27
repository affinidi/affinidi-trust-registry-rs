# DID Service Discovery for Trust Registries and VTCs

**Status:** proposal, not implemented
**Scope:** the `service` block of a Trust Registry DID document, the `service`
block of a VTC that delegates to one, and the client-side resolution rules that
join them.

## 1. What the specs actually give us

Three sources, and only one of the three service types we need is standardised.

| Type | Status |
|---|---|
| `DIDCommMessaging` | Registered in [W3C DID Extensions](https://www.w3.org/TR/did-extensions-properties/#service-types). Use as-is. |
| `TSPTransport` | No spec. OpenWallet-Foundation-Labs reference-implementation convention; the ToIP TSP spec names no DID-document service type. |
| `TrustRegistry` | [ToIP Service Profile spec](https://github.com/trustoverip/tswg-trust-registry-service-profile/blob/main/spec.md), **Pre-Draft 0.0.1**, self-described as "not binding". Written by the Trust Registry Task Force for exactly this problem. |
| `TRQPRest` | Local to this workspace. No external cover. |

[CID 1.0 §Services](https://www.w3.org/TR/cid-1.0/#services) governs the
container: `type` is required and may be a string **or a set of strings**;
`serviceEndpoint` is required and may be a string, a map, or a set; service
`id`s must be unique within the document.

[TRQP v2.0](https://trustoverip.github.io/tswg-trust-registry-protocol/approved/)
declines to name a service type, but does bless the VTC→registry indirection:

> "It is RECOMMENDED that the TRQP service endpoint(s) for any authoritative
> trust registry be machine-discoverable via the `authority_id`. An example
> would be to publish either of the following in the DID document for the
> `authority_id`: 1. The authoritative TRQP service endpoint URL(s). 2. The
> DID(s) identifying authoritative trust registries."

DIDComm and TSP bindings of TRQP are named in that spec only as out-of-scope
future work. There is no TRQP metadata endpoint that advertises supported
bindings, so **the DID document is the only capability-discovery surface.**

The ToIP Service Profile struct is `{uri, profile|definition, integrity?}`,
`uri` required, exactly one of `profile`/`definition`, `integrity` an optional
multihash. Its own spec text states "An array of structs is not valid" — so one
service entry per binding, always.

We use `https://trustoverip.org/profiles/trqp/v2` as the profile URI. **The
spec's own example says `.../profiles/trp/v2`** — a leftover from when the
protocol was still called TRP. Neither URI resolves (both 404), so nothing
depends on the choice today; we name the protocol as it is now called. See §7
for the upstream fix that would remove the divergence.

## 2. Trust Registry DID document

Advertises what this process actually serves. One entry per transport.

```json
{
  "@context": [
    "https://www.w3.org/ns/did/v1",
    "https://w3id.org/security/suites/jws-2020/v1",
    "https://trustoverip.org/profile/v2"
  ],
  "id": "did:webvh:QmRegistryScid:registry.example",

  "service": [
    {
      "id": "did:webvh:QmRegistryScid:registry.example#rest",
      "type": ["TRQPRest", "TrustRegistry"],
      "serviceEndpoint": {
        "uri": "https://registry.example",
        "profile": "https://trustoverip.org/profiles/trqp/v2"
      }
    },
    {
      "id": "did:webvh:QmRegistryScid:registry.example#didcomm",
      "type": "DIDCommMessaging",
      "serviceEndpoint": {
        "uri": "did:web:mediator.example",
        "accept": ["didcomm/v2"],
        "routingKeys": []
      }
    },
    {
      "id": "did:webvh:QmRegistryScid:registry.example#tsp",
      "type": "TSPTransport",
      "serviceEndpoint": "did:web:mediator.example"
    }
  ]
}
```

Notes:

- **`#rest`** carries both types via the set form CID 1.0 permits: `TRQPRest`
  for this workspace, `TrustRegistry` for anyone following ToIP. The struct
  endpoint is the ToIP shape. `integrity` is omitted deliberately — an
  unverified multihash is worse than none; add it only when the client
  actually pins and checks it.
- **`#didcomm` / `#tsp`** endpoints are the **mediator DID**, not a URL. The
  transport address lives in the mediator's own document, so consumers resolve
  a second hop. This is existing behaviour, unchanged.
- **No `profile` on `#didcomm` / `#tsp`.** No ToIP profile document exists for
  those bindings. Do not invent a `trustoverip.org` URL that will not resolve;
  self-host one under our own domain if we want capability advertisement there.
- Every entry stays gated on `TransportFlags`, so the document can never claim
  a transport the process does not answer.

## 3. VTC DID document

A VTC does not serve TRQP; it names the registry authoritative for it. Same
type, `uri` holds a **DID** instead of an HTTPS URL. Legal — the ToIP schema is
`{"type":"string","format":"uri"}` and a `did:` string is a valid URI.

```json
{
  "@context": [
    "https://www.w3.org/ns/did/v1",
    "https://trustoverip.org/profile/v2"
  ],
  "id": "did:webvh:QmVtcScid:community.example",

  "service": [
    {
      "id": "did:webvh:QmVtcScid:community.example#trust-registry",
      "type": "TrustRegistry",
      "serviceEndpoint": {
        "uri": "did:webvh:QmRegistryScid:registry.example",
        "profile": "https://trustoverip.org/profiles/trqp/v2"
      }
    },
    {
      "id": "did:webvh:QmVtcScid:community.example#didcomm",
      "type": "DIDCommMessaging",
      "serviceEndpoint": {
        "uri": "did:web:mediator.example",
        "accept": ["didcomm/v2"],
        "routingKeys": []
      }
    }
  ]
}
```

Multiple registries get multiple entries with distinct fragments
(`#trust-registry-eu`, `#trust-registry-apac`) — never an array inside one
`serviceEndpoint`.

## 4. Client resolution rules

`TrustRegistry` means two different things depending on whose document it is
in: an endpoint in the registry's own document, a referral in a VTC's. The
client must disambiguate before parsing capabilities.

1. Resolve the starting DID.
2. For each `TrustRegistry` entry: if `serviceEndpoint.uri` starts with `did:`
   and differs from this document's `id`, it is a **referral**. Otherwise it is
   an **endpoint**.
3. On a referral, resolve that DID once and restart at step 2 against the new
   document. **Cap at one hop** — TRQP's wording assumes the registry document
   holds the endpoints, and chasing chains invites cycles.
4. Parse the resulting document into `ServiceCapabilities` and `select()` a
   transport as today: TSP > DIDComm > HTTPS, no silent downgrade.
5. **Close the loop.** Query the registry and confirm it returns a record whose
   `authority_id` equals the DID we started from.

Step 5 is not optional. A pointer in a VTC's own document is a self-assertion —
anyone can publish a DID document naming any registry. Authority flows
registry → subject, never the reverse. Until the registry confirms, the referral
has told us *where to ask* and nothing about the answer.

The `did:` prefix test in step 2 stays unambiguous because mediator-DID
endpoints always carry `DIDCommMessaging` or `TSPTransport`, never
`TrustRegistry`.

## 5. Changes required in this repo

**`trust-registry/src/didcomm/did_document.rs`**

- `build_services`: emit `#rest` with `type` as the two-element array and the
  `{uri, profile}` struct endpoint. Add a `TRQP_PROFILE_URI` const.
- Test helper `rest_entry` (line ~492) does `s["type"] == REST_SERVICE_TYPE`
  and breaks against an array — switch it to the same set-aware check
  `discovery.rs` already uses.
- `public_url_adds_a_trqp_rest_entry` asserts the endpoint "must be a plain
  string"; update to assert the struct, keeping the trailing-slash trim.

**`trql-client/src/discovery.rs`**

- Add a referral branch **ahead of** the capability parse. Do **not** add
  `TrustRegistry` to `REST_SERVICE_TYPES`: a VTC's referral DID would land in
  `caps.https` and `select()` would hand an HTTPS transport a `did:webvh:`
  string.
- `service_has_type` (line ~221) already handles set-valued `type`;
  `endpoint_uri` (line ~232) already handles string / `{uri}` / array. Both are
  fine as-is.
- Today a `TrustRegistry` entry falls through the unknown-type branch (line
  ~168) and is silently ignored — safe, but not followed.

## 6. Compatibility risk

The `#rest` entry changes on both axes at once: string `type` → array, and
string `serviceEndpoint` → struct. A consumer doing `s["type"] == "TRQPRest"`
or reading `serviceEndpoint` as a string reads the result as **no REST
advertised at all** — a silent capability loss, not a parse error. This is the
R3.4/R3.6 two-sided-contract case from `CLAUDE.md`.

`trql-client` survives both changes. **`vtc-service` and `vta-sdk` must be
audited before this ships.**

If they cannot be updated in lockstep, the zero-breakage path is to leave
`#rest` exactly as it is today and add a fourth entry:

```json
{
  "id": "did:webvh:QmRegistryScid:registry.example#trust-registry",
  "type": "TrustRegistry",
  "serviceEndpoint": {
    "uri": "https://registry.example",
    "profile": "https://trustoverip.org/profiles/trqp/v2"
  }
}
```

Same URL under two types. CID forbids duplicate `id`s, not duplicate
endpoints, and the existing first-entry-of-a-type-wins rule handles it.

## 7. Upstream actions

- Raise on [tswg-trust-registry-protocol](https://github.com/trustoverip/tswg-trust-registry-protocol/issues)
  that TRQP v2 recommends DID-document discoverability without naming a service
  type, and that the Service Profile spec it depends on is still Pre-Draft.
- The ToIP Service Profile example has a JSON syntax error (unterminated
  `"integrity: "`, trailing comma) — worth a PR regardless.
- Same PR should rename the example's profile URI `.../profiles/trp/v2` →
  `.../profiles/trqp/v2`. The protocol has been TRQP since v2; `trp` reads as a
  different, older thing. Until that lands we diverge from the example (§1).
- Registering `TRQPRest`/`TSPTransport` in w3c/did-extensions is the other
  route, but [issue #125](https://github.com/w3c/did-extensions/issues/125)
  argues that registry should not hold service types at all, so the ToIP path
  is likelier to land.
