# trql-client

A transport-agnostic client for querying a Trust Registry with **TRQP** (the
ToIP Trust Registry Query Protocol): "is this entity authorized, or
recognized, by this authority for this action on this resource?"

Queries travel as Trust Task documents (`registry/authorization` and
`registry/recognition`, version 0.2, falling back to 0.1 for a registry that
answers `unsupportedVersion`), the contract the
[Affinidi Trust Registry](https://github.com/affinidi/affinidi-trust-registry-rs)
serves over HTTPS, DIDComm and TSP. The name `trql` is only this crate's name;
the protocol is TRQP.

## Transports (Cargo features)

| Feature | Transport | Wire |
|---|---|---|
| `https` (default) | `HttpsTransport` | `POST <registry>/trust-tasks` (`trust-tasks-https`) |
| `didcomm` | `DidcommTransport` | `trust-tasks-didcomm` envelope through an ATM mediator |
| `tsp` | `TspTransport` | `trust-tasks-tsp` envelope in a TSP `Direct` message, on the same mediator websocket |

`ServiceCapabilities::from_document` reads the transports a registry advertises
in its DID document, and `select` picks the most preferred one both sides speak
(TSP, then DIDComm, then HTTPS), never silently falling back to one the
registry did not advertise.

## Example

```rust
use std::sync::Arc;
use trql_client::{HttpsTransport, HttpsTransportConfig, TrqlClient, TrqpQuery};

let transport = HttpsTransport::new(HttpsTransportConfig::new("https://registry.example.com"))?;
let client = TrqlClient::new(Arc::new(transport), "did:webvh:...registry");

let answer = client
    .authorization(TrqpQuery::new(
        "did:webvh:...signer",    // entity
        "did:webvh:...authority", // authority
        "git.commit.sign",        // action
        "openvtc",                // resource
    ))
    .await?;
if answer.authorized {
    // ...
}
```

A registry with no matching record answers `authorized: false`: absence is a
denial, not an error.

## What the client checks

It fails closed: an answer is returned only when the reply

- is correlated to the request (`threadId` equals the request `id`);
- comes from the registry the request was addressed to (the TLS server over
  HTTPS, an authcrypt key of the registry DID over DIDComm, the verified
  sender VID over TSP); a correlated reply from anyone else is ignored and the
  query keeps waiting for the registry;
- over HTTPS, agrees with the status: an error status never carries an
  answer;
- answers the question asked: the same entity, authority, action and
  resource and, for a query made with `TrqpQuery::at(time)`, the same
  evaluation time;
- parses as the spec's response.

A registry refusal arrives as `TrqlError::Rejected` with its machine-readable
code. `TrqlError::is_retryable` says whether trying again can help.

## Following a referral

A VTC's DID document may name the registry authoritative for it in a
`TrustRegistry` service (`registry_referral`). A referral is a self-assertion,
so follow at most one hop, and build the client with
`TrqlClient::referred_by(vtc_did)`: an answer for any authority other than the
VTC that referred you is then refused (`TrqlError::ReferralNotClosed`).

## HTTPS defaults

`HttpsTransport` requires `https` (plain `http` only to a loopback host),
follows no redirects, caps the reply at 64 KiB and connects only to public
addresses. Set `HttpsTransportConfig::with_allow_non_public_addresses(true)`
only for a registry URL you configured yourself, never for one taken from a
DID document you do not control.

## DIDComm and TSP

Give each mediator transport an `ATMProfile` of its own, with a mediator and
websocket live delivery enabled: the transport owns the profile's inbound
stream and deletes what it cannot use. If that stream fails repeatedly, or the
transport's reply-routing task stops, queries fail at once with
`TrqlError::Transport` naming the cause rather than waiting out the 60-second
reply window; `inbound_error()` reports the same.

## License

Apache-2.0
