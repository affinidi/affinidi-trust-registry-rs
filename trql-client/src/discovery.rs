//! Transport discovery from a registry's DID document.
//!
//! A registry advertises the wires it speaks as `service` entries in its DID
//! document. This module turns those entries into a [`ServiceCapabilities`]
//! set and picks the transport to use — the highest-preference protocol
//! **both** sides speak, in the workspace order **TSP > DIDComm > HTTPS**.
//!
//! Two rules the matching deliberately follows:
//!
//! * **Match on service `type`**, never on the `#id` fragment and never on the
//!   endpoint's value shape. A TSP VID is a DID too, so "it looks like a DID,
//!   therefore DIDComm" is wrong. Fragments are arbitrary labels — the OWF
//!   reference TSP implementation names its id `#tsp-transport` while Affinidi
//!   names it `#tsp`, for the same `TSPTransport` type.
//! * **Never silently downgrade** past what the registry advertises. No shared
//!   protocol is a typed [`TrqlError::NoMatchingTransport`], not a quiet
//!   fallback to HTTPS.
//!
//! Resolution itself is the caller's job: this module is pure logic over an
//! already-resolved document, so it needs no resolver dependency and works
//! under any feature combination.
//!
//! ```rust,ignore
//! let doc: serde_json::Value = resolve(registry_did).await?;
//! let caps = ServiceCapabilities::from_document(&doc);
//! let choice = caps.select(TransportKind::compiled())?;
//! match choice.kind {
//!     TransportKind::Https => /* build HttpsTransport with choice.endpoint */,
//!     // TSP/DIDComm endpoints are the registry's *mediator* DID — resolve
//!     // onward for the transport URL, or hand it to an ATM profile.
//!     _ => { /* ... */ }
//! }
//! ```

use serde_json::Value;

use crate::error::TrqlError;
use crate::transport::TransportKind;

/// DID-document service `type` for a TSP transport endpoint.
///
/// `TSPTransport` is the OpenWallet-Foundation-Labs reference-implementation
/// convention; the ToIP TSP spec names no DID-document service type. Kept in
/// sync with `vta_sdk::protocol::matching::TSP_SERVICE_TYPE` and the registry's
/// own `didcomm::did_document::TSP_SERVICE_TYPE`.
pub const TSP_SERVICE_TYPE: &str = "TSPTransport";

/// DID-document service `type` for a DIDComm v2 mediator endpoint (W3C).
pub const DIDCOMM_SERVICE_TYPE: &str = "DIDCommMessaging";

/// DID-document service `type` for a Trust Registry's REST/TRQP surface.
///
/// Names the interface served — TRQP over REST — matching how the sibling
/// types name protocols rather than products.
pub const REST_SERVICE_TYPE: &str = "TRQPRest";

/// A VTA's REST API service `type`.
///
/// Accepted when discovering a peer because a caller may point this client at
/// a VTA-hosted endpoint, and because `vta-sdk` and `vta-service` continue to
/// use it — correctly, for VTAs. A Trust Registry must **not** advertise it:
/// see `trust_registry::didcomm::did_document::REST_SERVICE_TYPE`.
pub const VTA_REST_SERVICE_TYPE: &str = "VTARest";

/// Every service `type` that denotes a REST endpoint, in match order.
///
/// Matching a set rather than one string is what lets a consumer discover both
/// kinds of peer without either having to claim the other's identity.
pub const REST_SERVICE_TYPES: [&str; 2] = [REST_SERVICE_TYPE, VTA_REST_SERVICE_TYPE];

/// Transports in descending preference order: TSP, then DIDComm, then HTTPS.
///
/// TSP is preferred where both sides speak it because it keeps intermediaries
/// blind to routing metadata; HTTPS is the floor.
pub const PREFERENCE_ORDER: [TransportKind; 3] = [
    TransportKind::Tsp,
    TransportKind::Didcomm,
    TransportKind::Https,
];

impl TransportKind {
    /// The DID-document service `type` that advertises this transport.
    #[must_use]
    pub fn service_type(self) -> &'static str {
        match self {
            Self::Tsp => TSP_SERVICE_TYPE,
            Self::Didcomm => DIDCOMM_SERVICE_TYPE,
            Self::Https => REST_SERVICE_TYPE,
        }
    }

    /// Whether this build can actually construct this transport.
    #[must_use]
    pub fn is_compiled(self) -> bool {
        match self {
            Self::Tsp => cfg!(feature = "tsp"),
            Self::Didcomm => cfg!(feature = "didcomm"),
            Self::Https => cfg!(feature = "https"),
        }
    }

    /// The transports compiled into this build, in preference order.
    ///
    /// Selecting against this rather than a hard-coded list means a binary
    /// built without `--features tsp` will not choose TSP and then fail to
    /// construct the transport.
    #[must_use]
    pub fn compiled() -> Vec<TransportKind> {
        PREFERENCE_ORDER
            .into_iter()
            .filter(|k| k.is_compiled())
            .collect()
    }
}

/// The transports a registry advertises, parsed from its DID document by
/// service `type`.
///
/// Each field holds the endpoint to route to for that protocol:
///
/// * `tsp` / `didcomm` — the registry's **mediator DID**, not a transport URL.
///   Both use mediator indirection; the URL lives in the mediator's own DID
///   document, so a second resolution hop is required.
/// * `https` — the registry's REST **base URL**, used directly.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ServiceCapabilities {
    /// Mediator DID advertised for TSP, if any.
    pub tsp: Option<String>,
    /// Mediator DID advertised for DIDComm, if any.
    pub didcomm: Option<String>,
    /// REST base URL advertised, if any.
    pub https: Option<String>,
}

/// The transport chosen for a registry, and where to send.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransportChoice {
    /// The selected binding.
    pub kind: TransportKind,
    /// Where to route: the registry's **mediator DID** for TSP/DIDComm (resolve
    /// onward), its **base URL** for HTTPS.
    pub endpoint: String,
}

impl ServiceCapabilities {
    /// Parse the `service` array of a resolved DID document.
    ///
    /// Unknown service types are ignored, entries missing a usable endpoint are
    /// skipped, and the first entry of each type wins — a document advertising
    /// two DIDComm services is not an error, it just has one preferred.
    #[must_use]
    pub fn from_document(doc: &Value) -> Self {
        let mut caps = Self::default();
        let Some(services) = doc.get("service").and_then(Value::as_array) else {
            return caps;
        };
        for svc in services {
            let Some(uri) = svc.get("serviceEndpoint").and_then(endpoint_uri) else {
                continue;
            };
            if uri.is_empty() {
                continue;
            }
            if service_has_type(svc, TSP_SERVICE_TYPE) {
                caps.tsp.get_or_insert(uri);
            } else if service_has_type(svc, DIDCOMM_SERVICE_TYPE) {
                caps.didcomm.get_or_insert(uri);
            } else if REST_SERVICE_TYPES.iter().any(|t| service_has_type(svc, t)) {
                caps.https.get_or_insert(uri);
            }
        }
        caps
    }

    /// The endpoint advertised for `kind`, if any.
    #[must_use]
    pub fn endpoint(&self, kind: TransportKind) -> Option<&str> {
        match kind {
            TransportKind::Tsp => self.tsp.as_deref(),
            TransportKind::Didcomm => self.didcomm.as_deref(),
            TransportKind::Https => self.https.as_deref(),
        }
    }

    /// Every transport advertised, in preference order.
    #[must_use]
    pub fn advertised(&self) -> Vec<TransportKind> {
        PREFERENCE_ORDER
            .into_iter()
            .filter(|k| self.endpoint(*k).is_some())
            .collect()
    }

    /// Choose the transport to use: the highest-preference one present in both
    /// `ours` and this capability set.
    ///
    /// Returns [`TrqlError::NoMatchingTransport`] carrying both sides' sets
    /// when the intersection is empty, so an operator can see what each side
    /// offers rather than guessing why a query failed.
    pub fn select(&self, ours: &[TransportKind]) -> Result<TransportChoice, TrqlError> {
        for kind in PREFERENCE_ORDER {
            if ours.contains(&kind)
                && let Some(endpoint) = self.endpoint(kind)
            {
                return Ok(TransportChoice {
                    kind,
                    endpoint: endpoint.to_string(),
                });
            }
        }
        Err(TrqlError::NoMatchingTransport {
            ours: ours.to_vec(),
            theirs: self.advertised(),
        })
    }
}

/// Does this service entry carry `type_`?
///
/// `type` may be a string or an array of strings per the DID Core spec.
fn service_has_type(svc: &Value, type_: &str) -> bool {
    match svc.get("type") {
        Some(Value::String(s)) => s == type_,
        Some(Value::Array(arr)) => arr.iter().any(|t| t.as_str() == Some(type_)),
        _ => false,
    }
}

/// Resolve a `serviceEndpoint` to its URI, tolerating the three shapes a DID
/// document may carry it in: a plain string (the TSP/REST convention), an
/// object with a `uri` field (DIDComm v2), or an array of either.
fn endpoint_uri(endpoint: &Value) -> Option<String> {
    match endpoint {
        Value::String(s) => Some(s.clone()),
        Value::Object(map) => map.get("uri")?.as_str().map(str::to_string),
        Value::Array(arr) => arr.iter().find_map(endpoint_uri),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn doc(services: Value) -> Value {
        json!({ "id": "did:webvh:registry.example", "service": services })
    }

    const ALL: [TransportKind; 3] = [
        TransportKind::Tsp,
        TransportKind::Didcomm,
        TransportKind::Https,
    ];

    #[test]
    fn parses_each_service_type() {
        let caps = ServiceCapabilities::from_document(&doc(json!([
            { "id": "#tsp", "type": "TSPTransport", "serviceEndpoint": "did:web:mediator" },
            { "id": "#didcomm", "type": "DIDCommMessaging",
              "serviceEndpoint": { "uri": "did:web:mediator", "accept": ["didcomm/v2"] } },
            { "id": "#rest", "type": "TRQPRest", "serviceEndpoint": "https://registry.example" },
        ])));
        assert_eq!(caps.tsp.as_deref(), Some("did:web:mediator"));
        assert_eq!(caps.didcomm.as_deref(), Some("did:web:mediator"));
        assert_eq!(caps.https.as_deref(), Some("https://registry.example"));
    }

    /// The registry's two DID-document builders emit different endpoint
    /// shapes for the same service, so both must parse identically.
    #[test]
    fn tolerates_string_object_and_array_endpoints() {
        for endpoint in [
            json!("did:web:mediator"),
            json!({ "uri": "did:web:mediator", "accept": ["didcomm/v2"] }),
            json!([{ "uri": "did:web:mediator" }]),
        ] {
            let caps = ServiceCapabilities::from_document(&doc(json!([
                { "id": "#x", "type": "DIDCommMessaging", "serviceEndpoint": endpoint }
            ])));
            assert_eq!(caps.didcomm.as_deref(), Some("did:web:mediator"));
        }
    }

    /// Fragments are arbitrary labels; only `type` decides.
    #[test]
    fn matches_on_type_not_fragment() {
        let caps = ServiceCapabilities::from_document(&doc(json!([
            { "id": "did:x#tsp-transport", "type": "TSPTransport", "serviceEndpoint": "did:web:m" },
            { "id": "did:x#tsp", "type": "TRQPRest", "serviceEndpoint": "https://r.example" },
        ])));
        assert_eq!(caps.tsp.as_deref(), Some("did:web:m"));
        // The `#tsp`-fragmented entry is REST by type, and must be read as such.
        assert_eq!(caps.https.as_deref(), Some("https://r.example"));
    }

    #[test]
    fn type_may_be_an_array() {
        let caps = ServiceCapabilities::from_document(&doc(json!([
            { "id": "#m", "type": ["DIDCommMessaging", "Other"], "serviceEndpoint": "did:web:m" }
        ])));
        assert_eq!(caps.didcomm.as_deref(), Some("did:web:m"));
    }

    #[test]
    fn ignores_unknown_types_empty_and_missing_endpoints() {
        let caps = ServiceCapabilities::from_document(&doc(json!([
            { "id": "#a", "type": "SomethingElse", "serviceEndpoint": "https://x" },
            { "id": "#b", "type": "TRQPRest", "serviceEndpoint": "" },
            { "id": "#c", "type": "TSPTransport" },
            { "id": "#d", "type": "DIDCommMessaging", "serviceEndpoint": 42 },
        ])));
        assert_eq!(caps, ServiceCapabilities::default());
        assert!(caps.advertised().is_empty());
    }

    #[test]
    fn document_without_services_yields_nothing() {
        assert_eq!(
            ServiceCapabilities::from_document(&json!({ "id": "did:x" })),
            ServiceCapabilities::default()
        );
    }

    #[test]
    fn first_entry_of_a_type_wins() {
        let caps = ServiceCapabilities::from_document(&doc(json!([
            { "id": "#r1", "type": "TRQPRest", "serviceEndpoint": "https://first.example" },
            { "id": "#r2", "type": "TRQPRest", "serviceEndpoint": "https://second.example" },
        ])));
        assert_eq!(caps.https.as_deref(), Some("https://first.example"));
    }

    #[test]
    fn selects_the_most_preferred_shared_transport() {
        let caps = ServiceCapabilities {
            tsp: Some("did:web:m".into()),
            didcomm: Some("did:web:m".into()),
            https: Some("https://r.example".into()),
        };
        assert_eq!(caps.select(&ALL).unwrap().kind, TransportKind::Tsp);

        // We don't speak TSP -> next best.
        let choice = caps
            .select(&[TransportKind::Didcomm, TransportKind::Https])
            .unwrap();
        assert_eq!(choice.kind, TransportKind::Didcomm);
        assert_eq!(choice.endpoint, "did:web:m");

        // HTTPS-only client falls to REST and gets the URL, not the mediator.
        let choice = caps.select(&[TransportKind::Https]).unwrap();
        assert_eq!(choice.kind, TransportKind::Https);
        assert_eq!(choice.endpoint, "https://r.example");
    }

    /// A registry that advertises only DIDComm must not be reached over HTTPS
    /// merely because we can speak it — that is a silent downgrade past what
    /// the peer offered.
    #[test]
    fn no_shared_transport_is_a_typed_error_not_a_fallback() {
        let caps = ServiceCapabilities {
            didcomm: Some("did:web:m".into()),
            ..Default::default()
        };
        let err = caps.select(&[TransportKind::Https]).unwrap_err();
        match err {
            TrqlError::NoMatchingTransport { ours, theirs } => {
                assert_eq!(ours, vec![TransportKind::Https]);
                assert_eq!(theirs, vec![TransportKind::Didcomm]);
            }
            other => panic!("expected NoMatchingTransport, got {other:?}"),
        }
    }

    /// A registry advertising nothing is the same failure, and must name that
    /// it advertised nothing rather than blaming the client.
    #[test]
    fn empty_capabilities_report_an_empty_peer_set() {
        let err = ServiceCapabilities::default()
            .select(&ALL)
            .expect_err("no transports advertised");
        match err {
            TrqlError::NoMatchingTransport { theirs, .. } => assert!(theirs.is_empty()),
            other => panic!("expected NoMatchingTransport, got {other:?}"),
        }
    }

    #[test]
    fn no_matching_transport_is_not_retryable() {
        let err = ServiceCapabilities::default().select(&ALL).unwrap_err();
        assert!(!err.is_retryable());
    }

    #[test]
    fn service_types_match_the_workspace_constants() {
        assert_eq!(TransportKind::Tsp.service_type(), "TSPTransport");
        assert_eq!(TransportKind::Didcomm.service_type(), "DIDCommMessaging");
        assert_eq!(TransportKind::Https.service_type(), "TRQPRest");
    }

    /// A registry advertises `TRQPRest`; a VTA advertises `VTARest`. Both are
    /// REST endpoints, and neither has to claim the other's type for a
    /// consumer to find it.
    #[test]
    fn both_rest_type_names_are_discovered() {
        for ty in ["TRQPRest", "VTARest"] {
            let caps = ServiceCapabilities::from_document(&doc(json!([
                { "id": "#rest", "type": ty, "serviceEndpoint": "https://r.example" }
            ])));
            assert_eq!(
                caps.https.as_deref(),
                Some("https://r.example"),
                "{ty} must be recognised as REST"
            );
        }
    }

    #[test]
    fn compiled_transports_are_in_preference_order() {
        let compiled = TransportKind::compiled();
        let expected: Vec<_> = PREFERENCE_ORDER
            .into_iter()
            .filter(|k| compiled.contains(k))
            .collect();
        assert_eq!(compiled, expected);
        // The default feature set always includes HTTPS.
        #[cfg(feature = "https")]
        assert!(compiled.contains(&TransportKind::Https));
    }
}
