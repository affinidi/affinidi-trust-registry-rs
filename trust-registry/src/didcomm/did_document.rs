use crate::configs::ProfileConfig;
use serde_json::Value;

pub fn build_public_jwk(jwk: &affinidi_tdk::affinidi_crypto::JWK) -> serde_json::Value {
    match &jwk.params {
        affinidi_tdk::affinidi_crypto::Params::EC(params) => {
            let mut jwk_obj = serde_json::json!({
                "kty": "EC",
                "crv": params.curve,
                "x": params.x,
                "y": params.y,
            });
            if let Some(kid) = &jwk.key_id {
                jwk_obj["kid"] = serde_json::json!(kid);
            }
            jwk_obj
        }
        affinidi_tdk::affinidi_crypto::Params::OKP(params) => {
            let mut jwk_obj = serde_json::json!({
                "kty": "OKP",
                "crv": params.curve,
                "x": params.x,
            });
            if let Some(kid) = &jwk.key_id {
                jwk_obj["kid"] = serde_json::json!(kid);
            }
            jwk_obj
        }
        // The `Params` enum is non-exhaustive upstream (e.g. RSA, symmetric).
        // The Trust Registry only publishes EC/OKP verification methods, so any
        // other key type is not representable here.
        _ => serde_json::json!({}),
    }
}

pub fn build_verification_methods(profile_config: &ProfileConfig) -> Vec<serde_json::Value> {
    profile_config
        .secrets
        .iter()
        .enumerate()
        .map(|(index, secret)| {
            let public_jwk = match &secret.secret_material {
                affinidi_tdk::secrets_resolver::secrets::SecretMaterial::JWK(jwk) => {
                    build_public_jwk(jwk)
                }
                _ => serde_json::json!({}),
            };

            serde_json::json!({
                "id": format!("{}#key-{}", profile_config.did, index),
                "type": "JsonWebKey2020",
                "controller": profile_config.did,
                "publicKeyJwk": public_jwk,
            })
        })
        .collect()
}

/// DID-document service `type` for the Trust Registry's REST/TRQP surface.
///
/// `TRQPRest` names the interface actually served — TRQP over REST — matching
/// how the sibling types `TSPTransport` and `DIDCommMessaging` name protocols
/// rather than products. Any TRQP-compliant registry can advertise it.
///
/// Deliberately **not** `VTARest`. That type belongs to a VTA's REST API and
/// remains correct there; a Trust Registry is not a VTA, and claiming that
/// type would tell a consumer it can expect a VTA's endpoints. No legacy
/// alias is carried because the registry has never advertised a REST service
/// before — there is no deployed DID document to stay compatible with.
///
/// Consumers must match this in addition to `VTARest`, not instead of it:
/// see `vta_sdk::protocol::matching::REST_SERVICE_TYPES`.
pub const REST_SERVICE_TYPE: &str = "TRQPRest";

/// DID-document service `type` for the DIDComm v2 mediator endpoint.
pub const DIDCOMM_SERVICE_TYPE: &str = "DIDCommMessaging";

/// Fragment for the DIDComm service entry. Consumers match on `type`, never
/// on the fragment (it is an arbitrary label), but keeping one value across
/// both builders in this repo avoids two DID documents that describe the same
/// registry differently.
pub const DIDCOMM_SERVICE_FRAGMENT: &str = "#didcomm";

/// Fragment for the REST service entry.
pub const REST_SERVICE_FRAGMENT: &str = "#rest";

/// DID-document service `type` from the [ToIP Trust Registry Service
/// Profile][profile] — the cross-ecosystem name for "a TRQP surface lives
/// here", where `TRQPRest` is this workspace's own.
///
/// Advertised **in addition to** `TRQPRest`, on its own entry rather than as a
/// second `type` on `#rest`. Adding it to `#rest` would change that entry on
/// two axes at once — string `type` → array, string `serviceEndpoint` →
/// struct — and a consumer doing `s["type"] == "TRQPRest"` or reading the
/// endpoint as a string would read the result as *no REST advertised at all*:
/// a silent capability loss rather than a parse error (R3.4/R3.6). A separate
/// entry is additive by construction, so no existing consumer can regress.
///
/// [profile]: https://github.com/trustoverip/tswg-trust-registry-service-profile/blob/main/spec.md
pub const TRUST_REGISTRY_SERVICE_TYPE: &str = "TrustRegistry";

/// Fragment for the ToIP-profile Trust Registry service entry.
pub const TRUST_REGISTRY_SERVICE_FRAGMENT: &str = "#trust-registry";

/// The TRQP service profile a `TrustRegistry` entry declares conformance to.
///
/// Spelled `trqp`, not the `trp` the ToIP Service Profile spec's own example
/// carries — that spelling predates the protocol's rename to TRQP.
pub const TRQP_PROFILE_URI: &str = "https://trustoverip.org/profiles/trqp/v2";

/// DID-document service `type` for a TSP transport endpoint. Matches
/// `vta_sdk::protocol::matching::TSP_SERVICE_TYPE`.
pub const TSP_SERVICE_TYPE: &str = "TSPTransport";

/// Fragment for the TSP service entry.
pub const TSP_SERVICE_FRAGMENT: &str = "#tsp";

/// Which transports the registry serves, and therefore advertises.
///
/// One flag per protocol governs **both** halves — whether the listener runs
/// and whether the DID document carries the service entry — so the served
/// document can never claim a transport the process does not answer. Both DID
/// document builders (the runtime [`build_services`] and the `setup_trust_registry`
/// binary) take this same struct for the same reason: two builders reading two
/// sets of environment variables is how they drifted apart before.
///
/// REST is on by default: it is the transport a registry can always serve, and
/// it needs no mediator.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TransportFlags {
    /// Serve TRQP over REST, and advertise `TRQPRest` when a public URL is set.
    pub rest: bool,
    /// Run the DIDComm listener, and advertise `DIDCommMessaging`.
    pub didcomm: bool,
    /// Route multiplexed TSP frames, and advertise `TSPTransport`.
    pub tsp: bool,
}

impl Default for TransportFlags {
    fn default() -> Self {
        Self {
            rest: true,
            didcomm: true,
            tsp: false,
        }
    }
}

impl TransportFlags {
    /// Reject combinations the registry cannot honour.
    ///
    /// Each rule exists because the alternative is a registry that advertises a
    /// transport nothing answers — the failure this struct was introduced to
    /// prevent.
    pub fn validate(&self) -> Result<(), String> {
        if !self.rest && !self.didcomm && !self.tsp {
            return Err(
                "at least one transport must be enabled: set ENABLE_REST, ENABLE_DIDCOMM \
                 or ENABLE_TSP to 'true' (a registry with no transport can serve nobody)"
                    .to_string(),
            );
        }
        // TSP frames arrive multiplexed on the DIDComm pickup socket — the
        // mediator permits one websocket per DID, so there is no TSP-only
        // receive loop to fall back on.
        if self.tsp && !self.didcomm {
            return Err(
                "ENABLE_TSP=true requires ENABLE_DIDCOMM=true: TSP frames are multiplexed \
                 on the DIDComm mediator socket and cannot be received without it"
                    .to_string(),
            );
        }
        // A runtime flag cannot conjure the compiled-out TSP binding.
        if self.tsp && !cfg!(feature = "tsp") {
            return Err(
                "ENABLE_TSP=true requires a binary built with `--features tsp`; this build \
                 cannot serve TSP and must not advertise it"
                    .to_string(),
            );
        }
        Ok(())
    }
}

/// Reject a public URL the registry should not advertise.
///
/// Mirrors `vtc-service`'s `validate_registry_scheme` exactly: consumers
/// reject a cleartext registry URL as spoofable by an on-path attacker, so
/// advertising one would publish an endpoint the other side refuses to use.
/// Loopback `http://` stays allowed for local development.
pub fn validate_public_url(url: &str) -> Result<(), String> {
    if url.starts_with("https://") {
        return Ok(());
    }
    if let Some(rest) = url.strip_prefix("http://") {
        let host = rest.split(['/', ':', '?']).next().unwrap_or("");
        if host == "localhost" || host == "127.0.0.1" || rest.starts_with("[::1]") {
            return Ok(());
        }
    }
    Err(format!(
        "TR_PUBLIC_URL must be https:// (got '{url}'); cleartext TRQP is spoofable by an \
         on-path attacker. http:// is allowed only to loopback for local dev."
    ))
}

/// Build the service array for a Trust Registry DID document.
///
/// Every entry is gated on the matching [`TransportFlags`] field, so the
/// document advertises exactly the transports this process serves. REST carries
/// the additional condition of a non-empty `public_url`: `ENABLE_REST=true`
/// still serves the HTTP routes, but with nowhere externally reachable to point
/// at there is nothing honest to advertise (the bind address in
/// `LISTEN_ADDRESS` is not necessarily reachable, and is often `0.0.0.0`).
///
/// The DIDComm and TSP `serviceEndpoint`s carry the **mediator DID**, not a
/// URL: the transport URL lives in the mediator's own DID document. REST
/// carries a URL directly, since there is no indirection.
pub fn build_services(
    did: &str,
    mediator_did: &str,
    public_url: Option<&str>,
    flags: TransportFlags,
) -> Vec<Value> {
    let mut services = Vec::new();

    if flags.didcomm {
        services.push(serde_json::json!({
            "id": format!("{did}{DIDCOMM_SERVICE_FRAGMENT}"),
            "type": DIDCOMM_SERVICE_TYPE,
            "serviceEndpoint": {
                "uri": mediator_did,
                "accept": ["didcomm/v2"],
                "routingKeys": []
            }
        }));
    }

    if flags.rest
        && let Some(url) = public_url.map(str::trim).filter(|u| !u.is_empty())
    {
        let url = url.trim_end_matches('/');

        // Plain-string endpoint, matching the VTA's REST entry. Consumers
        // tolerate string / {uri} / array forms, but the string form is what
        // the rest of the workspace emits for REST.
        services.push(serde_json::json!({
            "id": format!("{did}{REST_SERVICE_FRAGMENT}"),
            "type": REST_SERVICE_TYPE,
            "serviceEndpoint": url,
        }));

        // The same surface under the ToIP profile's type, so a consumer that
        // knows only `TrustRegistry` can find us. Separate entry, not a second
        // `type` on `#rest` — see [`TRUST_REGISTRY_SERVICE_TYPE`] for why
        // changing that entry in place would be a silent capability loss.
        //
        // Two entries pointing at one URL is legal: CID 1.0 requires unique
        // service `id`s, not unique endpoints, and a consumer taking the first
        // entry of each type reaches the same place either way.
        services.push(serde_json::json!({
            "id": format!("{did}{TRUST_REGISTRY_SERVICE_FRAGMENT}"),
            "type": TRUST_REGISTRY_SERVICE_TYPE,
            "serviceEndpoint": {
                "uri": url,
                "profile": TRQP_PROFILE_URI,
            },
        }));
    }

    if flags.tsp {
        services.push(serde_json::json!({
            "id": format!("{did}{TSP_SERVICE_FRAGMENT}"),
            "type": TSP_SERVICE_TYPE,
            "serviceEndpoint": mediator_did,
        }));
    }

    services
}

pub fn build_did_document(
    profile_config: &ProfileConfig,
    mediator_did: &str,
    public_url: Option<&str>,
    flags: TransportFlags,
) -> String {
    let verification_methods = build_verification_methods(profile_config);

    let key_refs: Vec<String> = (0..profile_config.secrets.len())
        .map(|index| format!("{}#key-{}", profile_config.did, index))
        .collect();

    serde_json::json!({
        "@context": [
            "https://www.w3.org/ns/did/v1",
            "https://w3id.org/security/suites/jws-2020/v1"
        ],
        "id": profile_config.did,
        "verificationMethod": verification_methods,
        "authentication": key_refs,
        "assertionMethod": key_refs,
        "keyAgreement": key_refs,
        "service": build_services(&profile_config.did, mediator_did, public_url, flags)
    })
    .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use affinidi_tdk::{affinidi_crypto::JWK, secrets_resolver::secrets::Secret};
    use serde_json::json;

    #[test]
    fn test_build_public_jwk_ec() {
        // Create a test EC JWK and verify d field is removed
        let jwk: JWK = serde_json::from_value(json!({
          "crv": "P-256",
          "kty": "EC",
          "x": "DEtsdJXfi7IuqaZFkRW_aBwHHpID1jQjPqN_Y46zlZM",
          "y": "LQs6Q-gGqgtrUW2iEfb9YRyvPAuNALceHqGYs4sNwh4",
          "d": "private part"
        }))
        .unwrap();
        let result = build_public_jwk(&jwk);

        assert_eq!(result["kty"], "EC");
        assert!(result.get("x").is_some());
        assert!(result.get("y").is_some());
        assert!(result.get("d").is_none()); // Private key removed
    }

    #[test]
    fn test_build_public_jwk_okp() {
        // Create a test OKP JWK

        let jwk: JWK = serde_json::from_value(json!({
            "crv": "Ed25519",
            "kty": "OKP",
            "x": "DfRiO5mCASvWyPxr20GQEfzOmFFh50spyP7KHMjvGQo",
            "d": "private part"
        }))
        .unwrap();
        let result = build_public_jwk(&jwk);

        assert_eq!(result["kty"], "OKP");
        assert!(result.get("x").is_some());
        assert!(result.get("d").is_none()); // Private key removed
    }

    #[test]
    fn test_build_verification_methods_single_key() {
        let secret: Secret = serde_json::from_value(json!({
            "id": "did:web:example.com#key-0",
            "type": "JsonWebKey2020",
            "privateKeyJwk": {
                "crv": "P-256",
                // not real, just copy of x
                "d": "ctKLNB9cXUO3yD-jMCaRi680RmHOFuS30nVogmEhkx4",
                "kty": "EC",
                "x": "ctKLNB9cXUO3yD-jMCaRi680RmHOFuS30nVogmEhkx4",
                "y": "1GDFw4zkTPdVWwqxRhSnEVCdkZyfmViJR8Nq5ad2V9w"
            }
        }))
        .unwrap();

        let profile = ProfileConfig {
            did: "did:web:example.com".to_string(),
            alias: "test".to_string(),
            secrets: vec![secret],
        };

        let methods = build_verification_methods(&profile);
        assert_eq!(methods.len(), 1);
        assert_eq!(methods[0]["id"], "did:web:example.com#key-0");
        assert_eq!(methods[0]["type"], "JsonWebKey2020");
        assert_eq!(methods[0]["controller"], "did:web:example.com");
        assert_eq!(methods[0]["publicKeyJwk"]["kty"], "EC");
        assert_eq!(methods[0]["publicKeyJwk"]["crv"], "P-256");
        assert!(methods[0]["publicKeyJwk"].get("d").is_none());
    }

    #[test]
    fn test_build_verification_methods_multiple_keys() {
        let secret1: Secret = serde_json::from_value(json!({
            "id": "did:web:example.com#key-0",
            "type": "JsonWebKey2020",
            "privateKeyJwk": {
                "crv": "P-256",
                // not real, just copy of x
                "d": "ctKLNB9cXUO3yD-jMCaRi680RmHOFuS30nVogmEhkx4",
                "kty": "EC",
                "x": "ctKLNB9cXUO3yD-jMCaRi680RmHOFuS30nVogmEhkx4",
                "y": "1GDFw4zkTPdVWwqxRhSnEVCdkZyfmViJR8Nq5ad2V9w"
            }
        }))
        .unwrap();

        let secret2: Secret = serde_json::from_value(json!({
            "id": "did:web:example.com#key-1",
            "type": "JsonWebKey2020",
            "privateKeyJwk": {
                "crv": "secp256k1",
                // not real, just copy of x
                "d": "rJcdID8WLUt3Fby5ZsVgyVtrkaEXv050hISLxwY5RrI",
                "kty": "EC",
                "x": "rJcdID8WLUt3Fby5ZsVgyVtrkaEXv050hISLxwY5RrI",
                "y": "eKiDGeJExattkEmEBbOBOBuzvCB9YnfFaZ6xMzYpIMM"
            }
        }))
        .unwrap();

        let secret3: Secret = serde_json::from_value(json!({
            "id": "did:web:example.com#key-2",
            "type": "JsonWebKey2020",
            "privateKeyJwk": {
                "crv": "Ed25519",
                // not real, just copy of x
                "d": "DfRiO5mCASvWyPxr20GQEfzOmFFh50spyP7KHMjvGQo",
                "kty": "OKP",
                "x": "DfRiO5mCASvWyPxr20GQEfzOmFFh50spyP7KHMjvGQo"
            }
        }))
        .unwrap();

        let profile = ProfileConfig {
            did: "did:web:example.com".to_string(),
            alias: "test".to_string(),
            secrets: vec![secret1, secret2, secret3],
        };

        let methods = build_verification_methods(&profile);
        assert_eq!(methods.len(), 3);
        assert_eq!(methods[0]["id"], "did:web:example.com#key-0");
        assert_eq!(methods[1]["id"], "did:web:example.com#key-1");
        assert_eq!(methods[2]["id"], "did:web:example.com#key-2");

        // Verify all are JsonWebKey2020
        assert_eq!(methods[0]["type"], "JsonWebKey2020");
        assert_eq!(methods[1]["type"], "JsonWebKey2020");
        assert_eq!(methods[2]["type"], "JsonWebKey2020");

        // Verify all have controller set
        assert_eq!(methods[0]["controller"], "did:web:example.com");
        assert_eq!(methods[1]["controller"], "did:web:example.com");
        assert_eq!(methods[2]["controller"], "did:web:example.com");

        // Verify no private keys
        assert!(methods[0]["publicKeyJwk"].get("d").is_none());
        assert!(methods[1]["publicKeyJwk"].get("d").is_none());
        assert!(methods[2]["publicKeyJwk"].get("d").is_none());
    }

    #[test]
    fn test_build_did_document_structure() {
        let profile = ProfileConfig {
            did: "did:web:localhost%3A3232".to_string(),
            alias: "local-test".to_string(),
            secrets: vec![/* test secret */],
        };

        let doc = build_did_document(
            &profile,
            "did:web:mediator.example.com",
            None,
            TransportFlags::default(),
        );
        let parsed: serde_json::Value = serde_json::from_str(&doc).unwrap();

        assert_eq!(parsed["id"], "did:web:localhost%3A3232");
        assert!(parsed["@context"].is_array());
        assert!(parsed["verificationMethod"].is_array());
        assert!(parsed["authentication"].is_array());
        assert!(parsed["assertionMethod"].is_array());
        assert!(parsed["keyAgreement"].is_array());
        assert!(parsed["service"].is_array());
    }

    #[test]
    fn test_did_document_didcomm_service() {
        let profile = ProfileConfig {
            did: "did:web:example.com".to_string(),
            alias: "test".to_string(),
            secrets: vec![],
        };

        let doc = build_did_document(
            &profile,
            "did:web:mediator.com",
            None,
            TransportFlags::default(),
        );
        let parsed: serde_json::Value = serde_json::from_str(&doc).unwrap();

        let service = &parsed["service"][0];
        assert_eq!(service["type"], "DIDCommMessaging");
        assert_eq!(service["serviceEndpoint"]["uri"], "did:web:mediator.com");
        assert_eq!(service["serviceEndpoint"]["accept"][0], "didcomm/v2");
    }

    const DID: &str = "did:web:registry.example";
    const MEDIATOR: &str = "did:web:mediator.example";

    fn rest_entry(services: &[Value]) -> Option<&Value> {
        services.iter().find(|s| s["type"] == REST_SERVICE_TYPE)
    }

    /// Without a public URL the registry must not claim REST — a peer that
    /// selected it would route to nothing.
    #[test]
    fn no_public_url_advertises_didcomm_only() {
        let services = build_services(DID, MEDIATOR, None, TransportFlags::default());
        assert_eq!(services.len(), 1);
        assert_eq!(services[0]["type"], DIDCOMM_SERVICE_TYPE);
        assert!(rest_entry(&services).is_none());
    }

    /// An empty or whitespace-only value is "unset", not "advertise an empty
    /// endpoint" — absence means the restrictive reading.
    #[test]
    fn blank_public_url_is_treated_as_absent() {
        for blank in ["", "   ", "\t\n"] {
            let services = build_services(DID, MEDIATOR, Some(blank), TransportFlags::default());
            assert!(
                rest_entry(&services).is_none(),
                "blank {blank:?} must not advertise REST"
            );
        }
    }

    /// The REST entry is what makes DID-only linking possible, so assert its
    /// exact wire shape: a plain-string endpoint and the `TRQPRest` type that
    /// consumers match on for a Trust Registry.
    ///
    /// Pinned deliberately. Every deployed consumer reads this entry, and the
    /// ToIP-profile surface is advertised as a *separate* entry precisely so
    /// this one never has to change shape — see
    /// [`trust_registry_entry_is_additive_and_leaves_rest_untouched`].
    #[test]
    fn public_url_adds_a_trqp_rest_entry() {
        let services = build_services(
            DID,
            MEDIATOR,
            Some("https://registry.example"),
            TransportFlags::default(),
        );
        assert_eq!(services.len(), 3, "didcomm + rest + trust-registry");

        let rest = rest_entry(&services).expect("REST entry");
        assert_eq!(rest["type"], "TRQPRest");
        // A Trust Registry must never claim to be a VTA REST endpoint.
        assert_ne!(rest["type"], "VTARest");
        assert_eq!(rest["id"], format!("{DID}#rest"));
        assert_eq!(
            rest["serviceEndpoint"],
            Value::String("https://registry.example".into()),
            "REST endpoint must be a plain string, not the DIDComm object form"
        );
    }

    /// The ToIP-profile entry rides alongside `#rest` rather than replacing or
    /// re-typing it.
    ///
    /// Folding `TrustRegistry` into `#rest` would change that entry on two
    /// axes at once — string `type` → array, string endpoint → struct — and a
    /// consumer matching `s["type"] == "TRQPRest"` or reading the endpoint as
    /// a string would see *no REST advertised*: a silent capability loss, not
    /// a parse error (R3.4/R3.6). Additive cannot regress anyone.
    #[test]
    fn trust_registry_entry_is_additive_and_leaves_rest_untouched() {
        let services = build_services(
            DID,
            MEDIATOR,
            Some("https://registry.example/"),
            TransportFlags::default(),
        );

        let rest = rest_entry(&services).expect("REST entry");
        assert!(
            rest["type"].is_string(),
            "#rest keeps its string type: {}",
            rest["type"]
        );
        assert!(
            rest["serviceEndpoint"].is_string(),
            "#rest keeps its string endpoint: {}",
            rest["serviceEndpoint"]
        );

        let profile = services
            .iter()
            .find(|s| s["type"] == TRUST_REGISTRY_SERVICE_TYPE)
            .expect("TrustRegistry entry");
        assert_eq!(profile["id"], format!("{DID}#trust-registry"));
        assert_eq!(
            profile["serviceEndpoint"]["uri"], "https://registry.example",
            "same surface as #rest, trailing slash trimmed alike"
        );
        assert_eq!(profile["serviceEndpoint"]["profile"], TRQP_PROFILE_URI);
    }

    /// A registry's own `TrustRegistry` entry describes its surface; it is not
    /// a referral, so a client must not hop away from this document.
    ///
    /// The distinguishing test a consumer applies is whether the endpoint URI
    /// is a DID — ours is a URL, and must stay one.
    #[test]
    fn the_trust_registry_entry_is_an_endpoint_not_a_referral() {
        let services = build_services(
            DID,
            MEDIATOR,
            Some("https://registry.example"),
            TransportFlags::default(),
        );
        let profile = services
            .iter()
            .find(|s| s["type"] == TRUST_REGISTRY_SERVICE_TYPE)
            .expect("TrustRegistry entry");
        let uri = profile["serviceEndpoint"]["uri"].as_str().unwrap();
        assert!(
            !uri.starts_with("did:"),
            "a registry advertises where it serves, never another DID: {uri}"
        );
    }

    /// A trailing slash would make consumers build `https://host//recognition`.
    #[test]
    fn public_url_trailing_slash_is_trimmed() {
        let services = build_services(
            DID,
            MEDIATOR,
            Some("https://registry.example/"),
            TransportFlags::default(),
        );
        assert_eq!(
            rest_entry(&services).unwrap()["serviceEndpoint"],
            Value::String("https://registry.example".into())
        );
    }

    /// Both builders in this repo must spell the DIDComm fragment the same
    /// way; the setup binary previously used `#service`.
    #[test]
    fn didcomm_fragment_is_stable() {
        let services = build_services(DID, MEDIATOR, None, TransportFlags::default());
        assert_eq!(services[0]["id"], format!("{DID}#didcomm"));
    }

    /// Advertising cleartext publishes an endpoint consumers reject outright
    /// (vtc-service refuses a non-https registry URL), so fail early.
    #[test]
    fn cleartext_public_url_is_rejected() {
        assert!(validate_public_url("http://registry.example").is_err());
        assert!(validate_public_url("ftp://registry.example").is_err());
        assert!(validate_public_url("registry.example").is_err());
    }

    #[test]
    fn https_and_loopback_public_urls_are_accepted() {
        assert!(validate_public_url("https://registry.example").is_ok());
        assert!(validate_public_url("http://localhost:3232").is_ok());
        assert!(validate_public_url("http://127.0.0.1:3232").is_ok());
        assert!(validate_public_url("http://[::1]:3232").is_ok());
    }

    /// `http://localhost.evil.com` must not pass by prefix match.
    #[test]
    fn loopback_exception_does_not_leak_to_lookalike_hosts() {
        assert!(validate_public_url("http://localhost.evil.com").is_err());
        assert!(validate_public_url("http://127.0.0.1.evil.com").is_err());
    }

    // --- TransportFlags -------------------------------------------------
    //
    // `validate()` is exercised directly rather than `from_env()`: the latter
    // mutates process-global state and would race with every other test in
    // this binary.

    fn types_of(services: &[Value]) -> Vec<&str> {
        services.iter().filter_map(|s| s["type"].as_str()).collect()
    }

    /// REST on, everything else off — the default posture for a registry with
    /// no mediator. Nothing DIDComm-shaped may appear.
    ///
    /// Both REST entries are the one transport under two type names, so the
    /// flag still governs: turning REST off drops both.
    #[test]
    fn rest_only_advertises_rest_only() {
        let flags = TransportFlags {
            rest: true,
            didcomm: false,
            tsp: false,
        };
        let services = build_services(DID, MEDIATOR, Some("https://registry.example"), flags);
        assert_eq!(
            types_of(&services),
            vec![REST_SERVICE_TYPE, TRUST_REGISTRY_SERVICE_TYPE]
        );
    }

    /// Disabling REST must drop the entry even when TR_PUBLIC_URL is set —
    /// the flag governs, not the presence of a URL.
    #[test]
    fn rest_disabled_suppresses_entry_despite_public_url() {
        let flags = TransportFlags {
            rest: false,
            didcomm: true,
            tsp: false,
        };
        let services = build_services(DID, MEDIATOR, Some("https://registry.example"), flags);
        assert_eq!(types_of(&services), vec![DIDCOMM_SERVICE_TYPE]);
    }

    /// The bug this struct exists to prevent: TSP was serviceable but the
    /// runtime builder never emitted the entry, so no client could select it.
    #[test]
    fn tsp_enabled_advertises_tsp_at_the_mediator_did() {
        let flags = TransportFlags {
            rest: false,
            didcomm: true,
            tsp: true,
        };
        let services = build_services(DID, MEDIATOR, None, flags);
        let tsp = services
            .iter()
            .find(|s| s["type"] == TSP_SERVICE_TYPE)
            .expect("TSP entry");
        assert_eq!(tsp["id"], format!("{DID}#tsp"));
        assert_eq!(
            tsp["serviceEndpoint"],
            Value::String(MEDIATOR.into()),
            "TSP endpoint is the mediator DID, mirroring DIDComm's indirection"
        );
    }

    #[test]
    fn default_is_rest_and_didcomm_without_tsp() {
        let flags = TransportFlags::default();
        assert!(flags.rest && flags.didcomm && !flags.tsp);
        assert!(flags.validate().is_ok());
    }

    /// A registry serving no transport can answer nobody; fail at startup
    /// rather than run as an unreachable process.
    #[test]
    fn no_transport_enabled_is_rejected() {
        let flags = TransportFlags {
            rest: false,
            didcomm: false,
            tsp: false,
        };
        assert!(flags.validate().is_err());
    }

    /// TSP frames are multiplexed on the DIDComm pickup socket, so TSP without
    /// DIDComm has no socket to arrive on.
    #[test]
    fn tsp_without_didcomm_is_rejected() {
        let flags = TransportFlags {
            rest: true,
            didcomm: false,
            tsp: true,
        };
        let err = flags.validate().expect_err("TSP requires DIDComm");
        assert!(err.contains("ENABLE_DIDCOMM"), "unhelpful error: {err}");
    }

    /// A runtime flag cannot enable a compiled-out binding. Asserted in both
    /// directions so the rule is covered whichever way the suite is built.
    #[test]
    fn tsp_requires_the_tsp_build_feature() {
        let flags = TransportFlags {
            rest: true,
            didcomm: true,
            tsp: true,
        };
        if cfg!(feature = "tsp") {
            assert!(flags.validate().is_ok());
        } else {
            let err = flags.validate().expect_err("no tsp feature compiled in");
            assert!(err.contains("--features tsp"), "unhelpful error: {err}");
        }
    }
}
