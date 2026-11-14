use crate::configs::ProfileConfig;
use affinidi_tdk::secrets_resolver::secrets::{KeyType, Secret};
use serde_json::Value;

/// The JSON-LD contexts of a Trust Registry DID document: DID core and the
/// Multikey verification-method type every key is published as.
pub const DID_DOCUMENT_CONTEXT: [&str; 2] = [
    "https://www.w3.org/ns/did/v1",
    "https://w3id.org/security/multikey/v1",
];

/// The verification-method `type` both DID document builders publish.
pub const VERIFICATION_METHOD_TYPE: &str = "Multikey";

/// What a key may be used for, which decides the verification relationships
/// it is listed under.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyPurpose {
    /// A signing key: `authentication` and `assertionMethod`.
    Signing,
    /// A key-agreement key: `keyAgreement`.
    KeyAgreement,
    /// An EC key (P-256, secp256k1), which can do both: `authentication` and
    /// `assertionMethod`, and also `keyAgreement` when the profile has no
    /// X25519 key. Profiles from before the move to Curve25519 hold only EC
    /// keys and authcrypt with them; listing none under `keyAgreement` would
    /// leave peers no key to encrypt to.
    SigningOrAgreement,
}

/// The purpose a key of `key_type` serves, or `None` when the registry does
/// not publish keys of that type.
///
/// Ed25519 signs; X25519 agrees keys; P-256 and secp256k1 can do both. An
/// X25519 key under `authentication`, or an Ed25519 key under `keyAgreement`,
/// would let a peer pick a key that cannot perform the operation.
pub fn key_purpose(key_type: KeyType) -> Option<KeyPurpose> {
    match key_type {
        KeyType::Ed25519 => Some(KeyPurpose::Signing),
        KeyType::P256 | KeyType::Secp256k1 => Some(KeyPurpose::SigningOrAgreement),
        KeyType::X25519 => Some(KeyPurpose::KeyAgreement),
        _ => None,
    }
}

/// The verification-method id of `secret` in `did`'s document: the secret's
/// own id, made absolute when it is a bare `#fragment`.
///
/// The registry signs and authcrypts under the secret's id, so the published
/// document must carry exactly that id. An id invented here (e.g. by
/// position) names a key a peer cannot find, or the wrong one.
fn verification_method_id(did: &str, secret: &Secret) -> Result<String, String> {
    let id = secret.id.trim();
    if id.starts_with('#') && id.len() > 1 {
        Ok(format!("{did}{id}"))
    } else if let Some((id_did, _)) = id.split_once('#')
        && id_did.starts_with("did:")
    {
        // A did:scid profile DID carries `?src=`; its keys are under the bare
        // DID (VTI-KEY-161), which is the same identity.
        let bare = did.split_once('?').map_or(did, |(d, _)| d);
        if id_did != did && id_did != bare {
            tracing::warn!(
                "secret id {id} names {id_did}, not the profile's DID {did}: peers resolving \
                 {did} will not find this key under that id"
            );
        }
        Ok(id.to_string())
    } else {
        Err(format!(
            "secret id {id:?} is not a DID URL with a fragment (expected {did}#<key>)"
        ))
    }
}

/// The public key of `secret` as a multikey (`z…`).
///
/// An EC secret read from a JWK holds its public key as `x || y`, without
/// the `0x04` prefix the SDK's point compression expects, so its multibase
/// form fails there. Such a key is re-derived from its private half, and the
/// derived public key must equal the JWK's, else the secret is inconsistent.
fn public_multibase(secret: &Secret) -> Result<String, String> {
    match secret.get_public_keymultibase() {
        Ok(multibase) => Ok(multibase),
        Err(first) if matches!(secret.get_key_type(), KeyType::P256 | KeyType::Secp256k1) => {
            let derived = secret
                .get_private_keymultibase()
                .and_then(|private| Secret::from_multibase(&private, None))
                .map_err(|e| format!("{first}; re-deriving from the private key: {e}"))?;
            let ours = secret.get_public_bytes();
            let theirs = derived.get_public_bytes();
            if theirs.len() == ours.len() + 1 && theirs.ends_with(ours) {
                derived.get_public_keymultibase().map_err(|e| e.to_string())
            } else {
                Err("the private key does not match the public key".to_string())
            }
        }
        Err(e) => Err(e.to_string()),
    }
}

/// One verification method per secret, with the purpose its key type serves.
///
/// A secret whose key cannot be published (an unsupported type, or material
/// with no public multibase form) is an error: emitting an empty key would
/// publish a document that names a key nobody can use.
pub fn build_verification_methods_for(
    did: &str,
    secrets: &[Secret],
) -> Result<Vec<(Value, KeyPurpose)>, String> {
    secrets
        .iter()
        .map(|secret| {
            let id = verification_method_id(did, secret)?;
            let key_type = secret.get_key_type();
            let purpose = key_purpose(key_type).ok_or_else(|| {
                format!("{id}: key type {key_type:?} cannot be published in the DID document")
            })?;
            let multibase = public_multibase(secret)
                .map_err(|e| format!("{id}: no public multibase form for this key: {e}"))?;
            Ok((
                serde_json::json!({
                    "id": id,
                    "type": VERIFICATION_METHOD_TYPE,
                    "controller": did,
                    "publicKeyMultibase": multibase,
                }),
                purpose,
            ))
        })
        .collect()
}

/// The verification methods of `profile_config`'s document.
pub fn build_verification_methods(profile_config: &ProfileConfig) -> Result<Vec<Value>, String> {
    Ok(
        build_verification_methods_for(&profile_config.did, &profile_config.secrets)?
            .into_iter()
            .map(|(method, _)| method)
            .collect(),
    )
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
        // A bracketed IPv6 literal contains ':' itself, so its host is
        // delimited by the closing bracket rather than by the port separator.
        // Matching `rest.starts_with("[::1]")` instead — as this did — also
        // accepted `http://[::1].evil.com`, an entirely different host, which
        // would have been advertised as a cleartext TRQP endpoint. Same class
        // of bug as the named-host arm below already avoids.
        if let Some(after) = rest.strip_prefix('[') {
            return match after.split_once(']') {
                Some((host, tail))
                    if host == "::1" && (tail.is_empty() || tail.starts_with([':', '/', '?'])) =>
                {
                    Ok(())
                }
                _ => Err(cleartext_rejection(url)),
            };
        }
        let host = rest.split(['/', ':', '?']).next().unwrap_or("");
        if host == "localhost" || host == "127.0.0.1" {
            return Ok(());
        }
    }
    Err(cleartext_rejection(url))
}

fn cleartext_rejection(url: &str) -> String {
    format!(
        "TR_PUBLIC_URL must be https:// (got '{url}'); cleartext TRQP is spoofable by an \
         on-path attacker. http:// is allowed only to loopback (localhost, 127.0.0.1, \
         [::1]) for local dev."
    )
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

/// The DID document for `did` with `secrets`, as a JSON value.
///
/// The one builder for both the registry's runtime document (served when
/// `DID_DOCUMENT` is unset) and the document `setup-trust-registry` publishes
/// for a did:web / did:webvh, so the two never describe one registry
/// differently: each verification method carries its secret's own id,
/// relationships follow key type, and the service entries come from
/// [`build_services`].
pub fn build_did_document_value(
    did: &str,
    secrets: &[Secret],
    mediator_did: &str,
    public_url: Option<&str>,
    flags: TransportFlags,
) -> Result<Value, String> {
    let methods = build_verification_methods_for(did, secrets)?;
    let refs = |wanted: &[KeyPurpose]| -> Vec<Value> {
        methods
            .iter()
            .filter(|(_, purpose)| wanted.contains(purpose))
            .map(|(method, _)| method["id"].clone())
            .collect()
    };
    let signing = refs(&[KeyPurpose::Signing, KeyPurpose::SigningOrAgreement]);
    let mut key_agreement = refs(&[KeyPurpose::KeyAgreement]);
    if key_agreement.is_empty() {
        // A profile with no X25519 key agrees keys with its EC keys.
        key_agreement = refs(&[KeyPurpose::SigningOrAgreement]);
    }
    if flags.didcomm && !methods.is_empty() && key_agreement.is_empty() {
        tracing::warn!(
            "{did}: the profile has no key-agreement key (X25519, P-256 or secp256k1), so the \
             DID document lists none under keyAgreement and peers cannot encrypt to it"
        );
    }
    let verification_methods: Vec<Value> = methods.iter().map(|(m, _)| m.clone()).collect();

    Ok(serde_json::json!({
        "@context": DID_DOCUMENT_CONTEXT,
        "id": did,
        "verificationMethod": verification_methods,
        "authentication": signing,
        "assertionMethod": signing,
        "keyAgreement": key_agreement,
        "service": build_services(did, mediator_did, public_url, flags),
    }))
}

/// [`build_did_document_value`] for `profile_config`, serialised.
pub fn build_did_document(
    profile_config: &ProfileConfig,
    mediator_did: &str,
    public_url: Option<&str>,
    flags: TransportFlags,
) -> Result<String, String> {
    Ok(build_did_document_value(
        &profile_config.did,
        &profile_config.secrets,
        mediator_did,
        public_url,
        flags,
    )?
    .to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// A secret from its JWK, as a profile bundle carries it.
    fn secret(id: &str, jwk: Value) -> Secret {
        serde_json::from_value(json!({
            "id": id,
            "type": "JsonWebKey2020",
            "privateKeyJwk": jwk,
        }))
        .unwrap()
    }

    fn ed25519(id: &str) -> Secret {
        let mut s = Secret::generate_ed25519(None, None);
        s.id = id.to_string();
        s
    }

    fn x25519(id: &str) -> Secret {
        let mut s = Secret::generate_x25519(None, None).unwrap();
        s.id = id.to_string();
        s
    }

    /// What `setup-trust-registry` generates: Ed25519 `#key-1`, X25519
    /// `#key-2`. The served document must carry those ids and nothing else,
    /// since the registry signs and authcrypts under them.
    #[test]
    fn methods_carry_each_secrets_own_id_and_relationships_follow_key_type() {
        let did = "did:web:registry.example";
        let profile = ProfileConfig {
            did: did.to_string(),
            alias: "test".to_string(),
            secrets: vec![
                ed25519("did:web:registry.example#key-1"),
                x25519("did:web:registry.example#key-2"),
            ],
        };
        let doc: Value = serde_json::from_str(
            &build_did_document(
                &profile,
                "did:web:mediator.example",
                None,
                TransportFlags::default(),
            )
            .unwrap(),
        )
        .unwrap();

        let ids: Vec<&str> = doc["verificationMethod"]
            .as_array()
            .unwrap()
            .iter()
            .map(|m| m["id"].as_str().unwrap())
            .collect();
        assert_eq!(ids, [format!("{did}#key-1"), format!("{did}#key-2")]);
        for method in doc["verificationMethod"].as_array().unwrap() {
            assert_eq!(method["type"], "Multikey");
            assert_eq!(method["controller"], did);
            assert!(
                method["publicKeyMultibase"]
                    .as_str()
                    .unwrap()
                    .starts_with('z')
            );
            assert!(method.get("publicKeyJwk").is_none());
        }
        assert_eq!(doc["authentication"], json!([format!("{did}#key-1")]));
        assert_eq!(doc["assertionMethod"], json!([format!("{did}#key-1")]));
        assert_eq!(doc["keyAgreement"], json!([format!("{did}#key-2")]));
        assert_eq!(doc["@context"], json!(DID_DOCUMENT_CONTEXT));
    }

    /// Ids are the secrets' own, whatever order or numbering they come in.
    #[test]
    fn ids_are_not_invented_by_position() {
        let did = "did:web:registry.example";
        let secrets = vec![x25519("#enc"), ed25519(&format!("{did}#sig"))];
        let methods = build_verification_methods_for(did, &secrets).unwrap();
        assert_eq!(methods[0].0["id"], format!("{did}#enc"));
        assert_eq!(methods[0].1, KeyPurpose::KeyAgreement);
        assert_eq!(methods[1].0["id"], format!("{did}#sig"));
        assert_eq!(methods[1].1, KeyPurpose::Signing);
    }

    #[test]
    fn the_published_key_is_the_secrets_public_key() {
        let s = ed25519("did:web:registry.example#key-1");
        let methods =
            build_verification_methods_for("did:web:registry.example", std::slice::from_ref(&s))
                .unwrap();
        assert_eq!(
            methods[0].0["publicKeyMultibase"],
            s.get_public_keymultibase().unwrap()
        );
    }

    #[test]
    fn ec_signing_keys_are_published_under_authentication() {
        for generated in [
            Secret::generate_p256(Some("did:web:example.com#key-1"), None).unwrap(),
            Secret::generate_secp256k1(Some("did:web:example.com#key-1"), None).unwrap(),
        ] {
            // Through JSON, as a profile bundle delivers it.
            let parsed: Secret =
                serde_json::from_value(serde_json::to_value(&generated).unwrap()).unwrap();
            let methods = build_verification_methods_for("did:web:example.com", &[parsed]).unwrap();
            assert_eq!(methods[0].1, KeyPurpose::SigningOrAgreement);
            assert_eq!(
                methods[0].0["publicKeyMultibase"],
                generated.get_public_keymultibase().unwrap()
            );
        }
    }

    /// A profile from before the move to Curve25519 (P-256 `#key-1`,
    /// secp256k1 `#key-2`) keeps a key to encrypt to: with no X25519 key, its
    /// EC keys are listed under `keyAgreement` too.
    #[test]
    fn a_legacy_ec_profile_keeps_key_agreement() {
        let did = "did:web:example.com";
        let secrets = vec![
            Secret::generate_p256(Some(&format!("{did}#key-1")), None).unwrap(),
            Secret::generate_secp256k1(Some(&format!("{did}#key-2")), None).unwrap(),
        ];
        let doc =
            build_did_document_value(did, &secrets, "did:web:m", None, TransportFlags::default())
                .unwrap();
        let both = json!([format!("{did}#key-1"), format!("{did}#key-2")]);
        assert_eq!(doc["authentication"], both);
        assert_eq!(doc["keyAgreement"], both);

        // With an X25519 key present, EC keys stay out of keyAgreement.
        let mut with_x = secrets.clone();
        with_x.push(x25519(&format!("{did}#key-3")));
        let doc =
            build_did_document_value(did, &with_x, "did:web:m", None, TransportFlags::default())
                .unwrap();
        assert_eq!(doc["keyAgreement"], json!([format!("{did}#key-3")]));
    }

    /// A did:scid profile DID carries `?src=`; its keys are under the bare
    /// DID, and both forms are accepted.
    #[test]
    fn scid_keys_under_the_bare_did_are_accepted() {
        let did = "did:scid:vh:1:QmAbc?src=example.com";
        let methods =
            build_verification_methods_for(did, &[ed25519("did:scid:vh:1:QmAbc#key-1")]).unwrap();
        assert_eq!(methods[0].0["id"], "did:scid:vh:1:QmAbc#key-1");
    }

    /// A JWK whose private half is not its public key's is refused rather
    /// than published under a key the registry cannot sign for.
    #[test]
    fn an_ec_secret_whose_halves_disagree_is_an_error() {
        let p256 = secret(
            "did:web:example.com#key-1",
            json!({
                "crv": "P-256",
                "d": "ctKLNB9cXUO3yD-jMCaRi680RmHOFuS30nVogmEhkx4",
                "kty": "EC",
                "x": "DEtsdJXfi7IuqaZFkRW_aBwHHpID1jQjPqN_Y46zlZM",
                "y": "LQs6Q-gGqgtrUW2iEfb9YRyvPAuNALceHqGYs4sNwh4"
            }),
        );
        let err = build_verification_methods_for("did:web:example.com", &[p256]).unwrap_err();
        assert!(err.contains("does not match"), "{err}");
    }

    /// A key that cannot be represented is a configuration error, never an
    /// empty `{}` key in the served document.
    #[test]
    fn an_unpublishable_secret_is_an_error() {
        let bad_id = ed25519("key-1");
        assert!(build_verification_methods_for("did:web:example.com", &[bad_id]).is_err());

        let p384 = secret(
            "did:web:example.com#key-1",
            json!({
                "kty": "EC",
                "crv": "P-384",
                "x": "iA7lWQLzVrKGEFjfGMfMHfTEZ2KnLiKU7JuNT3E7ygsfE7ygAqtV1UYAsHSdGI_6",
                "y": "vbYb9_K4xs7YpWSiNm8TbqQcGGbtBY-v6ySSOihkzCjQwX4yU8QEf0Kl9F2-RoWh",
                "d": "u2jqGxbGJMKbDCgtyDiOjJWaQ2ZtFYsLNuUDxx3t-kG5k-gl_6Wd2b5JX5brQWwA"
            }),
        );
        let err = build_verification_methods_for("did:web:example.com", &[p384]).unwrap_err();
        assert!(err.contains("cannot be published"), "{err}");

        let profile = ProfileConfig {
            did: "did:web:example.com".to_string(),
            alias: "t".to_string(),
            secrets: vec![ed25519("no-fragment")],
        };
        assert!(
            build_did_document(&profile, "did:web:m", None, TransportFlags::default()).is_err()
        );
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
        )
        .unwrap();
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
    ///
    /// The bracketed IPv6 cases are the arm this test did not cover:
    /// `rest.starts_with("[::1]")` accepted `http://[::1].evil.com`, a wholly
    /// different host, which would then have been advertised in the DID
    /// document as a cleartext TRQP endpoint. A bracketed literal ends at its
    /// closing bracket, and only a port, path or query may follow.
    #[test]
    fn loopback_exception_does_not_leak_to_lookalike_hosts() {
        for url in [
            "http://localhost.evil.com",
            "http://localhostevil.com",
            "http://127.0.0.1.evil.com",
            "http://[::1].evil.com",
            "http://[::1]evil.com",
            "http://[::1]@evil.com",
            "http://[::2]:3232",
            // Unterminated bracket: not a host we can vouch for.
            "http://[::1",
        ] {
            assert!(
                validate_public_url(url).is_err(),
                "a lookalike host must not inherit the loopback exception: {url}"
            );
        }
    }

    /// The forms the exception exists to permit must keep working.
    #[test]
    fn every_loopback_form_stays_accepted() {
        for url in [
            "http://localhost",
            "http://localhost:3232",
            "http://localhost/trust-tasks",
            "http://127.0.0.1:3232",
            "http://[::1]",
            "http://[::1]:3232",
            "http://[::1]/trust-tasks",
        ] {
            assert!(
                validate_public_url(url).is_ok(),
                "local dev must stay usable: {url}"
            );
        }
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
