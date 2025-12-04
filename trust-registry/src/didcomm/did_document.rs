use crate::configs::ProfileConfig;

pub fn build_public_jwk(jwk: &affinidi_tdk::secrets_resolver::jwk::JWK) -> serde_json::Value {
    match &jwk.params {
        affinidi_tdk::secrets_resolver::jwk::Params::EC(params) => {
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
        affinidi_tdk::secrets_resolver::jwk::Params::OKP(params) => {
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

pub fn build_did_document(profile_config: &ProfileConfig, mediator_did: &str) -> String {
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
        "service": [{
            "id": format!("{}#didcomm", profile_config.did),
            "type": "DIDCommMessaging",
            "serviceEndpoint": {
                "uri": mediator_did,
                "accept": ["didcomm/v2"],
                "routingKeys": []
            }
        }]
    })
    .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use affinidi_tdk::secrets_resolver::{jwk::JWK, secrets::Secret};
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
      })).unwrap();
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
        })).unwrap();
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
        })).unwrap();

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
        })).unwrap();

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
        })).unwrap();

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
        })).unwrap();

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
        
        let doc = build_did_document(&profile, "did:web:mediator.example.com");
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
        
        let doc = build_did_document(&profile, "did:web:mediator.com");
        let parsed: serde_json::Value = serde_json::from_str(&doc).unwrap();
        
        let service = &parsed["service"][0];
        assert_eq!(service["type"], "DIDCommMessaging");
        assert_eq!(service["serviceEndpoint"]["uri"], "did:web:mediator.com");
        assert_eq!(service["serviceEndpoint"]["accept"][0], "didcomm/v2");
    }
}