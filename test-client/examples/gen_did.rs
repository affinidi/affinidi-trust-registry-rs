use affinidi_tdk::{
    did_common::{DID as DIDCommon, PeerCreateKey, PeerKeyPurpose, PeerService, PeerServiceEndpoint},
    secrets_resolver::secrets::Secret,
};
use serde_json::json;

fn main() {
    let mediator_did = std::env::var("MEDIATOR_DID")
        .unwrap_or_else(|_| "did:web:mediator.fabric-demo.octo.affinidi.io".to_string());

    let mut v_key = Secret::generate_ed25519(None, None);
    let mut e_key = Secret::generate_x25519(None, None).expect("Couldn't create X25519 secret");

    let v_multibase = v_key
        .get_public_keymultibase()
        .expect("Couldn't get verification key multibase");
    let e_multibase = e_key
        .get_public_keymultibase()
        .expect("Couldn't get encryption key multibase");

    let keys = vec![
        PeerCreateKey::from_multibase(PeerKeyPurpose::Verification, v_multibase),
        PeerCreateKey::from_multibase(PeerKeyPurpose::Encryption, e_multibase),
    ];

    let services = Some(vec![PeerService {
        id: None,
        type_: "dm".into(),
        endpoint: PeerServiceEndpoint::Uri(mediator_did),
    }]);

    let (did_peer, _) =
        DIDCommon::generate_peer(&keys, services.as_deref()).expect("Failed to create did:peer");
    let did_peer_str = did_peer.to_string();

    v_key.id = format!("{}#key-1", did_peer_str);
    e_key.id = format!("{}#key-2", did_peer_str);

    let config = json!({
        did_peer_str.clone(): {
            "alias": "SampleTRAdmin",
            "secrets": [v_key, e_key]
        }
    });

    println!("{}", serde_json::to_string_pretty(&config).unwrap());
}
