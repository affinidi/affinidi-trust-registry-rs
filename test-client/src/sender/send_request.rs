use crate::common::common::build_message;
use affinidi_tdk::messaging::{ATM, errors::ATMError, profiles::ATMProfile, protocols::Protocols};
use serde_json::Value;
use std::sync::Arc;

pub async fn send_request(
    atm: &ATM,
    issuer_profile: Arc<ATMProfile>,
    service_did: &str,
    protocols: &Protocols,
    mediator_did: &str,
    body: &Value,
    operation: &str,
) -> Result<(), ATMError> {
    let message_type = format!("https://affinidi.com/didcomm/protocols/{}", operation);

    let msg = build_message(
        service_did.to_string(),
        issuer_profile.inner.did.clone(),
        &body.to_string(),
        message_type,
        None,
    );

    let packed_msg = atm
        .pack_encrypted(
            &msg,
            service_did,
            Some(&issuer_profile.inner.did),
            Some(&issuer_profile.inner.did),
            None,
        )
        .await?;

    let (forward_id, forward_msg) = protocols
        .routing
        .forward_message(
            &atm,
            &issuer_profile,
            false,
            &packed_msg.0,
            mediator_did,
            service_did,
            None,
            None,
        )
        .await?;

    match atm
        .send_message(&issuer_profile, &forward_msg, &forward_id, false, false)
        .await
    {
        Ok(_) => {
            println!("Message sent from {}", issuer_profile.inner.alias);
        }
        Err(e) => {
            println!("Error in sending message: {:#?}", e);
            return Err(e);
        }
    };

    Ok(())
}
