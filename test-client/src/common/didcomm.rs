use affinidi_tdk::didcomm::Message;
use anyhow::Result;
use std::time::{SystemTime, UNIX_EPOCH};
use uuid::Uuid;

// TODO: reuse didcomm-server/src/didcomm
pub fn build_message(
    service_did: String,
    issuer_profile_did: String,
    body: &str,
    message_type: String,
    msg_id: Option<String>,
) -> Result<Message> {
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    let id = msg_id.unwrap_or(Uuid::new_v4().into());
    let m = Message::build(id, message_type, serde_json::from_str(body)?)
        .to(service_did)
        .from(issuer_profile_did)
        .created_time(now)
        .expires_time(now + 10)
        .finalize();

    println!("---  MESSAGE: '{}' ---", &m.typ);
    println!("{:?}", serde_json::to_string(&m));
    println!("------");
    Ok(m)
}
