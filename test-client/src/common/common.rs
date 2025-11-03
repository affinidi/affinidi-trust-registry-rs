
use affinidi_tdk::didcomm::Message;
use std::time::{SystemTime, UNIX_EPOCH};
use uuid::Uuid;


pub fn build_message(
    service_did: String,
    issuer_profile_did: String,
    body: &str,
    message_type: String,
    msg_id: Option<String>,
) -> Message {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let id = msg_id.unwrap_or(Uuid::new_v4().into());
    let m = Message::build(id, message_type, serde_json::from_str(&body).unwrap())
        .to(service_did)
        .from(issuer_profile_did)
        .created_time(now)
        .expires_time(now + 10)
        .finalize();

    println!("---  MESSAGE: '{}' ---", &m.type_);
    println!("{:?}", serde_json::to_string(&m));
    println!("------");
    m
}
