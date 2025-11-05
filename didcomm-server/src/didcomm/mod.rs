use affinidi_tdk::didcomm::Message;
use uuid::Uuid;

pub mod problem_report;
pub mod transport;

/// Returns the thread ID for a message, falling back to the message ID if no thread ID is set.
pub fn get_thread_id(msg: &Message) -> Option<String> {
    msg.thid.clone().or_else(|| Some(msg.id.clone()))
}

/// Returns the parent thread ID, falling back to thread ID, then message ID.
pub fn get_parent_thread_id(msg: &Message) -> Option<String> {
    msg.pthid.clone().or_else(|| get_thread_id(msg))
}

pub fn new_message_id() -> String {
    Uuid::new_v4().to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_get_thread_id() {
        let msg = Message::build(new_message_id(), "test".to_string(), serde_json::json!({}))
            .thid("thread-123".to_string())
            .finalize();

        assert_eq!(get_thread_id(&msg), Some("thread-123".to_string()));
    }

    #[test]
    fn test_new_message_id() {
        let id1 = new_message_id();
        let id2 = new_message_id();
        assert_ne!(id1, id2);
        assert!(Uuid::parse_str(&id1).is_ok());
    }
}
