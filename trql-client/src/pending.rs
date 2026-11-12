//! Reply demultiplexing shared by the mediator-based transports.
//!
//! One background task owns the inbound stream (never per-request wait
//! loops — concurrent callers must not steal each other's replies) and routes
//! each reply document to its waiter by the document's `threadId`.
//!
//! A reply is handed over only when the party the transport authenticated as
//! its sender is the party the request was addressed to. The `threadId` is
//! chosen by whoever sends the document, so it identifies the exchange but
//! not who answered it; the sender binding does that.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use affinidi_tdk::did_common::scid::same_reference;
use serde_json::Value;
use tokio::sync::oneshot;
use trust_tasks_rs::TrustTask;

/// A registered exchange: the party whose reply it waits for, and where to
/// deliver that reply.
struct Waiter {
    expected_sender: String,
    tx: oneshot::Sender<TrustTask<Value>>,
}

/// What [`PendingReplies::route`] did with a document.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum RouteOutcome {
    /// Handed to the waiter registered under its `threadId`.
    Delivered,
    /// No waiter for its `threadId` (or it carried none, or the waiter had
    /// already gone away).
    Unsolicited,
    /// A waiter exists, but the document did not come from the party that
    /// waiter's request was addressed to (or its sender was not
    /// authenticated). The waiter stays registered for the real reply.
    WrongSender {
        /// The party the request was addressed to.
        expected: String,
    },
}

/// In-flight exchanges awaiting a reply, keyed by request document id.
#[derive(Clone, Default)]
pub(crate) struct PendingReplies {
    inner: Arc<Mutex<HashMap<String, Waiter>>>,
}

impl PendingReplies {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    /// Register a waiter for `request_id` before the request is sent, so a
    /// fast reply cannot race the registration. Only a reply authenticated
    /// as coming from `expected_sender` (the request's recipient) completes it.
    pub(crate) fn register(
        &self,
        request_id: &str,
        expected_sender: &str,
    ) -> oneshot::Receiver<TrustTask<Value>> {
        let (tx, rx) = oneshot::channel();
        self.lock().insert(
            request_id.to_string(),
            Waiter {
                expected_sender: expected_sender.to_string(),
                tx,
            },
        );
        rx
    }

    /// Drop the waiter for `request_id` (send failure or timeout).
    pub(crate) fn abandon(&self, request_id: &str) {
        self.lock().remove(request_id);
    }

    /// Route `document` to the waiter registered under its `threadId`, if
    /// `sender` — the sender the transport authenticated, `None` when it
    /// authenticated none — is the party that waiter's request was addressed
    /// to. A document from anyone else leaves the waiter in place, so it can
    /// neither complete nor cancel the exchange.
    pub(crate) fn route(&self, document: TrustTask<Value>, sender: Option<&str>) -> RouteOutcome {
        let Some(thread_id) = document.thread_id.clone() else {
            return RouteOutcome::Unsolicited;
        };
        // Take the sender under the lock, send after releasing it.
        let waiter = {
            let mut map = self.lock();
            let Some(waiter) = map.get(&thread_id) else {
                return RouteOutcome::Unsolicited;
            };
            if !sender.is_some_and(|s| same_reference(s, &waiter.expected_sender)) {
                return RouteOutcome::WrongSender {
                    expected: waiter.expected_sender.clone(),
                };
            }
            map.remove(&thread_id)
        };
        match waiter.map(|waiter| waiter.tx.send(document).is_ok()) {
            Some(true) => RouteOutcome::Delivered,
            _ => RouteOutcome::Unsolicited,
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<String, Waiter>> {
        // A poisoned map only means another thread panicked mid-insert; the
        // map itself is still coherent for our usage.
        self.inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

#[cfg(test)]
pub(crate) mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    pub(crate) const REGISTRY: &str = "did:example:registry";
    pub(crate) const OTHER: &str = "did:example:someone-else";

    /// A well-formed authorization `#response` correlated to `request_id`
    /// that echoes the asked tuple, as the registry would send it.
    pub(crate) fn reply_to(request_id: &str) -> TrustTask<Value> {
        let mut doc = TrustTask::new(
            "urn:uuid:reply".to_string(),
            "https://trusttasks.org/spec/registry/authorization/0.2#response"
                .parse()
                .unwrap(),
            serde_json::json!({
                "entity_id": "did:example:e",
                "authority_id": "did:example:a",
                "action": "act",
                "resource": "res",
                "authorized": true,
            }),
        );
        doc.thread_id = Some(request_id.to_string());
        doc
    }

    #[test]
    fn a_reply_from_the_addressed_party_is_delivered() {
        let pending = PendingReplies::new();
        let mut rx = pending.register("req-1", REGISTRY);
        assert_eq!(
            pending.route(reply_to("req-1"), Some(REGISTRY)),
            RouteOutcome::Delivered
        );
        assert_eq!(rx.try_recv().unwrap().thread_id.as_deref(), Some("req-1"));
    }

    #[test]
    fn a_correlated_reply_from_another_party_does_not_complete_the_exchange() {
        let pending = PendingReplies::new();
        let mut rx = pending.register("req-1", REGISTRY);

        assert_eq!(
            pending.route(reply_to("req-1"), Some(OTHER)),
            RouteOutcome::WrongSender {
                expected: REGISTRY.to_string()
            }
        );
        // Neither completed nor cancelled.
        assert!(matches!(
            rx.try_recv(),
            Err(oneshot::error::TryRecvError::Empty)
        ));

        // The registry's own reply still gets through afterwards.
        assert_eq!(
            pending.route(reply_to("req-1"), Some(REGISTRY)),
            RouteOutcome::Delivered
        );
        assert!(rx.try_recv().is_ok());
    }

    #[test]
    fn a_reply_with_no_authenticated_sender_does_not_complete_the_exchange() {
        let pending = PendingReplies::new();
        let mut rx = pending.register("req-1", REGISTRY);
        assert!(matches!(
            pending.route(reply_to("req-1"), None),
            RouteOutcome::WrongSender { .. }
        ));
        assert!(matches!(
            rx.try_recv(),
            Err(oneshot::error::TryRecvError::Empty)
        ));
    }

    #[test]
    fn an_uncorrelated_reply_is_unsolicited() {
        let pending = PendingReplies::new();
        let _rx = pending.register("req-1", REGISTRY);
        assert_eq!(
            pending.route(reply_to("req-2"), Some(REGISTRY)),
            RouteOutcome::Unsolicited
        );
        let mut no_thread = reply_to("req-1");
        no_thread.thread_id = None;
        assert_eq!(
            pending.route(no_thread, Some(REGISTRY)),
            RouteOutcome::Unsolicited
        );
    }

    #[test]
    fn a_did_scid_sender_matches_regardless_of_its_src_locator() {
        let pending = PendingReplies::new();
        let mut rx = pending.register("req-1", "did:scid:vh:1:Qm?src=example.com/r");
        assert_eq!(
            pending.route(reply_to("req-1"), Some("did:scid:vh:1:Qm")),
            RouteOutcome::Delivered
        );
        assert!(rx.try_recv().is_ok());
    }
}
