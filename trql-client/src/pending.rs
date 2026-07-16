//! Reply demultiplexing shared by the mediator-based transports.
//!
//! One background task owns the inbound stream (never per-request wait
//! loops — concurrent callers must not steal each other's replies) and routes
//! each reply document to its waiter by the document's `threadId`.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use serde_json::Value;
use tokio::sync::oneshot;
use trust_tasks_rs::TrustTask;

/// In-flight exchanges awaiting a reply, keyed by request document id.
#[derive(Clone, Default)]
pub(crate) struct PendingReplies {
    inner: Arc<Mutex<HashMap<String, oneshot::Sender<TrustTask<Value>>>>>,
}

impl PendingReplies {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    /// Register a waiter for `request_id` before the request is sent, so a
    /// fast reply cannot race the registration.
    pub(crate) fn register(&self, request_id: &str) -> oneshot::Receiver<TrustTask<Value>> {
        let (tx, rx) = oneshot::channel();
        self.lock().insert(request_id.to_string(), tx);
        rx
    }

    /// Drop the waiter for `request_id` (send failure or timeout).
    pub(crate) fn abandon(&self, request_id: &str) {
        self.lock().remove(request_id);
    }

    /// Route `document` to the waiter registered under its `threadId`.
    /// Returns `true` if a waiter received it.
    pub(crate) fn route(&self, document: TrustTask<Value>) -> bool {
        let Some(thread_id) = document.thread_id.clone() else {
            return false;
        };
        // Take the sender under the lock, send after releasing it.
        let waiter = self.lock().remove(&thread_id);
        match waiter {
            Some(tx) => tx.send(document).is_ok(),
            None => false,
        }
    }

    fn lock(
        &self,
    ) -> std::sync::MutexGuard<'_, HashMap<String, oneshot::Sender<TrustTask<Value>>>> {
        // A poisoned map only means another thread panicked mid-insert; the
        // map itself is still coherent for our usage.
        self.inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}
