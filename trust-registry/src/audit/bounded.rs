//! A rate bound on audit entries nobody has proven.
//!
//! A refusal issued before the writer's proof was checked can be provoked by
//! anyone, as fast as they can send. Recording each one individually would let
//! an unauthenticated sender fill the audit log and bury the entries that
//! matter. [`BoundedAuditLogger`] records up to a fixed number of such entries
//! per window and counts the rest; the count is recorded as one entry when the
//! next window opens. Entries with a proven actor always pass through.

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use crate::audit::model::{AuditLog, AuditLogBuilder, AuditLogger, AuditOperation, AuditResource};

/// How many unproven entries are recorded individually per window.
pub const DEFAULT_UNPROVEN_PER_WINDOW: u32 = 60;

/// The window [`DEFAULT_UNPROVEN_PER_WINDOW`] applies to.
pub const DEFAULT_UNPROVEN_WINDOW: Duration = Duration::from_secs(60);

struct Budget {
    window_start: Instant,
    recorded: u32,
    suppressed: u64,
}

pub struct BoundedAuditLogger {
    inner: Arc<dyn AuditLogger>,
    per_window: u32,
    window: Duration,
    budget: Mutex<Budget>,
}

impl BoundedAuditLogger {
    pub fn new(inner: Arc<dyn AuditLogger>) -> Self {
        Self::with_budget(inner, DEFAULT_UNPROVEN_PER_WINDOW, DEFAULT_UNPROVEN_WINDOW)
    }

    pub fn with_budget(inner: Arc<dyn AuditLogger>, per_window: u32, window: Duration) -> Self {
        Self {
            inner,
            per_window,
            window,
            budget: Mutex::new(Budget {
                window_start: Instant::now(),
                recorded: 0,
                suppressed: 0,
            }),
        }
    }

    /// Open a new window if the current one has closed, returning how many
    /// entries the closed one suppressed. Then decide whether `unproven` fits.
    fn admit(&self, unproven: bool) -> (u64, bool) {
        let mut budget = self
            .budget
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let mut closed_suppressed = 0;
        if budget.window_start.elapsed() >= self.window {
            closed_suppressed = budget.suppressed;
            budget.window_start = Instant::now();
            budget.recorded = 0;
            budget.suppressed = 0;
        }
        if !unproven {
            return (closed_suppressed, true);
        }
        if budget.recorded < self.per_window {
            budget.recorded += 1;
            (closed_suppressed, true)
        } else {
            budget.suppressed += 1;
            (closed_suppressed, false)
        }
    }
}

#[async_trait::async_trait]
impl AuditLogger for BoundedAuditLogger {
    async fn log(&self, audit_log: AuditLog) {
        let (suppressed, admitted) = self.admit(audit_log.actor.is_empty());
        if suppressed > 0 {
            self.inner
                .log(
                    AuditLogBuilder::new()
                        .operation(AuditOperation::Update)
                        .resource(AuditResource::empty())
                        .build_unauthorized(format!(
                            "{suppressed} further refusals of unproven writes in the previous \
                             window were counted but not recorded individually"
                        )),
                )
                .await;
        }
        if admitted {
            self.inner.log(audit_log).await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Default)]
    struct Recording(Mutex<Vec<AuditLog>>);

    #[async_trait::async_trait]
    impl AuditLogger for Recording {
        async fn log(&self, audit_log: AuditLog) {
            self.0.lock().unwrap().push(audit_log);
        }
    }

    fn unproven() -> AuditLog {
        AuditLogBuilder::new()
            .claimed_actor(Some("did:example:anyone".to_string()))
            .build_unauthorized("proofRequired")
    }

    fn proven() -> AuditLog {
        AuditLogBuilder::new()
            .actor("did:example:admin")
            .build_success()
    }

    #[tokio::test]
    async fn unproven_entries_are_bounded_and_counted() {
        let recording = Arc::new(Recording::default());
        let bounded =
            BoundedAuditLogger::with_budget(recording.clone(), 2, Duration::from_millis(20));

        for _ in 0..5 {
            bounded.log(unproven()).await;
        }
        bounded.log(proven()).await;
        assert_eq!(
            recording.0.lock().unwrap().len(),
            3,
            "two unproven entries, then only the proven one"
        );

        tokio::time::sleep(Duration::from_millis(30)).await;
        bounded.log(unproven()).await;
        let entries = recording.0.lock().unwrap();
        let summary = &entries[3];
        assert!(
            summary
                .extra
                .as_deref()
                .is_some_and(|extra| extra.contains("3 further refusals")),
            "the suppressed count is recorded: {:?}",
            summary.extra
        );
        assert_eq!(entries.len(), 5);
    }
}
