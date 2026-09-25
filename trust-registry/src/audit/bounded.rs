//! A rate bound on audit entries nobody has proven.
//!
//! A refusal issued before the writer's proof was checked can be provoked by
//! anyone, as fast as they can send. Recording each one individually would let
//! an unauthenticated sender fill the audit log and bury the entries that
//! matter. [`BoundedAuditLogger`] records up to a fixed number of such entries
//! per window and counts the rest. The count is recorded as one entry when the
//! next window opens, on a timer ([`BoundedAuditLogger::spawn_flusher`]) and
//! at shutdown ([`BoundedAuditLogger::flush`]), so it is not lost when no
//! further entry arrives. Entries with a proven actor always pass through.

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

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

    /// Record the refusals counted since the last summary, if any.
    pub async fn flush(&self) {
        let suppressed = {
            let mut budget = self
                .budget
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            std::mem::take(&mut budget.suppressed)
        };
        self.log_summary(suppressed).await;
    }

    /// Flush every window, and once more when `shutdown` is cancelled.
    pub fn spawn_flusher(self: &Arc<Self>, shutdown: CancellationToken) -> JoinHandle<()> {
        let logger = self.clone();
        tokio::spawn(async move {
            let mut ticks = tokio::time::interval(logger.window);
            ticks.tick().await;
            loop {
                tokio::select! {
                    _ = ticks.tick() => logger.flush().await,
                    _ = shutdown.cancelled() => {
                        logger.flush().await;
                        return;
                    }
                }
            }
        })
    }

    async fn log_summary(&self, suppressed: u64) {
        if suppressed == 0 {
            return;
        }
        self.inner
            .log(
                AuditLogBuilder::new()
                    .operation(AuditOperation::Update)
                    .resource(AuditResource::empty())
                    .build_unauthorized(format!(
                        "{suppressed} further refusals of unproven documents were counted \
                         but not recorded individually"
                    )),
            )
            .await;
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
        self.log_summary(suppressed).await;
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

    #[tokio::test]
    async fn the_count_is_flushed_without_a_further_entry() {
        let recording = Arc::new(Recording::default());
        let bounded = Arc::new(BoundedAuditLogger::with_budget(
            recording.clone(),
            1,
            Duration::from_millis(20),
        ));
        let shutdown = CancellationToken::new();
        let flusher = bounded.spawn_flusher(shutdown.clone());

        for _ in 0..4 {
            bounded.log(unproven()).await;
        }
        tokio::time::sleep(Duration::from_millis(60)).await;
        assert_eq!(
            recording.0.lock().unwrap().len(),
            2,
            "one entry and its count"
        );

        bounded.log(unproven()).await;
        bounded.log(unproven()).await;
        shutdown.cancel();
        flusher.await.unwrap();
        let entries = recording.0.lock().unwrap();
        assert!(
            entries
                .last()
                .and_then(|entry| entry.extra.as_deref())
                .is_some_and(|extra| extra.contains("1 further refusals")),
            "the count is flushed at shutdown: {:?}",
            entries.last().map(|e| &e.extra)
        );
    }
}
