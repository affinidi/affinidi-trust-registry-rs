//! A rate bound on audit entries nobody has proven.
//!
//! A refusal issued before the writer's proof was checked can be provoked by
//! anyone, as fast as they can send. Recording each one individually would let
//! one sender fill the audit log and bury the entries that matter.
//! [`BoundedAuditLogger`] records up to a fixed number of such entries per
//! window *per source* and counts the rest. A source is either "an
//! unauthenticated caller" (the HTTP surface, or a host transport that passed
//! no sender) or one transport-authenticated sender (a DIDComm authcrypt
//! sender, a TSP VID), so anonymous traffic cannot use up the entries that
//! refusals over an authenticated transport need, and one authenticated peer
//! cannot use up another's.
//!
//! The counts are recorded as one summary entry per source when the next
//! window opens, on a timer ([`BoundedAuditLogger::spawn_flusher`]) and at
//! shutdown ([`BoundedAuditLogger::flush`]), so they are not lost when no
//! further entry arrives. A summary keeps the reason codes and task types it
//! counted and the first few claimed issuers. Entries with a proven actor
//! always pass through.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

use crate::audit::model::{AuditLog, AuditLogBuilder, AuditLogger, AuditOperation, AuditResource};

/// How many unproven entries are recorded individually per source per window.
pub const DEFAULT_UNPROVEN_PER_WINDOW: u32 = 60;

/// The window [`DEFAULT_UNPROVEN_PER_WINDOW`] applies to.
pub const DEFAULT_UNPROVEN_WINDOW: Duration = Duration::from_secs(60);

/// The most authenticated senders given a budget of their own in one window.
/// Senders beyond this share one further budget, so memory stays bounded
/// however many identities send.
pub const MAX_TRACKED_SENDERS: usize = 1024;

/// The most distinct claimed issuers, reason codes or task types a summary
/// names; the rest are counted under `other`.
pub const MAX_SUMMARY_KEYS: usize = 8;

/// Where an unproven entry came from, for budgeting.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
enum Source {
    /// No transport authentication: anyone, under any claimed issuer.
    Unauthenticated,
    /// One transport-authenticated sender.
    Sender(String),
    /// Authenticated senders beyond [`MAX_TRACKED_SENDERS`].
    OtherSenders,
}

/// Counts of `key`s, naming at most [`MAX_SUMMARY_KEYS`] of them.
#[derive(Default)]
struct Tally(BTreeMap<String, u64>);

impl Tally {
    fn add(&mut self, key: &str) {
        let key = if self.0.contains_key(key) || self.0.len() < MAX_SUMMARY_KEYS {
            key
        } else {
            "other"
        };
        *self.0.entry(key.to_string()).or_default() += 1;
    }

    fn render(&self) -> String {
        self.0
            .iter()
            .map(|(key, count)| format!("{key}={count}"))
            .collect::<Vec<_>>()
            .join(", ")
    }
}

/// What one source's suppressed entries had in common.
#[derive(Default)]
struct Suppressed {
    count: u64,
    reasons: Tally,
    tasks: Tally,
    claimed: BTreeSet<String>,
}

impl Suppressed {
    fn add(&mut self, audit_log: &AuditLog) {
        self.count += 1;
        self.reasons.add(&reason_code(audit_log));
        self.tasks
            .add(audit_log.task.as_deref().unwrap_or("unknown"));
        if let Some(claimed) = &audit_log.claimed_actor
            && self.claimed.len() < MAX_SUMMARY_KEYS
        {
            self.claimed.insert(claimed.clone());
        }
    }
}

/// The reason code of a refusal: the part of its reason before the first `:`.
fn reason_code(audit_log: &AuditLog) -> String {
    let reason = audit_log
        .extra
        .as_deref()
        .and_then(|extra| extra.split_once('=').map(|(_, value)| value))
        .unwrap_or("unknown");
    reason
        .split_once(':')
        .map_or(reason, |(code, _)| code)
        .trim()
        .to_string()
}

#[derive(Default)]
struct SourceBudget {
    recorded: u32,
    suppressed: Suppressed,
}

struct Budget {
    window_start: Instant,
    sources: HashMap<Source, SourceBudget>,
    tracked_senders: usize,
}

impl Budget {
    fn new() -> Self {
        Self {
            window_start: Instant::now(),
            sources: HashMap::new(),
            tracked_senders: 0,
        }
    }

    /// Start a new window, returning what the closed one suppressed.
    fn reset(&mut self) -> Vec<(Source, Suppressed)> {
        let closed = std::mem::replace(self, Self::new());
        let mut suppressed: Vec<(Source, Suppressed)> = closed
            .sources
            .into_iter()
            .filter(|(_, budget)| budget.suppressed.count > 0)
            .map(|(source, budget)| (source, budget.suppressed))
            .collect();
        suppressed.sort_by(|(a, _), (b, _)| a.cmp(b));
        suppressed
    }

    fn source_for(&mut self, authenticated_sender: Option<&str>) -> Source {
        let Some(sender) = authenticated_sender else {
            return Source::Unauthenticated;
        };
        let source = Source::Sender(sender.to_string());
        if self.sources.contains_key(&source) {
            return source;
        }
        if self.tracked_senders < MAX_TRACKED_SENDERS {
            self.tracked_senders += 1;
            source
        } else {
            Source::OtherSenders
        }
    }
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

    /// `per_window` applies to each source separately.
    pub fn with_budget(inner: Arc<dyn AuditLogger>, per_window: u32, window: Duration) -> Self {
        Self {
            inner,
            per_window,
            window,
            budget: Mutex::new(Budget::new()),
        }
    }

    /// Record the refusals counted since the last summary, if any.
    pub async fn flush(&self) {
        let suppressed = {
            let mut budget = self
                .budget
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            budget.reset()
        };
        self.log_summaries(suppressed).await;
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

    async fn log_summaries(&self, suppressed: Vec<(Source, Suppressed)>) {
        for (source, suppressed) in suppressed {
            let (from, authenticated_sender) = match source {
                Source::Unauthenticated => ("unauthenticated callers".to_string(), None),
                Source::Sender(sender) => ("this authenticated sender".to_string(), Some(sender)),
                Source::OtherSenders => (
                    format!("authenticated senders beyond the first {MAX_TRACKED_SENDERS}"),
                    None,
                ),
            };
            let mut summary = format!(
                "{} further refusals of unproven documents from {from} were counted but not \
                 recorded individually; reasons: {}; tasks: {}",
                suppressed.count,
                suppressed.reasons.render(),
                suppressed.tasks.render(),
            );
            if !suppressed.claimed.is_empty() {
                summary.push_str("; claimed issuers include: ");
                summary.push_str(
                    &suppressed
                        .claimed
                        .iter()
                        .cloned()
                        .collect::<Vec<_>>()
                        .join(", "),
                );
            }
            self.inner
                .log(
                    AuditLogBuilder::new()
                        .operation(AuditOperation::Update)
                        .resource(AuditResource::empty())
                        .authenticated_sender(authenticated_sender)
                        .build_unauthorized(summary),
                )
                .await;
        }
    }

    /// Open a new window if the current one has closed, returning what the
    /// closed one suppressed. Then decide whether `audit_log` fits its
    /// source's budget, counting it if not.
    fn admit(&self, audit_log: &AuditLog) -> (Vec<(Source, Suppressed)>, bool) {
        let mut budget = self
            .budget
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let closed = if budget.window_start.elapsed() >= self.window {
            budget.reset()
        } else {
            Vec::new()
        };
        if !audit_log.actor.is_empty() {
            return (closed, true);
        }
        let source = budget.source_for(audit_log.authenticated_sender.as_deref());
        let source_budget = budget.sources.entry(source).or_default();
        if source_budget.recorded < self.per_window {
            source_budget.recorded += 1;
            (closed, true)
        } else {
            source_budget.suppressed.add(audit_log);
            (closed, false)
        }
    }
}

#[async_trait::async_trait]
impl AuditLogger for BoundedAuditLogger {
    async fn log(&self, audit_log: AuditLog) {
        let (suppressed, admitted) = self.admit(&audit_log);
        self.log_summaries(suppressed).await;
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
                .is_some_and(|extra| extra.contains("3 further refusals")
                    && extra.contains("from unauthenticated callers")
                    && extra.contains("proofRequired=3")
                    && extra.contains("did:example:anyone")),
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

    fn unproven_over(sender: &str) -> AuditLog {
        AuditLogBuilder::new()
            .claimed_actor(Some(sender.to_string()))
            .authenticated_sender(Some(sender.to_string()))
            .task("registry/record/put")
            .build_unauthorized("proofInvalid: the proof did not verify")
    }

    #[tokio::test]
    async fn unauthenticated_refusals_do_not_use_up_an_authenticated_senders_budget() {
        let recording = Arc::new(Recording::default());
        let bounded = BoundedAuditLogger::with_budget(
            recording.clone(),
            DEFAULT_UNPROVEN_PER_WINDOW,
            Duration::from_secs(3600),
        );

        for _ in 0..1000 {
            bounded.log(unproven()).await;
        }
        bounded.log(unproven_over("did:example:peer")).await;

        let entries = recording.0.lock().unwrap();
        assert_eq!(entries.len(), DEFAULT_UNPROVEN_PER_WINDOW as usize + 1);
        let last = entries.last().expect("an entry");
        assert_eq!(
            last.authenticated_sender.as_deref(),
            Some("did:example:peer"),
            "the authenticated refusal is recorded individually"
        );
        assert_eq!(last.claimed_actor.as_deref(), Some("did:example:peer"));
        assert_eq!(last.task.as_deref(), Some("registry/record/put"));
    }

    #[tokio::test]
    async fn each_authenticated_sender_has_its_own_budget() {
        let recording = Arc::new(Recording::default());
        let bounded =
            BoundedAuditLogger::with_budget(recording.clone(), 2, Duration::from_secs(3600));

        for _ in 0..10 {
            bounded.log(unproven_over("did:example:noisy")).await;
        }
        bounded.log(unproven_over("did:example:quiet")).await;
        assert_eq!(recording.0.lock().unwrap().len(), 3);

        bounded.flush().await;
        let entries = recording.0.lock().unwrap();
        let summary = entries.last().expect("a summary");
        assert_eq!(
            summary.authenticated_sender.as_deref(),
            Some("did:example:noisy")
        );
        let extra = summary.extra.as_deref().unwrap_or_default();
        assert!(extra.contains("8 further refusals"), "{extra}");
        assert!(extra.contains("proofInvalid=8"), "{extra}");
        assert!(extra.contains("registry/record/put=8"), "{extra}");
    }

    #[tokio::test]
    async fn senders_beyond_the_tracked_limit_share_one_budget() {
        let recording = Arc::new(Recording::default());
        let bounded =
            BoundedAuditLogger::with_budget(recording.clone(), 1, Duration::from_secs(3600));

        for index in 0..MAX_TRACKED_SENDERS + 5 {
            bounded
                .log(unproven_over(&format!("did:example:sender-{index}")))
                .await;
        }
        assert_eq!(
            recording.0.lock().unwrap().len(),
            MAX_TRACKED_SENDERS + 1,
            "one entry per tracked sender, then one for all the others"
        );
        let budget = bounded.budget.lock().unwrap();
        assert!(budget.sources.len() <= MAX_TRACKED_SENDERS + 2);
    }

    #[test]
    fn a_summary_names_a_bounded_number_of_keys() {
        let mut tally = Tally::default();
        for index in 0..100 {
            tally.add(&format!("code-{index}"));
        }
        assert_eq!(tally.0.len(), MAX_SUMMARY_KEYS + 1);
        assert_eq!(tally.0.get("other"), Some(&(100 - MAX_SUMMARY_KEYS as u64)));
    }
}
