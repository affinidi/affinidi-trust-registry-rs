//! Liveness and capability reporting for `/health`.
//!
//! The registry has two independent surfaces: a read path (REST/TRQP over
//! HTTP) and a write path (Trust Tasks over DIDComm, via a mediator). They
//! fail independently, and an unreachable mediator must not take the read
//! path down with it — a registry that can still answer recognition and
//! authorization queries is useful even when no new records can arrive.
//!
//! What it must *not* do is claim to be fully healthy while writes are
//! impossible. A green health check masking a dead write path is how a
//! deployment ends up silently serving records that stopped updating hours
//! ago. So the write path's state is reported explicitly.
//!
//! `/health` keeps returning **200** while degraded: the process is alive and
//! serving reads, so an orchestrator should not evict or restart it — the
//! mediator being unreachable is rarely something a restart fixes. The
//! degradation is carried in the body, where a monitor can alert on it.

use std::sync::RwLock;

/// State of the DIDComm write path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WriteStatus {
    /// The DIDComm listener is running; record mutations can arrive.
    Ok,
    /// DIDComm is switched off by configuration (`ENABLE_DIDCOMM != "true"`).
    /// This is a deployment choice, not a fault — a read-only registry is a
    /// legitimate configuration, so it does not degrade health.
    Disabled,
    /// DIDComm was enabled but the listener stopped — typically the mediator
    /// is unreachable or authentication failed. Reads continue; no new record
    /// mutations can be received until it recovers.
    Unavailable,
}

impl WriteStatus {
    /// Lowercase wire value for the `writes` field.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Ok => "ok",
            Self::Disabled => "disabled",
            Self::Unavailable => "unavailable",
        }
    }

    /// Whether this state should be reported as degraded overall.
    #[must_use]
    pub fn is_degraded(self) -> bool {
        matches!(self, Self::Unavailable)
    }
}

/// Shared, mutable health state, updated by the supervisor and read by the
/// `/health` handler.
#[derive(Debug)]
pub struct RegistryHealth {
    writes: RwLock<WriteState>,
}

#[derive(Debug, Clone)]
struct WriteState {
    status: WriteStatus,
    /// Why writes are unavailable, when they are — surfaced so an operator
    /// does not have to correlate against server logs to find out.
    detail: Option<String>,
}

impl RegistryHealth {
    /// Create health state for a server whose DIDComm path is enabled or not.
    #[must_use]
    pub fn new(didcomm_enabled: bool) -> Self {
        Self {
            writes: RwLock::new(WriteState {
                status: if didcomm_enabled {
                    WriteStatus::Ok
                } else {
                    WriteStatus::Disabled
                },
                detail: None,
            }),
        }
    }

    /// Record that the DIDComm listener has stopped, with the reason.
    pub fn mark_writes_unavailable(&self, detail: impl Into<String>) {
        let mut guard = self.write_lock();
        guard.status = WriteStatus::Unavailable;
        guard.detail = Some(detail.into());
    }

    /// Current write-path status.
    #[must_use]
    pub fn write_status(&self) -> WriteStatus {
        self.read_lock().status
    }

    /// The `/health` response body.
    ///
    /// `status` stays exactly `"OK"` in the healthy case — it is a documented
    /// wire value that existing probes match on — and becomes `"degraded"`
    /// only when the write path has failed.
    #[must_use]
    pub fn to_json(&self) -> serde_json::Value {
        let state = self.read_lock().clone();
        let mut body = serde_json::json!({
            "status": if state.status.is_degraded() { "degraded" } else { "OK" },
            "writes": state.status.as_str(),
        });
        if let Some(detail) = state.detail {
            body["detail"] = serde_json::Value::String(detail);
        }
        body
    }

    /// Read the state, tolerating a poisoned lock.
    ///
    /// A panic while holding this lock must not turn every subsequent health
    /// probe into a panic — the reported state is still readable and is more
    /// useful than an unresponsive endpoint.
    fn read_lock(&self) -> std::sync::RwLockReadGuard<'_, WriteState> {
        self.writes
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn write_lock(&self) -> std::sync::RwLockWriteGuard<'_, WriteState> {
        self.writes
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// The healthy body must stay byte-identical to what shipped before this
    /// module existed, apart from the additive `writes` field: probes in the
    /// wild match on `status == "OK"`.
    #[test]
    fn healthy_reports_ok() {
        let health = RegistryHealth::new(true);
        assert_eq!(health.to_json(), json!({ "status": "OK", "writes": "ok" }));
        assert!(!health.write_status().is_degraded());
    }

    /// DIDComm switched off is a configuration choice, not a fault. A
    /// read-only registry must not alarm every monitor that watches it.
    #[test]
    fn disabled_didcomm_is_not_degraded() {
        let health = RegistryHealth::new(false);
        assert_eq!(
            health.to_json(),
            json!({ "status": "OK", "writes": "disabled" })
        );
        assert!(!health.write_status().is_degraded());
    }

    #[test]
    fn failed_listener_degrades_and_explains_why() {
        let health = RegistryHealth::new(true);
        health.mark_writes_unavailable("mediator unreachable: NXDOMAIN");

        assert_eq!(
            health.to_json(),
            json!({
                "status": "degraded",
                "writes": "unavailable",
                "detail": "mediator unreachable: NXDOMAIN",
            })
        );
        assert!(health.write_status().is_degraded());
    }

    /// A registry configured without DIDComm can still be marked unavailable
    /// if something else stops the path; the transition must not be silently
    /// ignored because the initial state was `Disabled`.
    #[test]
    fn disabled_can_still_transition_to_unavailable() {
        let health = RegistryHealth::new(false);
        health.mark_writes_unavailable("stopped");
        assert_eq!(health.write_status(), WriteStatus::Unavailable);
    }

    #[test]
    fn detail_is_absent_until_something_fails() {
        let health = RegistryHealth::new(true);
        assert!(health.to_json().get("detail").is_none());
    }

    #[test]
    fn wire_values_are_stable() {
        assert_eq!(WriteStatus::Ok.as_str(), "ok");
        assert_eq!(WriteStatus::Disabled.as_str(), "disabled");
        assert_eq!(WriteStatus::Unavailable.as_str(), "unavailable");
    }
}
