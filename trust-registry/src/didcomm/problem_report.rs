//! DIDComm problem reports (DIDComm v2 "Problem Reports"). The registry sends
//! one in answer to a `trqp/1.0` query it cannot answer; see
//! `DIDCOMM_PROTOCOLS.md` for when each code is used. Sent through
//! `transport::send_problem_report`.

use serde_json::json;

/// The problem-report message type.
pub const PROBLEM_REPORT_TYPE: &str = "https://didcomm.org/report-problem/2.0/problem-report";

pub mod codes {
    pub const ERROR_UNAUTHORIZED: &str = "e.p.msg.unauthorized";
    pub const ERROR_BAD_REQUEST: &str = "e.p.msg.bad-request";
    pub const ERROR_NOT_FOUND: &str = "e.p.msg.not-found";
    pub const ERROR_CONFLICT: &str = "e.p.msg.conflict";
    pub const ERROR_INTERNAL: &str = "e.p.msg.internal-error";
}

/// Problem report structure following DIDComm problem-report protocol
/// <https://identity.foundation/didcomm-messaging/spec/#problem-reports>
#[derive(Debug, Clone)]
pub struct ProblemReport {
    pub code: String,
    pub comment: String,
    pub args: Option<Vec<String>>,
    pub escalate_to: Option<String>,
}

impl ProblemReport {
    pub fn new(code: impl Into<String>, comment: impl Into<String>) -> Self {
        Self {
            code: code.into(),
            comment: comment.into(),
            args: None,
            escalate_to: None,
        }
    }

    pub fn unauthorized(comment: impl Into<String>) -> Self {
        Self::new(codes::ERROR_UNAUTHORIZED, comment)
    }

    pub fn bad_request(comment: impl Into<String>) -> Self {
        Self::new(codes::ERROR_BAD_REQUEST, comment)
    }

    pub fn not_found(comment: impl Into<String>) -> Self {
        Self::new(codes::ERROR_NOT_FOUND, comment)
    }

    pub fn conflict(comment: impl Into<String>) -> Self {
        Self::new(codes::ERROR_CONFLICT, comment)
    }

    pub fn internal_error(comment: impl Into<String>) -> Self {
        Self::new(codes::ERROR_INTERNAL, comment)
    }

    pub fn with_args(mut self, args: Vec<String>) -> Self {
        self.args = Some(args);
        self
    }

    pub fn with_escalate_to(mut self, escalate_to: String) -> Self {
        self.escalate_to = Some(escalate_to);
        self
    }

    pub fn to_body(&self) -> serde_json::Value {
        let mut body = json!({
            "code": self.code,
            "comment": self.comment
        });

        if let Some(args) = &self.args {
            body["args"] = json!(args);
        }

        if let Some(escalate_to) = &self.escalate_to {
            body["escalate_to"] = json!(escalate_to);
        }

        body
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_problem_report_basic() {
        let report = ProblemReport::unauthorized("Invalid DID");
        let body = report.to_body();

        assert_eq!(body["code"], codes::ERROR_UNAUTHORIZED);
        assert_eq!(body["comment"], "Invalid DID");
    }

    #[test]
    fn test_problem_report_with_args() {
        let report = ProblemReport::bad_request("Missing fields")
            .with_args(vec!["entity_id".to_string(), "authority_id".to_string()]);
        let body = report.to_body();

        assert_eq!(body["code"], codes::ERROR_BAD_REQUEST);
        assert!(body["args"].is_array());
    }
}
