//! TSP relationship-control policy for the registry.
//!
//! [`decide_control`] is a pure function — testable without a mediator or a
//! socket — that says what the registry does about an inbound TSP relationship
//! request (§7.2). The answering side (sending the accept/cancel) lives in
//! [`super::service`]; the recording of the relationship happens inside the SDK
//! transport before this is reached.
//!
//! Ported verbatim from `vta-service::messaging::tsp_inbound`: the registry is a
//! responder like the VTA's control plane, so its policy is identical.

use affinidi_messaging_core::RelationshipRequest;

/// What the registry does about an inbound TSP relationship request (§7.2).
///
/// Separated from the sends so the *policy* can be tested without a mediator or
/// a socket.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ControlDecision {
    /// Send an accept (`XRFA`). The transport has already recorded the
    /// relationship; this completes it.
    Accept,
    /// Send a cancellation (`XRFD`), carrying why. Named for the wire action
    /// rather than the intent, because it serves **answering** a peer's
    /// cancellation of a mutual relationship (§7.3) rather than refusing
    /// anything.
    Cancel(&'static str),
    /// Send nothing. The message needed recording and nothing else.
    Nothing,
}

/// Decide what to do about a relationship request.
///
/// # Why there is no ACL check here
///
/// A peer may send its invite and its first Trust Task together (§3.6 permits
/// exactly that). Refusing the invite would make §7.2.2 then drop the Trust
/// Task — so the peer's actual request goes unanswered, and the cancellation it
/// gets is a *control* message its application layer never sees. So the
/// relationship is formed with any sender TSP has authenticated, and **the ACL
/// remains the only gate, where it already lives** — at the Trust Task layer,
/// which answers with a named `permissionDenied`/`malformedRequest` envelope the
/// peer can act on. A relationship grants no authority on its own, every task
/// behind it is still checked, and the sender VID is cryptographically proven,
/// so there is no enumeration exposure.
pub fn decide_control(request: RelationshipRequest, reply_expected: bool) -> ControlDecision {
    match request {
        // §7.2.5: an invite may introduce a VID, whose signature the transport
        // verified before this was reached. Not gated here either — the
        // introduced VID gains a relationship and no authority.
        RelationshipRequest::Invite => ControlDecision::Accept,
        // The peer accepted an invite we sent. The transport recorded the state
        // change; answering an accept would start a loop.
        RelationshipRequest::Accept => ControlDecision::Nothing,
        // §7.3: a cancellation for a relationship held in both directions is
        // answered with one of our own before forgetting it. `reply_expected`
        // is the transport's reading of that condition, deliberately not
        // re-derived here.
        RelationshipRequest::Cancel => {
            if reply_expected {
                ControlDecision::Cancel("the peer cancelled a mutual relationship (§7.3)")
            } else {
                ControlDecision::Nothing
            }
        }
        // `RelationshipRequest` is `#[non_exhaustive]`. Record and say nothing,
        // rather than agree to something we cannot describe.
        _ => ControlDecision::Nothing,
    }
}

#[cfg(test)]
mod tests {
    use super::{ControlDecision, decide_control};
    use affinidi_messaging_core::RelationshipRequest;

    /// An invite is accepted from any sender TSP authenticated, because the ACL
    /// gate lives at the Trust Task layer. Refusing here drops the peer's first
    /// task and answers it with nothing.
    #[test]
    fn an_invite_is_accepted_and_the_acl_gate_stays_at_the_task_layer() {
        assert_eq!(
            decide_control(RelationshipRequest::Invite, false),
            ControlDecision::Accept,
        );
    }

    /// Answering an accept would start a loop: the peer answers our answer.
    #[test]
    fn an_accept_is_not_answered() {
        assert_eq!(
            decide_control(RelationshipRequest::Accept, false),
            ControlDecision::Nothing
        );
    }

    /// §7.3 — and `reply_expected` is the transport's reading of the condition,
    /// deliberately not re-derived here.
    #[test]
    fn a_cancellation_is_answered_only_when_the_relationship_was_mutual() {
        assert_eq!(
            decide_control(RelationshipRequest::Cancel, false),
            ControlDecision::Nothing
        );
        assert!(matches!(
            decide_control(RelationshipRequest::Cancel, true),
            ControlDecision::Cancel(_)
        ));
    }
}
