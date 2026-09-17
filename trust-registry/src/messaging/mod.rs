//! Delivery-layer messaging for a TSP-enabled registry (feature `tsp`).
//!
//! A DIDComm-only registry drives the mediator socket with the hand-rolled
//! pickup loop in [`crate::didcomm::listener`]. A TSP-enabled registry instead
//! drives it through the D1 delivery layer ([`service::build_messaging`] +
//! [`service::run_inbound_loop`]) so that:
//!
//! - inbound TSP **relationship-control** frames are recorded and answered
//!   (Rev 3 §7.2.2), rather than misrouted into the Trust-Task dispatcher; and
//! - TSP relationship state is **persisted** across a restart
//!   ([`relationship_store`]), so a restarted registry does not silently drop an
//!   established peer's traffic.
//!
//! The DIDComm arm is behaviourally identical to the pickup loop — the same
//! [`crate::didcomm::listener::MessageHandler`] handles each rehydrated message.

pub mod kv;
pub mod outbox_store;
pub mod relationship_store;
pub mod service;
pub mod tsp_inbound;
