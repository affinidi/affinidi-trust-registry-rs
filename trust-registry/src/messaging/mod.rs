//! The delivery-layer receive path of a TSP-enabled registry (feature `tsp`).
//!
//! The registry has two receive paths over its one mediator websocket:
//!
//! - **TSP disabled** (`ENABLE_TSP` is not `true`): the DIDComm pickup listener
//!   in [`crate::didcomm::listener`], with a 30-second offline sync.
//! - **TSP enabled**, for `DidCommSource::Managed` and
//!   `DidCommSource::SharedAtm`: [`service`], which receives DIDComm and TSP
//!   through the SDK's `DidCommTransport`. That transport records inbound TSP
//!   relationship-control frames (Rev 3 §7.2.2) and tags each message as
//!   traffic or control, so the registry answers control frames and never
//!   mistakes one for a Trust Task. On `Managed`, TSP relationship state is
//!   **persisted** across a restart ([`relationship_store`]), so a restarted
//!   registry does not silently drop an established peer's traffic.
//!
//! Both paths ack a message at the mediator only after it has been handled,
//! and use the same ledger so a message that arrives twice is handled once.
//! They differ in that the delivery-layer path has no periodic offline sync:
//! a message left queued after a failed attempt is offered again when the
//! mediator next pushes the inbox (on each websocket (re)connect). DIDComm
//! messages on either path go to the same
//! [`MessageHandler`](crate::didcomm::listener::MessageHandler).

pub mod kv;
pub mod relationship_store;
pub mod service;
pub mod tsp_inbound;
