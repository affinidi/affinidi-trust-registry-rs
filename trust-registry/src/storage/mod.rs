pub mod adapters;
// Test-only. Each backend's suite uses a different subset of the fixture's
// hooks (peer, corrupter, guard) and service lookups, so any build with
// fewer than all backends leaves some of them unused.
#[cfg(test)]
#[allow(dead_code)]
pub(crate) mod conformance;
pub mod factory;
pub mod keyed;
pub mod repository;
