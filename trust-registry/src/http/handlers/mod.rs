use crate::SharedData;
use crate::storage::repository::TrustRecordRepository;
use axum::{
    Router,
    extract::DefaultBodyLimit,
    routing::{get, post},
};

pub mod trqp;
pub mod trust_tasks;
pub mod wellknown;

/// The registry's HTTP routes over `shared_data`, at the root. A host that
/// wants them under a prefix nests the router itself
/// ([`TrustRegistry::router`](crate::TrustRegistry::router)).
pub fn application_routes<R>(shared_data: SharedData<R>) -> Router
where
    R: TrustRecordRepository + Send + ?Sized + 'static,
{
    let max_body_bytes = shared_data.config.server_config.http_limits.max_body_bytes;
    Router::new()
        .route("/authorization", post(trqp::handle_trqp_authorization::<R>))
        .route("/recognition", post(trqp::handle_trqp_recognition::<R>))
        .route("/trust-tasks", post(trust_tasks::handle_trust_task::<R>))
        .route(
            "/.well-known/did.json",
            get(wellknown::handle_wellknown_did_json::<R>),
        )
        .layer(DefaultBodyLimit::max(max_body_bytes))
        .with_state(shared_data)
}
