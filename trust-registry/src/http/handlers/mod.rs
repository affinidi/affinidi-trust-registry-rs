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

pub fn application_routes<R>(api_prefix: &str, shared_data: SharedData<R>) -> Router
where
    R: TrustRecordRepository + Send + ?Sized + 'static,
{
    let all_handlers = Router::new()
        .route("/authorization", post(trqp::handle_trqp_authorization::<R>))
        .route("/recognition", post(trqp::handle_trqp_recognition::<R>))
        .route("/trust-tasks", post(trust_tasks::handle_trust_task::<R>))
        .route(
            "/.well-known/did.json",
            get(wellknown::handle_wellknown_did_json::<R>),
        );

    let max_body_bytes = shared_data.config.server_config.http_limits.max_body_bytes;
    let router = if api_prefix.is_empty() || api_prefix == "/" {
        Router::new().merge(all_handlers)
    } else {
        Router::new().nest(api_prefix, all_handlers)
    };
    router
        .layer(DefaultBodyLimit::max(max_body_bytes))
        .with_state(shared_data)
}
