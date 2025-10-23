use crate::SharedData;
use crate::handlers::trqp::handle_trqp_authorization;
use app::storage::repository::TrustRecordRepository;
use axum::{Router, routing::post};

pub mod trqp;

pub fn application_routes<R>(api_prefix: &str, shared_data: SharedData<R>) -> Router
where
    R: TrustRecordRepository + Send + ?Sized + 'static,
{
    let all_handlers = Router::new()
        .route("/authorization", post(handle_trqp_authorization::<R>))
        .route("/recognition", post(handle_trqp_authorization::<R>));

    let router = if api_prefix.is_empty() || api_prefix == "/" {
        Router::new().merge(all_handlers)
    } else {
        Router::new().nest(api_prefix, all_handlers)
    };
    router.with_state(shared_data)
}
