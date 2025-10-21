use std::sync::Arc;

use app::storage::{repository::TrustRecordRepository};

use crate::handlers::{trqp::TRQPMessagesHandler, BaseHandler};



impl<R: TrustRecordRepository + 'static> BaseHandler<R> {
    pub fn build(repository: Arc<R>) -> Self {


        let trqp = TRQPMessagesHandler {
           repository: repository.clone()
        };

        Self { repository, protocols_handlers: vec![Arc::new(trqp)] }

    }
}