use std::sync::Arc;

use app::storage::repository::TrustRecordAdminRepository;

use crate::{
    configs::DidcommServerConfigs, 
    handlers::{
        BaseHandler, 
        admin::AdminMessagesHandler, 
        problem_report::ProblemReportHandler, 
        trqp::TRQPMessagesHandler
    }
};

impl<R: ?Sized + TrustRecordAdminRepository + 'static> BaseHandler<R> 
{
    pub fn build_from_arc(repository: Arc<R>, config: Arc<DidcommServerConfigs>) -> BaseHandler<R> {
        let trqp = TRQPMessagesHandler {
            repository: repository.clone(),
        };

        let tradmin = AdminMessagesHandler {
            repository: repository.clone(),
            admin_config: config.admin_api_config.clone(),
        };

        let problem_report_handler = ProblemReportHandler::new();

        BaseHandler {
            repository,
            protocols_handlers: vec![
                Arc::new(trqp), 
                Arc::new(tradmin),
                Arc::new(problem_report_handler),
            ],
        }
    }
}
