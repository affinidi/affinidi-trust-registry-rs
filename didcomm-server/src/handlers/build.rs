use crate::{
    configs::DidcommServerConfigs,
    handlers::{
        BaseHandler, admin::AdminMessagesHandler, problem_report::ProblemReportHandler,
        trqp::TRQPMessagesHandler,
    },
};
use app::{
    audit::audit_logger::LoggingAuditLogger, storage::repository::TrustRecordAdminRepository,
};
use std::sync::Arc;

impl<R: ?Sized + TrustRecordAdminRepository + 'static> BaseHandler<R> {
    pub fn build_from_arc(repository: Arc<R>, config: Arc<DidcommServerConfigs>) -> BaseHandler<R> {
        let trqp = TRQPMessagesHandler {
            repository: repository.clone(),
        };

        let audit_logger = Arc::new(LoggingAuditLogger::new(
            config.admin_api_config.audit_config.clone(),
        ));
        let tradmin = AdminMessagesHandler {
            repository: repository.clone(),
            admin_config: config.admin_api_config.clone(),
            audit_service: audit_logger,
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
