use crate::{
    audit::audit_logger::BaseAuditLogger, storage::repository::TrustRecordAdminRepository,
};
use crate::{
    configs::DidcommConfig,
    didcomm::handlers::{
        BaseHandler, admin::AdminMessagesHandler, problem_report::ProblemReportHandler,
        trqp::TRQPMessagesHandler,
    },
};
use std::sync::Arc;

impl BaseHandler {
    pub fn build_from_arc<R: ?Sized + TrustRecordAdminRepository + 'static>(
        repository: Arc<R>,
        config: Arc<DidcommConfig>,
    ) -> BaseHandler {
        let trqp = TRQPMessagesHandler {
            repository: repository.clone(),
        };

        let audit_logger = Arc::new(BaseAuditLogger::new(
            config.admin_config.audit_config.clone(),
        ));
        let tradmin = AdminMessagesHandler {
            repository: repository.clone(),
            admin_config: config.admin_config.clone(),
            audit_service: audit_logger,
        };

        let problem_report_handler = ProblemReportHandler::new();

        BaseHandler {
            protocols_handlers: vec![
                Arc::new(trqp),
                Arc::new(tradmin),
                Arc::new(problem_report_handler),
            ],
        }
    }
}
