use crate::{
    audit::audit_logger::BaseAuditLogger, storage::repository::TrustRecordAdminRepository,
};
use crate::{
    configs::DidcommConfig,
    didcomm::handlers::{
        BaseHandler, admin::AdminMessagesHandler, problem_report::ProblemReportHandler,
        trqp::TRQPMessagesHandler, trust_tasks::TrustTasksHandler,
    },
};
use std::sync::Arc;

impl<R: ?Sized + TrustRecordAdminRepository + 'static> BaseHandler<R> {
    pub fn build_from_arc(
        repository: Arc<R>,
        config: Arc<DidcommConfig>,
        verifier: Arc<dyn trust_tasks_rs::DynProofVerifier>,
    ) -> BaseHandler<R> {
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

        // Trust Task DIDComm binding: routes the `registry/*` task family over
        // the same mediator connection, alongside the legacy trqp/1.0 and
        // tr-admin/1.0 protocols.
        let trust_tasks =
            TrustTasksHandler::new(repository.clone(), config.admin_config.clone(), verifier);

        BaseHandler {
            repository,
            protocols_handlers: vec![
                Arc::new(trqp),
                Arc::new(tradmin),
                Arc::new(problem_report_handler),
                Arc::new(trust_tasks),
            ],
        }
    }
}
