use crate::didcomm::handlers::{
    BaseHandler, problem_report::ProblemReportHandler, trqp::TRQPMessagesHandler,
    trust_tasks::TrustTasksHandler,
};
use crate::storage::repository::TrustRecordAdminRepository;
use crate::trust_tasks::TaskHandler;
use std::sync::Arc;

impl<R: ?Sized + TrustRecordAdminRepository + 'static> BaseHandler<R> {
    /// `tasks` is the registry's shared Trust Task handler: the same one the
    /// TSP binding uses, so both answer from one replay record and one audit
    /// trail.
    pub fn build_from_arc(repository: Arc<R>, tasks: TaskHandler) -> BaseHandler<R> {
        let trqp = TRQPMessagesHandler {
            repository: repository.clone(),
        };

        let problem_report_handler = ProblemReportHandler::new();

        // Trust Task DIDComm binding: routes the `registry/*` task family over
        // the same mediator connection, alongside the legacy read-only
        // trqp/1.0 protocol. Record changes are accepted only as signed
        // `registry/record/*` Trust Tasks.
        let trust_tasks = TrustTasksHandler::new(tasks);

        BaseHandler {
            repository,
            protocols_handlers: vec![
                Arc::new(trqp),
                Arc::new(problem_report_handler),
                Arc::new(trust_tasks),
            ],
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capabilities::DispatcherHandle;
    use crate::storage::adapters::local_storage::LocalStorage;
    use crate::trust_tasks::build_dispatcher;
    use tokio::sync::RwLock;

    #[test]
    fn no_handler_accepts_the_retired_tr_admin_protocol() {
        let repo = Arc::new(LocalStorage::new());
        let dispatcher: DispatcherHandle =
            Arc::new(RwLock::new(Arc::new(build_dispatcher(repo.clone()))));
        let tasks = TaskHandler::new(
            dispatcher,
            "did:example:registry",
            Vec::new(),
            trust_tasks_rs::erase_verifier(trust_tasks_proof::affinidi::Verifier::for_did_key()),
        );
        let handler = BaseHandler::build_from_arc(repo, tasks);

        let accepted: Vec<String> = handler
            .protocols_handlers
            .iter()
            .flat_map(|protocol| protocol.get_supported_inbound_message_types())
            .collect();

        assert!(
            accepted
                .iter()
                .all(|message_type| !message_type.contains("/protocols/tr-admin/")),
            "tr-admin/1.0 message types are still routed: {accepted:?}"
        );
    }
}
