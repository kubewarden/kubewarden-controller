use tokio::sync::Semaphore;

use crate::evaluation::EvaluationEnvironment;
use std::sync::Arc;

pub(crate) struct ApiServerState {
    pub(crate) semaphore: Semaphore,
    pub(crate) evaluation_environment: Arc<EvaluationEnvironment>,
}
