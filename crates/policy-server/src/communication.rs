use anyhow::Result;
use policy_evaluator::admission_response::AdmissionResponse;
use std::collections::HashMap;
use tokio::sync::oneshot;

use crate::admission_review::AdmissionRequest;
use crate::settings::Policy;

#[derive(Debug)]
pub(crate) struct EvalRequest {
    pub policy_id: String,
    pub req: AdmissionRequest,
    pub resp_chan: oneshot::Sender<Option<AdmissionResponse>>,
    pub parent_span: tracing::Span,
}

// Holds the bootstrap parameters of a worker pool
pub(crate) struct WorkerPoolBootRequest {
    // list of policies to load into each worker
    pub policies: HashMap<String, Policy>,
    // size of the worker pool
    pub pool_size: usize,
    // channel used to send back bootstrap status:
    // * Ok(()) -> all good
    // * Err(e) -> one or more workers couldn't bootstrap
    pub resp_chan: oneshot::Sender<Result<()>>,
}

// Holds the bootstrap parameters of a kube pooler
pub(crate) struct KubePollerBootRequest {
    // channel used to send back bootstrap status:
    // * Ok(()) -> all good
    // * Err(e) -> one or more workers couldn't bootstrap
    pub resp_chan: oneshot::Sender<Result<()>>,
}
