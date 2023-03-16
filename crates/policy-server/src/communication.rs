use anyhow::Result;
use policy_evaluator::admission_response::AdmissionResponse;
use std::collections::HashMap;
use tokio::sync::oneshot;

use crate::admission_review::AdmissionRequest;
use crate::policy_downloader::FetchedPolicies;
use crate::settings::Policy;

#[derive(Debug, Clone)]
pub(crate) enum RequestOrigin {
    Validate,
    Audit,
}

#[derive(Debug)]
pub(crate) struct EvalRequest {
    pub policy_id: String,
    pub req: AdmissionRequest,
    pub resp_chan: oneshot::Sender<Option<AdmissionResponse>>,
    pub parent_span: tracing::Span,
    pub request_origin: RequestOrigin,
}

/// Holds the bootstrap parameters of a worker pool
pub(crate) struct WorkerPoolBootRequest {
    /// list of policies to load into each worker
    pub policies: HashMap<String, Policy>,

    /// Locations of the WebAssembly modules on the local disk
    pub fetched_policies: FetchedPolicies,

    /// size of the worker pool
    pub pool_size: usize,

    /// channel used to send back bootstrap status:
    /// * Ok(()) -> all good
    /// * Err(e) -> one or more workers couldn't bootstrap
    pub resp_chan: oneshot::Sender<Result<()>>,
}
