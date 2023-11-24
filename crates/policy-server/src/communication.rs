use anyhow::Result;
use core::fmt;
use policy_evaluator::admission_response::AdmissionResponse;
use policy_evaluator::policy_evaluator::ValidateRequest;
use std::collections::HashMap;
use tokio::sync::oneshot;

use crate::policy_downloader::FetchedPolicies;
use crate::settings::Policy;

#[derive(Debug, Clone)]
pub(crate) enum RequestOrigin {
    Validate,
    Audit,
}

impl fmt::Display for RequestOrigin {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            RequestOrigin::Validate => write!(f, "validate"),
            RequestOrigin::Audit => write!(f, "audit"),
        }
    }
}

#[derive(Debug)]
pub(crate) struct EvalRequest {
    pub policy_id: String,
    pub req: ValidateRequest,
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
