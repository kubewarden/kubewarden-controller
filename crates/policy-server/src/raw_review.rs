use policy_evaluator::admission_response::AdmissionResponse;
use serde::{Deserialize, Serialize};

/// A review request that contains a raw json value.
#[derive(Serialize, Deserialize, Debug)]
pub(crate) struct RawReviewRequest {
    pub(crate) request: serde_json::Value,
}

/// A review response from a raw policy evaluation.
#[derive(Serialize, Deserialize, Debug)]
pub(crate) struct RawReviewResponse {
    pub(crate) response: AdmissionResponse,
}

impl RawReviewResponse {
    pub(crate) fn new(response: AdmissionResponse) -> Self {
        RawReviewResponse { response }
    }
}
