use policy_evaluator::admission_response::AdmissionResponse;
use serde::{Deserialize, Serialize};

/// A review request that contains a raw json value.
#[derive(Serialize, Deserialize, Debug)]
pub struct RawReviewRequest {
    pub request: serde_json::Value,
}

/// A review response from a raw policy evaluation.
#[derive(Serialize, Deserialize, Debug)]
pub struct RawReviewResponse {
    pub response: AdmissionResponse,
}

impl RawReviewResponse {
    pub(crate) fn new(response: AdmissionResponse) -> Self {
        RawReviewResponse { response }
    }
}
