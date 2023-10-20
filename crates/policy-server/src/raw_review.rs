use policy_evaluator::admission_response::AdmissionResponse;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug)]
pub(crate) struct RawReviewRequest {
    pub(crate) request: serde_json::Value,
}

#[derive(Serialize, Deserialize, Debug)]
pub(crate) struct RawReviewResponse {
    pub(crate) response: AdmissionResponse,
}

impl RawReviewResponse {
    pub(crate) fn new(response: AdmissionResponse) -> Self {
        RawReviewResponse { response }
    }
}
