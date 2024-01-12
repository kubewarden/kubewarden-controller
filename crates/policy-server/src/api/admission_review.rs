use policy_evaluator::admission_request::AdmissionRequest;
use policy_evaluator::admission_response::AdmissionResponse;

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AdmissionReviewRequest {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub api_version: Option<String>,

    pub request: AdmissionRequest,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AdmissionReviewResponse {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub api_version: Option<String>,

    pub response: AdmissionResponse,
}

impl AdmissionReviewResponse {
    pub fn new(response: AdmissionResponse) -> Self {
        AdmissionReviewResponse {
            api_version: Some(String::from("admission.k8s.io/v1")),
            kind: Some(String::from("AdmissionReview")),
            response,
        }
    }
}
