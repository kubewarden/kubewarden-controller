use policy_evaluator::admission_response::AdmissionResponse;
use std::convert::Infallible;
use tracing::span::Span;
use warp::http::StatusCode;

use crate::admission_review::AdmissionRequest;

mod audit_and_validation;
pub(crate) use audit_and_validation::{audit, validation};

pub(crate) fn populate_span_with_admission_request_data(adm_req: &AdmissionRequest) {
    Span::current().record("kind", adm_req.kind.kind.as_str());
    Span::current().record("kind_group", adm_req.kind.group.as_str());
    Span::current().record("kind_version", adm_req.kind.version.as_str());
    Span::current().record("name", adm_req.name.clone().unwrap_or_default().as_str());
    Span::current().record(
        "namespace",
        adm_req.namespace.clone().unwrap_or_default().as_str(),
    );
    Span::current().record("operation", adm_req.operation.as_str());
    Span::current().record("request_uid", adm_req.uid.as_str());
    Span::current().record("resource", adm_req.resource.resource.as_str());
    Span::current().record("resource_group", adm_req.resource.group.as_str());
    Span::current().record("resource_version", adm_req.resource.version.as_str());
    Span::current().record(
        "subresource",
        adm_req.sub_resource.clone().unwrap_or_default().as_str(),
    );
}

pub(crate) fn populate_span_with_policy_evaluation_results(response: &AdmissionResponse) {
    Span::current().record("allowed", response.allowed);
    Span::current().record("mutated", response.patch.is_some());
    if let Some(status) = &response.status {
        if let Some(code) = &status.code {
            Span::current().record("response_code", code);
        }
        if let Some(message) = &status.message {
            Span::current().record("response_message", message.as_str());
        }
    }
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ServerErrorResponse {
    pub message: String,
}

pub(crate) async fn readiness() -> Result<impl warp::Reply, Infallible> {
    Ok(StatusCode::OK)
}
