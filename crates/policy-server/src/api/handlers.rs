use axum::{
    extract::{self, FromRequest, Query},
    http::{header, StatusCode},
    response::IntoResponse,
    Json,
};
use policy_evaluator::{
    admission_request::AdmissionRequest, admission_response::AdmissionResponse,
    policy_evaluator::ValidateRequest,
};

use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::task;
use tracing::{debug, error, Span};

use crate::{
    api::{
        admission_review::{AdmissionReviewRequest, AdmissionReviewResponse},
        api_error::ApiError,
        raw_review::{RawReviewRequest, RawReviewResponse},
        service::{evaluate, RequestOrigin},
        state::ApiServerState,
    },
    profiling,
};
use crate::{evaluation::errors::EvaluationError, profiling::ReportGenerationError};

// create an extractor that internally uses `axum::Json` but has a custom rejection
#[derive(FromRequest)]
#[from_request(via(axum::Json), rejection(ApiError))]
pub(crate) struct JsonExtractor<T>(T);

impl<T: Serialize> IntoResponse for JsonExtractor<T> {
    fn into_response(self) -> axum::response::Response {
        let Self(value) = self;
        axum::Json(value).into_response()
    }
}

// note about tracing: we are manually adding the `policy_id` field
// because otherwise the automatic "export" would cause the string to be
// double quoted. This would make searching by tag inside of Jaeger ugly.
// A concrete example: the automatic generation leads to the creation
// of `policy_id = "\"psp-capabilities\""` instead of `policy_id = "psp-capabilities"`
#[tracing::instrument(
    name = "audit",
    fields(
        request_uid=tracing::field::Empty,
        host=crate::config::HOSTNAME.as_str(),
        policy_id=policy_id.as_str(),
        name=tracing::field::Empty,
        namespace=tracing::field::Empty,
        operation=tracing::field::Empty,
        subresource=tracing::field::Empty,
        kind_group=tracing::field::Empty,
        kind_version=tracing::field::Empty,
        kind=tracing::field::Empty,
        resource_group=tracing::field::Empty,
        resource_version=tracing::field::Empty,
        resource=tracing::field::Empty,
        allowed=tracing::field::Empty,
        mutated=tracing::field::Empty,
        response_code=tracing::field::Empty,
        response_message=tracing::field::Empty,
    ),
    skip_all)]
///  Run a validation in "audit" mode.
pub(crate) async fn audit_handler(
    extract::State(state): extract::State<Arc<ApiServerState>>,
    extract::Path(policy_id): extract::Path<String>,
    extract::Json(admission_review): extract::Json<AdmissionReviewRequest>,
) -> Result<Json<AdmissionReviewResponse>, (StatusCode, ApiError)> {
    debug!(admission_review = %serde_json::to_string(&admission_review).unwrap().as_str());

    populate_span_with_admission_request_data(&admission_review.request);

    let response = acquire_semaphore_and_evaluate(
        state,
        policy_id,
        ValidateRequest::AdmissionRequest(admission_review.request),
        RequestOrigin::Audit,
    )
    .await
    .map_err(handle_evaluation_error)?;

    populate_span_with_policy_evaluation_results(&response);

    Ok(Json(AdmissionReviewResponse::new(response)))
}

// note about tracing: we are manually adding the `policy_id` field
// because otherwise the automatic "export" would cause the string to be
// double quoted. This would make searching by tag inside of Jaeger ugly.
// A concrete example: the automatic generation leads to the creation
// of `policy_id = "\"psp-capabilities\""` instead of `policy_id = "psp-capabilities"`
#[tracing::instrument(
    name = "validation",
    fields(
        request_uid=tracing::field::Empty,
        host=crate::config::HOSTNAME.as_str(),
        policy_id=policy_id.as_str(),
        name=tracing::field::Empty,
        namespace=tracing::field::Empty,
        operation=tracing::field::Empty,
        subresource=tracing::field::Empty,
        kind_group=tracing::field::Empty,
        kind_version=tracing::field::Empty,
        kind=tracing::field::Empty,
        resource_group=tracing::field::Empty,
        resource_version=tracing::field::Empty,
        resource=tracing::field::Empty,
        allowed=tracing::field::Empty,
        mutated=tracing::field::Empty,
        response_code=tracing::field::Empty,
        response_message=tracing::field::Empty,
    ),
    skip_all)]
/// Validate a request against a policy.
pub(crate) async fn validate_handler(
    extract::State(state): extract::State<Arc<ApiServerState>>,
    extract::Path(policy_id): extract::Path<String>,
    JsonExtractor(admission_review): JsonExtractor<AdmissionReviewRequest>,
) -> Result<Json<AdmissionReviewResponse>, (StatusCode, ApiError)> {
    debug!(admission_review = %serde_json::to_string(&admission_review).unwrap().as_str());

    populate_span_with_admission_request_data(&admission_review.request);

    let response = acquire_semaphore_and_evaluate(
        state,
        policy_id,
        ValidateRequest::AdmissionRequest(admission_review.request),
        RequestOrigin::Validate,
    )
    .await
    .map_err(handle_evaluation_error)?;

    populate_span_with_policy_evaluation_results(&response);

    Ok(Json(AdmissionReviewResponse::new(response)))
}

#[tracing::instrument(
    name = "validation_raw",
    fields(
        request_uid=tracing::field::Empty,
        host=crate::config::HOSTNAME.as_str(),
        policy_id=policy_id.as_str(),
        allowed=tracing::field::Empty,
        mutated=tracing::field::Empty,
        response_code=tracing::field::Empty,
        response_message=tracing::field::Empty,
    ),
    skip_all)]
pub(crate) async fn validate_raw_handler(
    extract::State(state): extract::State<Arc<ApiServerState>>,
    extract::Path(policy_id): extract::Path<String>,
    extract::Json(raw_review): extract::Json<RawReviewRequest>,
) -> Result<Json<RawReviewResponse>, (StatusCode, ApiError)> {
    debug!(raw_review = %serde_json::to_string(&raw_review).unwrap().as_str());

    let response = acquire_semaphore_and_evaluate(
        state,
        policy_id,
        ValidateRequest::Raw(raw_review.request),
        RequestOrigin::Validate,
    )
    .await
    .map_err(handle_evaluation_error)?;

    populate_span_with_policy_evaluation_results(&response);

    Ok(Json(RawReviewResponse::new(response)))
}

#[derive(Deserialize)]
pub(crate) struct ProfileParams {
    /// profiling frequency (Hz)
    #[serde(default = "profiling::default_profiling_frequency")]
    pub frequency: i32,

    /// profiling time interval (seconds)
    #[serde(default = "profiling::default_profiling_interval")]
    pub interval: u64,
}

// Generate a pprof CPU profile using google's pprof format
// The report is generated and sent to the user as binary data
pub(crate) async fn pprof_get_cpu(
    profiling_params: Query<ProfileParams>,
) -> Result<impl axum::response::IntoResponse, (StatusCode, ApiError)> {
    let frequency = profiling_params.frequency;
    let interval = profiling_params.interval;

    let end = async move {
        tokio::time::sleep(tokio::time::Duration::from_secs(interval)).await;
        Ok(())
    };

    let body = profiling::start_one_cpu_profile(end, frequency)
        .await
        .map_err(handle_pprof_error)?;

    let mut headers = header::HeaderMap::new();
    headers.insert(
        header::CONTENT_DISPOSITION,
        r#"attachment; filename="cpu_profile"#.parse().unwrap(),
    );
    headers.insert(
        header::CONTENT_LENGTH,
        body.len().to_string().parse().unwrap(),
    );
    headers.insert(
        header::CONTENT_TYPE,
        mime::APPLICATION_OCTET_STREAM.to_string().parse().unwrap(),
    );

    Ok((headers, body))
}
pub(crate) async fn readiness_handler() -> StatusCode {
    StatusCode::OK
}

async fn acquire_semaphore_and_evaluate(
    state: Arc<ApiServerState>,
    policy_id: String,
    validate_request: ValidateRequest,
    request_origin: RequestOrigin,
) -> Result<AdmissionResponse, EvaluationError> {
    let _permit = state
        .semaphore
        .acquire()
        .await
        .expect("semaphore acquire failed");

    let state = state.clone();
    let span = Span::current();
    let response = task::spawn_blocking(move || {
        let _enter = span.enter();
        let evaluation_environment = &state.evaluation_environment;

        evaluate(
            evaluation_environment,
            &policy_id,
            &validate_request,
            request_origin,
        )
    })
    .await
    .expect("task::spawn_blocking failed")?;

    debug!(response =? &response, "policy evaluated");

    Ok(response)
}

fn populate_span_with_admission_request_data(adm_req: &AdmissionRequest) {
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

fn populate_span_with_policy_evaluation_results(response: &AdmissionResponse) {
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

fn handle_evaluation_error(error: EvaluationError) -> (StatusCode, ApiError) {
    match error {
        EvaluationError::PolicyNotFound(_) => (
            StatusCode::NOT_FOUND,
            ApiError {
                status: StatusCode::NOT_FOUND,
                message: error.to_string(),
            },
        ),
        err => {
            error!("Evaluation error: {}", err);

            (
                StatusCode::INTERNAL_SERVER_ERROR,
                ApiError {
                    status: StatusCode::INTERNAL_SERVER_ERROR,
                    message: "Something went wrong".to_owned(),
                },
            )
        }
    }
}

fn handle_pprof_error(error: ReportGenerationError) -> (StatusCode, ApiError) {
    error!("pprof error: {}", error);

    (
        StatusCode::INTERNAL_SERVER_ERROR,
        ApiError {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            message: "Something went wrong".to_owned(),
        },
    )
}
