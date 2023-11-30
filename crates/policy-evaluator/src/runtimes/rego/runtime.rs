use kubewarden_policy_sdk::settings::SettingsValidationResponse;
use serde::Deserialize;
use serde_json::json;
use tracing::{error, warn};

use crate::admission_response::{AdmissionResponse, AdmissionResponseStatus};
use crate::policy_evaluator::RegoPolicyExecutionMode;
use crate::policy_evaluator::{PolicySettings, ValidateRequest};
use crate::runtimes::rego::{
    context_aware, context_aware::KubernetesContext, errors::RegoRuntimeError, Stack,
};

pub(crate) struct Runtime<'a>(pub(crate) &'a mut Stack);

impl<'a> Runtime<'a> {
    pub fn validate(
        &mut self,
        settings: &PolicySettings,
        request: &ValidateRequest,
        ctx_data: &context_aware::KubernetesContext,
    ) -> AdmissionResponse {
        let uid = request.uid();

        // OPA and Gatekeeper expect arguments in different ways. Provide the ones that each expect.
        let (document_to_evaluate, data) = match self.0.policy_execution_mode {
            RegoPolicyExecutionMode::Opa => {
                let input = json!({
                    "request": &request,
                });

                // OPA data seems to be free-form, except for the
                // Kubernetes context aware data that must be under the
                // `kubernetes` key
                // We don't know the data that is provided by the users via
                // their settings, hence set the context aware data, to
                // ensure we overwrite what a user might have set.
                let data = match ctx_data {
                    KubernetesContext::Opa(ctx) => {
                        let mut data = settings.clone();
                        if data.insert("kubernetes".to_string(), json!(ctx)).is_some() {
                            warn!("OPA policy had user provided setting with key `kubernetes`. This value has been overwritten with the actual kubernetes context data");
                        }
                        json!(data)
                    }
                    _ => json!(settings),
                };

                (input, data)
            }
            RegoPolicyExecutionMode::Gatekeeper => {
                // Gatekeeper policies expect the `AdmissionRequest` variant only.
                let request = match request {
                    ValidateRequest::AdmissionRequest(adm_req) => adm_req,
                    ValidateRequest::Raw(_) => {
                        return AdmissionResponse::reject_internal_server_error(
                            uid.to_string(),
                            "Gatekeeper does not support raw validation requests".to_string(),
                        );
                    }
                };

                // Gatekeeper policies include a toplevel `review`
                // object that contains the AdmissionRequest to be
                // evaluated in an `object` attribute, and the
                // parameters -- defined in their `ConstraintTemplate`
                // and configured when the Policy is created.
                (
                    json!({
                        "parameters": settings,
                        "review": &request,
                    }),
                    json!({"inventory": ctx_data}),
                )
            }
        };

        let burrego_evaluation =
            self.0
                .evaluator
                .evaluate(self.0.entrypoint_id, &document_to_evaluate, &data);

        match burrego_evaluation {
            Ok(evaluation_result) => {
                match self.0.policy_execution_mode {
                    RegoPolicyExecutionMode::Opa => {
                        // Open Policy agent policies entrypoint
                        // return a Kubernetes `AdmissionReview`
                        // object.
                        let evaluation_result = evaluation_result
                            .get(0)
                            .and_then(|r| r.get("result"))
                            .and_then(|r| r.get("response"));

                        match evaluation_result {
                            Some(evaluation_result) => {
                                match serde_json::from_value(evaluation_result.clone()) {
                                    Ok(evaluation_result) => AdmissionResponse {
                                        uid: uid.to_string(),
                                        ..evaluation_result
                                    },
                                    Err(err) => AdmissionResponse::reject_internal_server_error(
                                        uid.to_string(),
                                        err.to_string(),
                                    ),
                                }
                            }
                            None => AdmissionResponse::reject_internal_server_error(
                                uid.to_string(),
                                "cannot interpret OPA policy result".to_string(),
                            ),
                        }
                    }
                    RegoPolicyExecutionMode::Gatekeeper => {
                        // Gatekeeper entrypoint is usually a
                        // `violations` rule that might evaluate to a
                        // list of violations, each violation with a
                        // `msg` string explaining the violation
                        // reason. If no violations are reported, the
                        // request is accepted. Otherwise it is
                        // rejected.
                        #[derive(Debug, Deserialize)]
                        struct Violation {
                            msg: Option<String>,
                        }
                        #[derive(Debug, Default, Deserialize)]
                        struct Violations {
                            result: Vec<Violation>,
                        }

                        let violations: Violations = evaluation_result
                            .get(0)
                            .ok_or_else(RegoRuntimeError::InvalidResponse)
                            .and_then(|response| {
                                serde_json::from_value(response.clone())
                                    .map_err(RegoRuntimeError::InvalidResponseWithError)
                            })
                            .unwrap_or_default();

                        if violations.result.is_empty() {
                            AdmissionResponse {
                                uid: uid.to_string(),
                                allowed: true,
                                ..Default::default()
                            }
                        } else {
                            AdmissionResponse {
                                uid: uid.to_string(),
                                allowed: false,
                                status: Some(AdmissionResponseStatus {
                                    message: Some(
                                        violations
                                            .result
                                            .iter()
                                            .filter_map(|violation| violation.msg.clone())
                                            .collect::<Vec<String>>()
                                            .join(", "),
                                    ),
                                    ..Default::default()
                                }),
                                ..Default::default()
                            }
                        }
                    }
                }
            }
            Err(err) => {
                error!(
                    error = ?err,
                    "error evaluating policy with burrego"
                );
                if matches!(
                    err,
                    burrego::errors::BurregoError::ExecutionDeadlineExceeded
                ) {
                    if let Err(reset_error) = self.0.evaluator.reset() {
                        error!(?reset_error, "cannot reset burrego evaluator, further invocations might fail or behave not properly");
                    }
                }
                AdmissionResponse::reject_internal_server_error(uid.to_string(), err.to_string())
            }
        }
    }

    pub fn validate_settings(&mut self, _settings: String) -> SettingsValidationResponse {
        // The burrego backend is mainly for compatibility with
        // existing OPA policies. Those policies don't have a generic
        // way of validating settings. Return true
        SettingsValidationResponse {
            valid: true,
            message: None,
        }
    }
}
