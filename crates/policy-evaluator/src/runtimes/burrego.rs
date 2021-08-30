use anyhow::anyhow;
use lazy_static::lazy_static;
use tracing::error;

pub(crate) struct Runtime<'a>(pub(crate) &'a mut crate::policy_evaluator::BurregoEvaluator);

use crate::policy_evaluator::{PolicySettings, ValidateRequest};
use crate::validation_response::{ValidationResponse, ValidationResponseStatus};
use burrego::opa::host_callbacks::HostCallbacks;

use kubewarden_policy_sdk::settings::SettingsValidationResponse;

use crate::policy_evaluator::RegoPolicyExecutionMode;
use serde::Deserialize;
use serde_json::json;

lazy_static! {
    pub static ref DEFAULT_HOST_CALLBACKS: HostCallbacks = HostCallbacks {
        opa_abort: Box::new(BurregoHostCallbacks::opa_abort),
        opa_println: Box::new(BurregoHostCallbacks::opa_println),
    };
}

struct BurregoHostCallbacks;

impl BurregoHostCallbacks {
    #[tracing::instrument(level = "error")]
    fn opa_abort(msg: String) {}

    #[tracing::instrument(level = "info")]
    fn opa_println(msg: String) {}
}

impl<'a> Runtime<'a> {
    pub fn validate(
        &mut self,
        settings: &PolicySettings,
        request: &ValidateRequest,
    ) -> ValidationResponse {
        let uid = request.uid();

        // OPA and Gatekeeper expect arguments in different ways. Provide the ones that each expect.
        let (document_to_evaluate, data) = match self.0.policy_execution_mode {
            RegoPolicyExecutionMode::Opa => {
                // Policies for OPA expect the whole `AdmissionReview`
                // object: produce a synthetic external one so
                // existing OPA policies are compatible.
                (
                    json!({
                        "apiVersion": "admission.k8s.io/v1",
                        "kind": "AdmissionReview",
                        "request": &request.0,
                    }),
                    json!(settings),
                )
            }
            RegoPolicyExecutionMode::Gatekeeper => {
                // Gatekeeper policies include a toplevel `review`
                // object that contains the AdmissionRequest to be
                // evaluated in an `object` attribute, and the
                // parameters -- defined in their `ConstraintTemplate`
                // and configured when the Policy is created.
                (
                    json!({
                        "parameters": settings,
                        "review": &request.0,
                    }),
                    json!({"kubernetes": ""}), // TODO (ereslibre): Kubernetes context goes here
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
                                    Ok(evaluation_result) => ValidationResponse {
                                        uid: uid.to_string(),
                                        ..evaluation_result
                                    },
                                    Err(err) => ValidationResponse::reject_internal_server_error(
                                        uid.to_string(),
                                        err.to_string(),
                                    ),
                                }
                            }
                            None => ValidationResponse::reject_internal_server_error(
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
                            .ok_or_else(|| anyhow!("invalid response from policy"))
                            .and_then(|response| {
                                serde_json::from_value(response.clone())
                                    .map_err(|err| anyhow!("invalid response from policy: {}", err))
                            })
                            .unwrap_or_default();

                        if violations.result.is_empty() {
                            ValidationResponse {
                                uid: uid.to_string(),
                                allowed: true,
                                ..Default::default()
                            }
                        } else {
                            ValidationResponse {
                                uid: uid.to_string(),
                                allowed: false,
                                status: Some(ValidationResponseStatus {
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
                    error = err.to_string().as_str(),
                    "error evaluating policy with burrego"
                );
                ValidationResponse::reject_internal_server_error(uid.to_string(), err.to_string())
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
