use anyhow::Result;
use itertools::Itertools;
use policy_evaluator::callback_requests::CallbackRequest;
use policy_evaluator::{
    policy_evaluator::{PolicyEvaluator, ValidateRequest},
    policy_evaluator_builder::PolicyEvaluatorBuilder,
    policy_metadata::Metadata,
    validation_response::{ValidationResponse, ValidationResponseStatus},
};
use std::collections::HashMap;
use std::time::Instant;
use std::{fmt, iter::FromIterator};
use tokio::sync::mpsc::{Receiver, Sender};
use tracing::{error, info, info_span};

use crate::communication::EvalRequest;
use crate::metrics;
use crate::settings::{Policy, PolicyMode};
use crate::utils::convert_yaml_map_to_json;

struct PolicyEvaluatorWithSettings {
    policy_evaluator: PolicyEvaluator,
    policy_mode: PolicyMode,
    allowed_to_mutate: bool,
    always_accept_admission_reviews_on_namespace: Option<String>,
}

pub(crate) struct Worker {
    evaluators: HashMap<String, PolicyEvaluatorWithSettings>,
    channel_rx: Receiver<EvalRequest>,
}

pub struct PolicyErrors(HashMap<String, String>);

impl fmt::Display for PolicyErrors {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let mut errors = self
            .0
            .iter()
            .map(|(policy, error)| format!("[{}: {}]", policy, error));
        write!(f, "{}", errors.join(", "))
    }
}

impl Worker {
    #[tracing::instrument(
        name = "worker_new",
        fields(host=crate::cli::HOSTNAME.as_str()),
        skip_all,
    )]
    pub(crate) fn new(
        rx: Receiver<EvalRequest>,
        policies: HashMap<String, Policy>,
        callback_handler_tx: Sender<CallbackRequest>,
        always_accept_admission_reviews_on_namespace: Option<String>,
    ) -> Result<Worker, PolicyErrors> {
        let mut evs_errors = HashMap::new();
        let mut evs = HashMap::new();

        for (id, policy) in policies.iter() {
            let settings_json = policy.settings.as_ref().and_then(|settings| {
                let settings =
                    serde_yaml::Mapping::from_iter(settings.iter().map(|(key, value)| {
                        (serde_yaml::Value::String(key.to_string()), value.clone())
                    }));
                match convert_yaml_map_to_json(settings) {
                    Ok(settings) => Some(settings),
                    Err(err) => {
                        error!(
                            error = err.to_string().as_str(),
                            "cannot convert YAML settings to JSON"
                        );
                        None
                    }
                }
            });

            let wasm_module_path = match &policy.wasm_module_path {
                Some(p) => p,
                None => {
                    evs_errors.insert(
                        policy.url.clone(),
                        "missing path to local Wasm file".to_string(),
                    );
                    continue;
                }
            };

            let policy_contents = match std::fs::read(&wasm_module_path) {
                Ok(policy_contents) => policy_contents,
                Err(err) => {
                    evs_errors.insert(
                        policy.url.clone(),
                        format!("policy contents are invalid: {:?}", err),
                    );
                    continue;
                }
            };

            let policy_metadata = match Metadata::from_contents(policy_contents.clone()) {
                Ok(policy_metadata) => policy_metadata,
                Err(err) => {
                    evs_errors.insert(
                        policy.url.clone(),
                        format!("policy metadata is invalid: {:?}", err),
                    );
                    continue;
                }
            };

            let policy_execution_mode = policy_metadata.unwrap_or_default().execution_mode;

            let mut policy_evaluator = match PolicyEvaluatorBuilder::new(id.to_string())
                .policy_contents(&policy_contents)
                .execution_mode(policy_execution_mode)
                .settings(settings_json)
                .callback_channel(callback_handler_tx.clone())
                .build()
            {
                Ok(policy_evaluator) => policy_evaluator,
                Err(err) => {
                    evs_errors.insert(
                        policy.url.clone(),
                        format!("could not instantiate policy: {:?}", err),
                    );
                    continue;
                }
            };

            let set_val_rep = policy_evaluator.validate_settings();
            if !set_val_rep.valid {
                evs_errors.insert(
                    policy.url.clone(),
                    format!(
                        "settings of policy {} are invalid: {:?}",
                        policy.url.clone(),
                        set_val_rep.message
                    ),
                );
                continue;
            }

            let policy_evaluator_with_settings = PolicyEvaluatorWithSettings {
                policy_evaluator,
                policy_mode: policy.policy_mode.clone(),
                allowed_to_mutate: policy.allowed_to_mutate.unwrap_or(false),
                always_accept_admission_reviews_on_namespace:
                    always_accept_admission_reviews_on_namespace.clone(),
            };

            evs.insert(id.to_string(), policy_evaluator_with_settings);
        }

        if !evs_errors.is_empty() {
            return Err(PolicyErrors(evs_errors));
        }

        Ok(Worker {
            evaluators: evs,
            channel_rx: rx,
        })
    }

    // Returns a validation response with policy-server specific
    // constraints taken into account:
    // - A policy might have tried to mutate while the policy-server
    //   configuration does not allow it to mutate
    // - A policy might be running in "Monitor" mode, that always
    //   accepts the request (without mutation), logging the answer
    fn validation_response_with_constraints(
        policy_id: &str,
        policy_mode: &PolicyMode,
        allowed_to_mutate: bool,
        validation_response: ValidationResponse,
    ) -> ValidationResponse {
        if validation_response.patch.is_some() && !allowed_to_mutate {
            // Return early -- a policy not allowed to mutate tried to
            // mutate --, we don't care about the policy mode at this
            // point, this will be a problem in Protect mode, so
            // return the error too if we are in Monitor mode.
            return ValidationResponse {
                allowed: false,
                status: Some(ValidationResponseStatus {
                    message: Some(format!("Request rejected by policy {}. The policy attempted to mutate the request, but it is currently configured to not allow mutations.", policy_id)),
                    code: None,
                }),
                // if `allowed_to_mutate` is false, we are in a validating webhook. If we send a patch, k8s will fail because validating webhook do not expect this field
                patch: None,
                patch_type: None,
                ..validation_response
            };
        };
        match policy_mode {
            PolicyMode::Protect => validation_response,
            PolicyMode::Monitor => {
                // In monitor mode we always accept
                // the request, but log what would
                // have been the decision of the
                // policy. We also force mutating
                // patches to be none. Status is also
                // overriden, as it's only taken into
                // account when a request is rejected.
                info!(
                    policy_id = policy_id,
                    allowed_to_mutate = allowed_to_mutate,
                    response = format!("{:?}", validation_response).as_str(),
                    "policy evaluation (monitor mode)",
                );
                ValidationResponse {
                    allowed: true,
                    patch_type: None,
                    patch: None,
                    status: None,
                    ..validation_response
                }
            }
        }
    }

    pub(crate) fn run(mut self) {
        while let Some(req) = self.channel_rx.blocking_recv() {
            let span = info_span!(parent: &req.parent_span, "policy_eval");
            let _enter = span.enter();

            let res = match self.evaluators.get_mut(&req.policy_id) {
                Some(PolicyEvaluatorWithSettings {
                    policy_evaluator,
                    policy_mode,
                    allowed_to_mutate,
                    always_accept_admission_reviews_on_namespace,
                }) => match serde_json::to_value(req.req.clone()) {
                    Ok(json) => {
                        let policy_name = policy_evaluator.policy.id.clone();
                        let policy_mode = policy_mode.clone();
                        let start_time = Instant::now();
                        let allowed_to_mutate = *allowed_to_mutate;
                        let validation_response =
                            policy_evaluator.validate(ValidateRequest::new(json));
                        let policy_evaluation_duration = start_time.elapsed();
                        let error_code = if let Some(status) = &validation_response.status {
                            status.code
                        } else {
                            None
                        };
                        let validation_response = Worker::validation_response_with_constraints(
                            &req.policy_id,
                            &policy_mode,
                            allowed_to_mutate,
                            validation_response,
                        );
                        let validation_response =
                            // If the policy server is configured to
                            // always accept admission reviews on a
                            // given namespace, just set the `allowed`
                            // part of the response to `true` if the
                            // request matches this namespace. Keep
                            // the rest of the behaviors unchanged,
                            // such as checking if the policy is
                            // allowed to mutate.
                            if let Some(namespace) = always_accept_admission_reviews_on_namespace {
                                if req.req.namespace == Some(namespace.to_string()) {
                                    ValidationResponse {
                                        allowed: true,
                                        ..validation_response
                                    }
                                } else {
                                    validation_response
                                }
                            } else {
                                validation_response
                            };
                        let accepted = validation_response.allowed;
                        let mutated = validation_response.patch.is_some();
                        let res = req.resp_chan.send(Some(validation_response));
                        let policy_evaluation = metrics::PolicyEvaluation {
                            policy_name,
                            policy_mode: policy_mode.into(),
                            resource_name: req.req.name.unwrap_or_else(|| "unknown".to_string()),
                            resource_namespace: req.req.namespace,
                            resource_kind: req.req.request_kind.unwrap_or_default().kind,
                            resource_request_operation: req.req.operation.clone(),
                            accepted,
                            mutated,
                            error_code,
                        };
                        metrics::record_policy_latency(
                            policy_evaluation_duration,
                            &policy_evaluation,
                        );
                        metrics::add_policy_evaluation(&policy_evaluation);
                        res
                    }
                    Err(e) => {
                        let error_msg = format!("Failed to serialize AdmissionReview: {:?}", e);
                        error!("{}", error_msg);
                        req.resp_chan.send(Some(ValidationResponse::reject(
                            req.policy_id,
                            error_msg,
                            hyper::StatusCode::BAD_REQUEST.as_u16(),
                        )))
                    }
                },
                None => req.resp_chan.send(None),
            };
            if res.is_err() {
                error!("receiver dropped");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const POLICY_ID: &str = "policy-id";

    #[test]
    fn validation_response_with_constraints_not_allowed_to_mutate() {
        let rejection_response = ValidationResponse {
            allowed: false,
            patch: None,
            patch_type: None,
            status: Some(ValidationResponseStatus {
                message: Some("Request rejected by policy policy-id. The policy attempted to mutate the request, but it is currently configured to not allow mutations.".to_string()),
                ..Default::default()
            }),
            ..Default::default()
        };

        assert_eq!(
            Worker::validation_response_with_constraints(
                POLICY_ID,
                &PolicyMode::Protect,
                false,
                ValidationResponse {
                    allowed: true,
                    patch: Some("patch".to_string()),
                    patch_type: Some("application/json-patch+json".to_string()),
                    ..Default::default()
                },
            ),
            rejection_response,
        );

        assert_eq!(
            Worker::validation_response_with_constraints(
                POLICY_ID,
                &PolicyMode::Monitor,
                false,
                ValidationResponse {
                    allowed: true,
                    patch: Some("patch".to_string()),
                    patch_type: Some("application/json-patch+json".to_string()),
                    ..Default::default()
                },
            ),
            rejection_response,
        );
    }

    #[test]
    fn validation_response_with_constraints_monitor_mode() {
        let admission_response = ValidationResponse {
            allowed: true,
            ..Default::default()
        };

        assert_eq!(
            Worker::validation_response_with_constraints(
                POLICY_ID,
                &PolicyMode::Monitor,
                false,
                ValidationResponse {
                    allowed: false,
                    status: Some(ValidationResponseStatus {
                        message: Some("some rejection message".to_string()),
                        code: Some(500),
                    }),
                    ..Default::default()
                },
            ),
            admission_response,
        );

        assert_eq!(
            Worker::validation_response_with_constraints(
                POLICY_ID,
                &PolicyMode::Monitor,
                true,
                ValidationResponse {
                    allowed: true,
                    patch: Some("patch".to_string()),
                    patch_type: Some("application/json-patch+json".to_string()),
                    ..Default::default()
                },
            ),
            admission_response,
        );
    }
}
