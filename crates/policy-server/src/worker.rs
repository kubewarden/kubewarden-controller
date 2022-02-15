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
use tracing::{error, info_span};

use crate::communication::EvalRequest;
use crate::metrics;
use crate::settings::Policy;
use crate::utils::convert_yaml_map_to_json;

struct PolicyEvaluatorWithSettings {
    policy_evaluator: PolicyEvaluator,
    allowed_to_mutate: Option<bool>,
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

            let policy_contents = match std::fs::read(&policy.wasm_module_path) {
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
                allowed_to_mutate: policy.allowed_to_mutate,
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

    pub(crate) fn run(mut self) {
        while let Some(req) = self.channel_rx.blocking_recv() {
            let span = info_span!(parent: &req.parent_span, "policy_eval");
            let _enter = span.enter();

            let res = match self.evaluators.get_mut(&req.policy_id) {
                Some(PolicyEvaluatorWithSettings {
                    policy_evaluator,
                    allowed_to_mutate,
                }) => match serde_json::to_value(req.req.clone()) {
                    Ok(json) => {
                        let start_time = Instant::now();
                        let resp = policy_evaluator.validate(ValidateRequest::new(json));
                        let policy_evaluation_duration = start_time.elapsed();
                        let accepted = resp.allowed;
                        let mutated = resp.patch.is_some();
                        let error_code = if let Some(status) = &resp.status {
                            status.code
                        } else {
                            None
                        };
                        let resp = if mutated && allowed_to_mutate.as_ref() == Some(&false) {
                            ValidationResponse {
                                allowed: false,
                                status: Some(ValidationResponseStatus {
                                    message: Some(format!("Request rejected by policy {}. The policy attempted to mutate the request, but it is currently configured to not allow mutations.", &req.policy_id)),
                                    code: None,
                                }),
                                // if `allowed_to_mutate` is false, we are in a validating webhook. If we send a patch, k8s will fail because validating webhook do not expect this field
                                patch: None,
                                patch_type: None,
                                ..resp
                            }
                        } else {
                            resp
                        };
                        let res = req.resp_chan.send(Some(resp));
                        let policy_evaluation = metrics::PolicyEvaluation {
                            policy_name: policy_evaluator.policy.id.clone(),
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
