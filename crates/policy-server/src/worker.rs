use crate::communication::EvalRequest;
use crate::settings::Policy;
use crate::utils::convert_yaml_map_to_json;
use anyhow::Result;
use itertools::Itertools;
use policy_evaluator::{
    policy_evaluator::{PolicyEvaluator, ValidateRequest},
    policy_metadata::Metadata,
};
use std::collections::HashMap;
use std::fmt;
use tokio::sync::mpsc::Receiver;
use tracing::{error, info_span};

pub(crate) struct Worker {
    evaluators: HashMap<String, PolicyEvaluator>,
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
    #[tracing::instrument(name = "worker_new", skip(rx, policies))]
    pub(crate) fn new(
        rx: Receiver<EvalRequest>,
        policies: HashMap<String, Policy>,
    ) -> Result<Worker, PolicyErrors> {
        let mut evs_errors = HashMap::new();
        let mut evs = HashMap::new();

        for (id, policy) in policies.iter() {
            let settings = policy.settings();

            let settings_json =
                settings.and_then(|settings| match convert_yaml_map_to_json(settings) {
                    Ok(settings) => Some(settings),
                    Err(err) => {
                        error!(
                            error = err.to_string().as_str(),
                            "cannot convert YAML settings to JSON"
                        );
                        None
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

            let mut policy_evaluator = match PolicyEvaluator::from_contents(
                id.to_string(),
                policy_contents,
                policy_execution_mode,
                settings_json,
            ) {
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

            evs.insert(id.to_string(), policy_evaluator);
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
                Some(policy_evaluator) => {
                    let resp = policy_evaluator.validate(ValidateRequest::new(req.req));
                    req.resp_chan.send(Some(resp))
                }
                None => req.resp_chan.send(None),
            };
            if res.is_err() {
                error!("receiver dropped");
            }
        }
    }
}
