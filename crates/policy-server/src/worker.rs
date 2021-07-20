use crate::communication::EvalRequest;
use crate::settings::Policy;
use crate::utils::convert_yaml_map_to_json;
use anyhow::{anyhow, Result};
use policy_evaluator::policy_evaluator::{PolicyEvaluator, PolicyExecutionMode, ValidateRequest};
use std::collections::HashMap;
use tokio::sync::mpsc::Receiver;
use tracing::{error, info_span};

pub(crate) struct Worker {
    evaluators: HashMap<String, PolicyEvaluator>,
    channel_rx: Receiver<EvalRequest>,
}

impl Worker {
    #[tracing::instrument(name = "worker_new", skip(rx, policies))]
    pub(crate) fn new(
        rx: Receiver<EvalRequest>,
        policies: HashMap<String, Policy>,
    ) -> Result<Worker> {
        let mut evs: HashMap<String, PolicyEvaluator> = HashMap::new();

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

            let mut policy_evaluator = PolicyEvaluator::from_file(
                id.to_string(),
                &policy.wasm_module_path,
                // TODO (ereslibre): choose based on metadata
                PolicyExecutionMode::KubewardenWapc,
                settings_json,
            )?;

            let set_val_rep = policy_evaluator.validate_settings();
            if !set_val_rep.valid {
                return Err(anyhow!(
                    "The settings of policy {} are invalid: {:?}",
                    policy.url,
                    set_val_rep.message
                ));
            }

            evs.insert(id.to_string(), policy_evaluator);
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
