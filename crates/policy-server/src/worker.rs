use crate::communication::EvalRequest;
use anyhow::{anyhow, Result};
use policy_evaluator::{policy::Policy, policy_evaluator::PolicyEvaluator};
use std::collections::HashMap;
use tokio::sync::mpsc::Receiver;
use tracing::error;

pub(crate) struct Worker {
    evaluators: HashMap<String, PolicyEvaluator>,
    channel_rx: Receiver<EvalRequest>,
}

impl Worker {
    #[tracing::instrument]
    pub(crate) fn new(
        rx: Receiver<EvalRequest>,
        policies: HashMap<String, Policy>,
    ) -> Result<Worker> {
        let mut evs: HashMap<String, PolicyEvaluator> = HashMap::new();

        for (id, policy) in policies.iter() {
            let settings = policy.settings();

            let policy_evaluator = PolicyEvaluator::new(&policy.wasm_module_path, settings)?;

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
            let res = match self.evaluators.get_mut(&req.policy_id) {
                Some(policy_evaluator) => {
                    let resp = policy_evaluator.validate(req.req);
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
