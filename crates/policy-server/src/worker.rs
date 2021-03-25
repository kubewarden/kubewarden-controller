use crate::communication::EvalRequest;
use anyhow::{anyhow, Result};
use policy_evaluator::{policy::Policy, policy_evaluator::PolicyEvaluator};
use std::collections::HashMap;
use tokio::sync::mpsc::Receiver;

#[allow(clippy::unnecessary_wraps)]
pub(crate) fn host_callback(
    id: u64,
    bd: &str,
    ns: &str,
    op: &str,
    payload: &[u8],
) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
    let payload = ::std::str::from_utf8(payload)
        .map_err(|e| anyhow!("Error converting payload to UTF8: {:?}", e))?;
    println!(
        "Guest {} invoked '{}->{}:{}' with payload of {}",
        id, bd, ns, op, payload
    );
    Ok(b"Host result".to_vec())
}

pub(crate) struct Worker {
    evaluators: HashMap<String, PolicyEvaluator>,
    channel_rx: Receiver<EvalRequest>,
}

impl Worker {
    pub(crate) fn new(
        rx: Receiver<EvalRequest>,
        policies: HashMap<String, Policy>,
    ) -> Result<Worker> {
        let mut evs: HashMap<String, PolicyEvaluator> = HashMap::new();

        for (id, policy) in policies.iter() {
            let settings = policy.settings();

            let mut policy_evaluator =
                PolicyEvaluator::new(policy.wasm_module_path.clone(), settings, host_callback)?;

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
            //TODO: handle error
            match self.evaluators.get_mut(&req.policy_id) {
                Some(policy_evaluator) => {
                    let resp = policy_evaluator.validate(req.req);
                    let _ = req.resp_chan.send(Some(resp));
                }
                None => {
                    let _ = req.resp_chan.send(None);
                }
            }
        }
    }
}
