use crate::{
    callback_requests::CallbackRequest,
    policy_evaluator::RegoPolicyExecutionMode,
    policy_metadata::ContextAwareResource,
    runtimes::rego::{
        context_aware, gatekeeper_inventory::GatekeeperInventory, opa_inventory::OpaInventory,
    },
};
use anyhow::{anyhow, Result};
use std::collections::HashSet;
use tokio::sync::mpsc;

pub(crate) struct BurregoStack {
    pub evaluator: burrego::Evaluator,
    pub entrypoint_id: i32,
    pub policy_execution_mode: RegoPolicyExecutionMode,
}

impl BurregoStack {
    pub fn build_kubernetes_context(
        &self,
        callback_channel: Option<&mpsc::Sender<CallbackRequest>>,
        ctx_aware_resources_allow_list: &HashSet<ContextAwareResource>,
    ) -> Result<context_aware::KubernetesContext> {
        if ctx_aware_resources_allow_list.is_empty() {
            return Ok(context_aware::KubernetesContext::Empty);
        }

        match callback_channel {
            None => Err(anyhow!(
                "cannot build Rego context aware data: callback channel is not set"
            )),
            Some(chan) => {
                let cluster_resources =
                    context_aware::get_allowed_resources(chan, ctx_aware_resources_allow_list)?;

                match self.policy_execution_mode {
                    RegoPolicyExecutionMode::Opa => {
                        let plural_names_by_resource =
                            context_aware::get_plural_names(chan, ctx_aware_resources_allow_list)?;
                        let inventory =
                            OpaInventory::new(&cluster_resources, &plural_names_by_resource)?;
                        Ok(context_aware::KubernetesContext::Opa(inventory))
                    }
                    RegoPolicyExecutionMode::Gatekeeper => {
                        let inventory = GatekeeperInventory::new(&cluster_resources)?;
                        Ok(context_aware::KubernetesContext::Gatekeeper(inventory))
                    }
                }
            }
        }
    }
}
