use std::collections::BTreeSet;
use tokio::sync::mpsc;

use crate::{
    callback_requests::CallbackRequest,
    policy_evaluator::RegoPolicyExecutionMode,
    policy_metadata::ContextAwareResource,
    runtimes::rego::{
        context_aware,
        errors::{RegoRuntimeError, Result},
        gatekeeper_inventory_cache::GATEKEEPER_INVENTORY_CACHE,
        opa_inventory::OpaInventory,
        stack_pre::StackPre,
    },
};

pub(crate) struct Stack {
    pub evaluator: burrego::Evaluator,
    pub entrypoint_id: i32,
    pub policy_execution_mode: RegoPolicyExecutionMode,
}

impl Stack {
    /// Create a new `Stack` using a `StackPre` object
    pub fn new_from_pre(stack_pre: &StackPre) -> Result<Self> {
        let evaluator = stack_pre
            .rehydrate()
            .map_err(|e| RegoRuntimeError::EvaluatorError(e.to_string()))?;
        Ok(Self {
            evaluator,
            entrypoint_id: stack_pre.entrypoint_id,
            policy_execution_mode: stack_pre.policy_execution_mode.clone(),
        })
    }

    pub fn build_kubernetes_context(
        &self,
        callback_channel: Option<&mpsc::Sender<CallbackRequest>>,
        ctx_aware_resources_allow_list: &BTreeSet<ContextAwareResource>,
    ) -> Result<context_aware::KubernetesContext> {
        if ctx_aware_resources_allow_list.is_empty() {
            return Ok(context_aware::KubernetesContext::Empty);
        }

        match callback_channel {
            None => Err(RegoRuntimeError::CallbackChannelNotSet),
            Some(chan) => match self.policy_execution_mode {
                RegoPolicyExecutionMode::Opa => {
                    let cluster_resources =
                        context_aware::get_allowed_resources(chan, ctx_aware_resources_allow_list)?;
                    let plural_names_by_resource =
                        context_aware::get_plural_names(chan, ctx_aware_resources_allow_list)?;
                    let inventory =
                        OpaInventory::new(&cluster_resources, &plural_names_by_resource)?;
                    Ok(context_aware::KubernetesContext::Opa(inventory))
                }
                RegoPolicyExecutionMode::Gatekeeper => {
                    let cached_inventory = GATEKEEPER_INVENTORY_CACHE
                        .get_inventory(chan, ctx_aware_resources_allow_list)?;
                    Ok(context_aware::KubernetesContext::Gatekeeper(
                        cached_inventory,
                    ))
                }
            },
        }
    }
}
