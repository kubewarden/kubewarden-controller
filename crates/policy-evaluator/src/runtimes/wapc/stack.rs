use anyhow::Result;
use std::sync::Arc;

use crate::evaluation_context::EvaluationContext;
use crate::runtimes::wapc::callback::new_host_callback;

use super::StackPre;

pub(crate) struct WapcStack {
    wapc_host: wapc::WapcHost,
    stack_pre: StackPre,
    eval_ctx: Arc<EvaluationContext>,
}

impl WapcStack {
    pub(crate) fn new_from_pre(stack_pre: &StackPre, eval_ctx: &EvaluationContext) -> Result<Self> {
        let eval_ctx = Arc::new(eval_ctx.to_owned());
        let wapc_host = Self::wapc_host_from_pre(stack_pre, eval_ctx.clone())?;

        Ok(Self {
            wapc_host,
            stack_pre: stack_pre.to_owned(),
            eval_ctx: eval_ctx.to_owned(),
        })
    }

    /// Provision a new wapc_host. Useful for starting from a clean slate
    /// after an epoch deadline interruption is raised.
    ///
    /// This method takes care of de-registering the old wapc_host and
    /// registering the new one inside of the global WAPC_POLICY_MAPPING
    /// variable.
    pub(crate) fn reset(&mut self) -> Result<()> {
        // Create a new wapc_host
        let new_wapc_host = Self::wapc_host_from_pre(&self.stack_pre, self.eval_ctx.clone())?;

        self.wapc_host = new_wapc_host;

        Ok(())
    }

    /// Invokes the given waPC function using the provided payload
    pub(crate) fn call(
        &self,
        op: &str,
        payload: &[u8],
    ) -> std::result::Result<Vec<u8>, wapc::errors::Error> {
        self.wapc_host.call(op, payload)
    }

    /// Create a new `WapcHost` by rehydrating the `StackPre`. This is faster than creating the
    /// `WasmtimeEngineProvider` from scratch
    fn wapc_host_from_pre(
        pre: &StackPre,
        eval_ctx: Arc<EvaluationContext>,
    ) -> Result<wapc::WapcHost> {
        let engine_provider = pre.rehydrate()?;
        let wapc_host =
            wapc::WapcHost::new(Box::new(engine_provider), Some(new_host_callback(eval_ctx)))?;
        Ok(wapc_host)
    }
}
