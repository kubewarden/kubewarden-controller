use anyhow::Result;
use std::sync::{Arc, Mutex};
use wasmtime_provider::wasmtime;

use crate::evaluation_context::EvaluationContext;
use crate::policy_evaluator_builder::EpochDeadlines;
use crate::runtimes::wapc::callback::new_host_callback;

pub(crate) struct WapcStack {
    engine: wasmtime::Engine,
    module: wasmtime::Module,
    epoch_deadlines: Option<EpochDeadlines>,
    wapc_host: wapc::WapcHost,
    eval_ctx: Arc<Mutex<EvaluationContext>>,
}

impl WapcStack {
    pub(crate) fn new(
        engine: wasmtime::Engine,
        module: wasmtime::Module,
        epoch_deadlines: Option<EpochDeadlines>,
        eval_ctx: EvaluationContext,
    ) -> Result<Self> {
        let eval_ctx = Arc::new(Mutex::new(eval_ctx));

        let wapc_host = Self::setup_wapc_host(
            // Using `clone` on an `Engine` is a cheap operation
            engine.clone(),
            // Using `clone` on a `Module` is a cheap operation
            module.clone(),
            epoch_deadlines,
            // Using `clone` on an `Arc` is a cheap operation
            eval_ctx.clone(),
        )?;

        Ok(Self {
            engine,
            module,
            epoch_deadlines,
            wapc_host,
            eval_ctx,
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
        let new_wapc_host = Self::setup_wapc_host(
            self.engine.clone(),
            self.module.clone(),
            self.epoch_deadlines,
            self.eval_ctx.clone(),
        )?;

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

    pub(crate) fn set_eval_ctx(&mut self, eval_ctx: &EvaluationContext) {
        let mut eval_ctx_orig = self.eval_ctx.lock().unwrap();
        eval_ctx_orig.copy_from(eval_ctx);
    }

    fn setup_wapc_host(
        engine: wasmtime::Engine,
        module: wasmtime::Module,
        epoch_deadlines: Option<EpochDeadlines>,
        eval_ctx: Arc<Mutex<EvaluationContext>>,
    ) -> Result<wapc::WapcHost> {
        let mut builder = wasmtime_provider::WasmtimeEngineProviderBuilder::new()
            .engine(engine)
            .module(module);
        if let Some(deadlines) = epoch_deadlines {
            builder = builder.enable_epoch_interruptions(deadlines.wapc_init, deadlines.wapc_func);
        }

        let engine_provider = builder.build()?;
        let wapc_host =
            wapc::WapcHost::new(Box::new(engine_provider), Some(new_host_callback(eval_ctx)))?;
        Ok(wapc_host)
    }
}
