use anyhow::Result;
use std::sync::{Arc, RwLock};
use wasmtime_provider::wasmtime;

use crate::runtimes::wapc::{
    callback::host_callback, evaluation_context_registry::unregister_policy,
};

use super::evaluation_context_registry::{get_eval_ctx, get_worker_id, register_policy};

pub(crate) struct WapcStack {
    engine: wasmtime::Engine,
    module: wasmtime::Module,
    epoch_deadlines: Option<crate::policy_evaluator_builder::EpochDeadlines>,
    wapc_host: wapc::WapcHost,
}

impl WapcStack {
    pub(crate) fn new(
        engine: wasmtime::Engine,
        module: wasmtime::Module,
        epoch_deadlines: Option<crate::policy_evaluator_builder::EpochDeadlines>,
    ) -> Result<Self> {
        let wapc_host = Self::setup_wapc_host(engine.clone(), module.clone(), epoch_deadlines)?;

        Ok(Self {
            engine,
            module,
            epoch_deadlines,
            wapc_host,
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
        )?;
        let old_wapc_host_id = self.wapc_host.id();
        let worker_id = get_worker_id(old_wapc_host_id)?;

        let eval_ctx = get_eval_ctx(old_wapc_host_id);
        unregister_policy(old_wapc_host_id);
        register_policy(
            new_wapc_host.id(),
            worker_id,
            Arc::new(RwLock::new(eval_ctx)),
        );

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

    fn setup_wapc_host(
        engine: wasmtime::Engine,
        module: wasmtime::Module,
        epoch_deadlines: Option<crate::policy_evaluator_builder::EpochDeadlines>,
    ) -> Result<wapc::WapcHost> {
        let mut builder = wasmtime_provider::WasmtimeEngineProviderBuilder::new()
            .engine(engine)
            .module(module);
        if let Some(deadlines) = epoch_deadlines {
            builder = builder.enable_epoch_interruptions(deadlines.wapc_init, deadlines.wapc_func);
        }

        let engine_provider = builder.build()?;
        let wapc_host =
            wapc::WapcHost::new(Box::new(engine_provider), Some(Box::new(host_callback)))?;
        Ok(wapc_host)
    }

    pub fn wapc_host_id(&self) -> u64 {
        self.wapc_host.id()
    }
}

impl Drop for WapcStack {
    fn drop(&mut self) {
        // ensure we clean this entry from the WAPC_POLICY_MAPPING mapping
        unregister_policy(self.wapc_host.id());
    }
}
