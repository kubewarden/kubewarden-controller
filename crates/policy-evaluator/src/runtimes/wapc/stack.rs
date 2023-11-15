use anyhow::{anyhow, Result};
use tracing::warn;
use wasmtime_provider::wasmtime;

use crate::runtimes::wapc::{callback::host_callback, WAPC_POLICY_MAPPING};

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

        // Remove the old policy from WAPC_POLICY_MAPPING and add the new one
        // We need a write lock to do that
        {
            let mut map = WAPC_POLICY_MAPPING
                .write()
                .expect("cannot get write access to WAPC_POLICY_MAPPING");
            let policy = map.remove(&old_wapc_host_id).ok_or_else(|| {
                anyhow!("cannot find old waPC policy with id {}", old_wapc_host_id)
            })?;
            map.insert(new_wapc_host.id(), policy);
        }

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
        match WAPC_POLICY_MAPPING.write() {
            Ok(mut map) => {
                map.remove(&self.wapc_host.id());
            }
            Err(_) => {
                warn!("cannot cleanup policy from WAPC_POLICY_MAPPING");
            }
        }
    }
}
