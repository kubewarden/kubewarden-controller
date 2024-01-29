use crate::policy_evaluator::RegoPolicyExecutionMode;
use crate::policy_evaluator_builder::EpochDeadlines;
use crate::runtimes::rego::errors::{RegoRuntimeError, Result};

/// This struct allows to follow the `StackPre -> Stack`
/// "pattern" also for Rego policies.
///
/// However, Rego policies cannot make use of `wasmtime::InstancePre`
/// to reduce the instantiation times. That happens because all
/// Rego WebAssembly policies import their Wasm Memory from the host.
/// The Wasm Memory is defined inside of a `wasmtime::Store`, which is
/// something that `wasmtime::InstnacePre` objects do not have (rightfully!).
///
/// However, Rego Wasm modules are so small thta instantiating them from scratch
/// is already a cheap operation.
#[derive(Clone)]
pub(crate) struct StackPre {
    engine: wasmtime::Engine,
    module: wasmtime::Module,
    epoch_deadlines: Option<EpochDeadlines>,
    pub entrypoint_id: i32,
    pub policy_execution_mode: RegoPolicyExecutionMode,
}

impl StackPre {
    pub(crate) fn new(
        engine: wasmtime::Engine,
        module: wasmtime::Module,
        epoch_deadlines: Option<EpochDeadlines>,
        entrypoint_id: i32,
        policy_execution_mode: RegoPolicyExecutionMode,
    ) -> Self {
        Self {
            engine,
            module,
            epoch_deadlines,
            entrypoint_id,
            policy_execution_mode,
        }
    }

    /// Create a fresh `burrego::Evaluator`
    pub(crate) fn rehydrate(&self) -> Result<burrego::Evaluator> {
        let mut builder = burrego::EvaluatorBuilder::default()
            .engine(&self.engine)
            .module(self.module.clone())
            .host_callbacks(crate::runtimes::rego::new_host_callbacks());

        if let Some(deadlines) = self.epoch_deadlines {
            builder = builder.enable_epoch_interruptions(deadlines.wapc_func);
        }
        let evaluator = builder
            .build()
            .map_err(RegoRuntimeError::RegoEngineBuilder)?;
        Ok(evaluator)
    }
}
