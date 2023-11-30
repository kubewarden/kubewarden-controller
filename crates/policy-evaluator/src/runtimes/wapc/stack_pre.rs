use anyhow::Result;
use wasmtime_provider::wasmtime;

use crate::policy_evaluator_builder::EpochDeadlines;

/// Reduce allocation time of new `WasmtimeProviderEngine`, see the `rehydrate` method
#[derive(Clone)]
pub(crate) struct StackPre {
    engine_provider_pre: wasmtime_provider::WasmtimeEngineProviderPre,
}

impl StackPre {
    pub(crate) fn new(
        engine: wasmtime::Engine,
        module: wasmtime::Module,
        epoch_deadlines: Option<EpochDeadlines>,
    ) -> Result<Self> {
        let mut builder = wasmtime_provider::WasmtimeEngineProviderBuilder::new()
            .engine(engine)
            .module(module);
        if let Some(deadlines) = epoch_deadlines {
            builder = builder.enable_epoch_interruptions(deadlines.wapc_init, deadlines.wapc_func);
        }

        let engine_provider_pre = builder.build_pre()?;
        Ok(Self {
            engine_provider_pre,
        })
    }

    /// Allocate a new `WasmtimeEngineProvider` instance by using a pre-allocated instance
    pub(crate) fn rehydrate(&self) -> Result<wasmtime_provider::WasmtimeEngineProvider> {
        let engine = self.engine_provider_pre.rehydrate()?;
        Ok(engine)
    }
}
