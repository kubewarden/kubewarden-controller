use wasmtime_provider::wasmtime;

use crate::runtimes::wapc::errors::{Result, WapcRuntimeError};

/// Reduce allocation time of new `WasmtimeProviderEngine`, see the `rehydrate` method
#[derive(Clone)]
pub(crate) struct StackPre {
    engine_provider_pre: wasmtime_provider::WasmtimeEngineProviderPre,
}

impl StackPre {
    pub(crate) fn new(engine: wasmtime::Engine, module: wasmtime::Module) -> Result<Self> {
        let builder = wasmtime_provider::WasmtimeEngineProviderBuilder::new()
            .engine(engine)
            .module(module);

        let engine_provider_pre = builder
            .build_pre()
            .map_err(WapcRuntimeError::WasmtimeEngineBuilder)?;
        Ok(Self {
            engine_provider_pre,
        })
    }

    /// Allocate a new `WasmtimeEngineProvider` instance by using a pre-allocated instance
    pub(crate) fn rehydrate(
        &self,
        epoch_deadline: Option<u64>,
    ) -> Result<wasmtime_provider::WasmtimeEngineProvider> {
        let wapc_epoch_deadlines =
            epoch_deadline.map(|deadline| wasmtime_provider::EpochDeadlines {
                wapc_init: deadline,
                wapc_func: deadline,
            });

        let engine = self
            .engine_provider_pre
            .rehydrate(wapc_epoch_deadlines)
            .map_err(WapcRuntimeError::WasmtimeEngineBuilder)?;
        Ok(engine)
    }
}
