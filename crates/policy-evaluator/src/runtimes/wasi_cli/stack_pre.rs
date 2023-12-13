use anyhow::Result;

use crate::policy_evaluator_builder::EpochDeadlines;
use crate::runtimes::wasi_cli::stack::Context;

/// Reduce the allocation time of a Wasi Stack. This is done by leveraging `wasmtime::InstancePre`.
#[derive(Clone)]
pub(crate) struct StackPre {
    engine: wasmtime::Engine,
    instance_pre: wasmtime::InstancePre<Context>,
    epoch_deadlines: Option<EpochDeadlines>,
}

impl StackPre {
    pub(crate) fn new(
        engine: wasmtime::Engine,
        module: wasmtime::Module,
        epoch_deadlines: Option<EpochDeadlines>,
    ) -> Result<Self> {
        let mut linker = wasmtime::Linker::<Context>::new(&engine);
        wasmtime_wasi::add_to_linker(&mut linker, |c: &mut Context| &mut c.wasi_ctx)?;

        let instance_pre = linker.instantiate_pre(&module)?;
        Ok(Self {
            engine,
            instance_pre,
            epoch_deadlines,
        })
    }

    /// Create a brand new `wasmtime::Store` to be used during an evaluation
    pub(crate) fn build_store(&self, ctx: Context) -> wasmtime::Store<Context> {
        let mut store = wasmtime::Store::new(&self.engine, ctx);
        if let Some(deadline) = self.epoch_deadlines {
            store.set_epoch_deadline(deadline.wapc_func);
        }

        store
    }

    /// Allocate a new `wasmtime::Instance` that is bound to the given `wasmtime::Store`.
    /// It's recommended to provide a brand new `wasmtime::Store` created by the
    /// `build_store` method
    pub(crate) fn rehydrate(
        &self,
        store: &mut wasmtime::Store<Context>,
    ) -> Result<wasmtime::Instance> {
        self.instance_pre.instantiate(store)
    }
}
