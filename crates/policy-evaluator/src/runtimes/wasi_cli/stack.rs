use anyhow::Result;
use wasi_common::WasiCtx;
use wasmtime::{Engine, InstancePre, Linker, Module};

use crate::policy_evaluator_builder::EpochDeadlines;

pub(crate) struct Context {
    pub(crate) wasi_ctx: WasiCtx,
}

pub(crate) struct Stack {
    pub(crate) engine: Engine,
    pub(crate) epoch_deadlines: Option<EpochDeadlines>,
    pub(crate) instance_pre: InstancePre<Context>,
}

impl Stack {
    pub(crate) fn new(
        engine: Engine,
        module: Module,
        epoch_deadlines: Option<EpochDeadlines>,
    ) -> Result<Self> {
        let mut linker = Linker::<Context>::new(&engine);
        wasmtime_wasi::add_to_linker(&mut linker, |c: &mut Context| &mut c.wasi_ctx)?;

        let instance_pre = linker.instantiate_pre(&module)?;

        Ok(Stack {
            engine,
            instance_pre,
            epoch_deadlines,
        })
    }
}
