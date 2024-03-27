use std::io::Write;

use wasmtime::{AsContext, Engine, InstancePre, Linker, Memory, Module, StoreContext};

use crate::runtimes::wasi_cli::errors::{Result, WasiRuntimeError};

use crate::policy_evaluator_builder::EpochDeadlines;
use crate::runtimes::{callback::host_callback, wasi_cli::stack::Context};

/// Reduce the allocation time of a Wasi Stack. This is done by leveraging `wasmtime::InstancePre`.
#[derive(Clone)]
pub(crate) struct StackPre {
    engine: Engine,
    instance_pre: InstancePre<Context>,
    epoch_deadlines: Option<EpochDeadlines>,
}

impl StackPre {
    pub(crate) fn new(
        engine: Engine,
        module: Module,
        epoch_deadlines: Option<EpochDeadlines>,
    ) -> Result<Self> {
        let mut linker = Linker::<Context>::new(&engine);
        wasi_common::sync::add_to_linker(&mut linker, |c: &mut Context| &mut c.wasi_ctx)
            .map_err(WasiRuntimeError::WasmLinkerError)?;
        add_host_call_to_linker(&mut linker)?;

        let instance_pre = linker
            .instantiate_pre(&module)
            .map_err(WasiRuntimeError::WasmInstantiate)?;
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
        self.instance_pre
            .instantiate(store)
            .map_err(WasiRuntimeError::WasmInstantiate)
    }
}

fn add_host_call_to_linker(linker: &mut wasmtime::Linker<Context>) -> Result<()> {
    linker
        .func_wrap(
            "host",
            "call",
            |mut caller: wasmtime::Caller<'_, Context>,
             bd_ptr: i32,
             bd_len: i32,
             ns_ptr: i32,
             ns_len: i32,
             op_ptr: i32,
             op_len: i32,
             ptr: i32,
             len: i32| {
                let memory_export = caller
                    .get_export("memory")
                    .ok_or_else(|| WasiRuntimeError::WasiMemExport)?;
                let memory = memory_export
                    .into_memory()
                    .ok_or_else(|| WasiRuntimeError::WasiMemExportCannotConvert)?;

                let stdin = caller.data().stdin_pipe.as_ref();

                let vec = get_vec_from_memory(caller.as_context(), memory, ptr, len);
                let bd_vec = get_vec_from_memory(caller.as_context(), memory, bd_ptr, bd_len);
                let bd = std::str::from_utf8(&bd_vec).map_err(WasiRuntimeError::WasiMemOpToUtF8)?;
                let ns_vec = get_vec_from_memory(caller.as_context(), memory, ns_ptr, ns_len);
                let ns = std::str::from_utf8(&ns_vec).map_err(WasiRuntimeError::WasiMemOpToUtF8)?;
                let op_vec = get_vec_from_memory(caller.as_context(), memory, op_ptr, op_len);
                let op = std::str::from_utf8(&op_vec).map_err(WasiRuntimeError::WasiMemOpToUtF8)?;

                let host_callback_response =
                    host_callback(bd, ns, op, &vec, &caller.data().eval_ctx);

                // return 1 if the host callback failed, 0 otherwise
                let func_return_value = host_callback_response.is_err() as i32;

                let response_msg = match host_callback_response {
                    Ok(r) => r,
                    Err(e) => e.to_string().as_bytes().to_owned(),
                };

                let mut stdin_pipe = stdin
                    .write()
                    .map_err(|_| WasiRuntimeError::WasiWriteAccessStdin())?;
                let _ = stdin_pipe
                    .write(&response_msg)
                    .map_err(|_| WasiRuntimeError::WasiCannotWriteStdin())?;
                Ok(func_return_value)
            },
        )
        .map_err(|e| WasiRuntimeError::WasmHostFuncDefinitionError {
            name: "host.call".to_string(),
            error: e.to_string(),
        })?;
    Ok(())
}

fn get_vec_from_memory<'a, T: 'a>(
    store: impl Into<StoreContext<'a, T>>,
    mem: Memory,
    ptr: i32,
    len: i32,
) -> Vec<u8> {
    let data = mem.data(store);
    data[ptr as usize..(ptr + len) as usize].to_vec()
}
