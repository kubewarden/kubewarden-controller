use anyhow::Result;
use std::io::Cursor;
use wasi_common::pipe::{ReadPipe, WritePipe};
use wasi_common::WasiCtx;
use wasmtime::{Engine, Module};
use wasmtime_wasi::sync::WasiCtxBuilder;

use crate::policy_evaluator_builder::EpochDeadlines;
use crate::runtimes::wasi_cli::{errors::WasiRuntimeError, stack_pre::StackPre};

const EXIT_SUCCESS: i32 = 0;

pub(crate) struct Context {
    pub(crate) wasi_ctx: WasiCtx,
}

pub(crate) struct Stack {
    stack_pre: StackPre,
}

pub(crate) struct RunResult {
    pub stdout: String,
    pub stderr: String,
}

impl Stack {
    pub(crate) fn new(
        engine: Engine,
        module: Module,
        epoch_deadlines: Option<EpochDeadlines>,
    ) -> Result<Self> {
        let stack_pre = StackPre::new(engine, module, epoch_deadlines)?;
        Ok(Self { stack_pre })
    }

    pub(crate) fn new_from_pre(stack_pre: &StackPre) -> Self {
        Self {
            stack_pre: stack_pre.to_owned(),
        }
    }

    /// Run a WASI program with the given input and args
    pub(crate) fn run(
        &self,
        input: &[u8],
        args: &[&str],
    ) -> std::result::Result<RunResult, WasiRuntimeError> {
        let stdout_pipe = WritePipe::new_in_memory();
        let stderr_pipe = WritePipe::new_in_memory();
        let stdin_pipe = ReadPipe::new(Cursor::new(input.to_owned()));

        let args: Vec<String> = args.iter().map(|s| s.to_string()).collect();

        let wasi_ctx = WasiCtxBuilder::new()
            .args(&args)?
            .stdin(Box::new(stdin_pipe))
            .stdout(Box::new(stdout_pipe.clone()))
            .stderr(Box::new(stderr_pipe.clone()))
            .build();
        let ctx = Context { wasi_ctx };

        let mut store = self.stack_pre.build_store(ctx);
        let instance = self
            .stack_pre
            .rehydrate(&mut store)
            .map_err(WasiRuntimeError::WasmInstantiate)?;
        let start_fn = instance
            .get_typed_func::<(), ()>(&mut store, "_start")
            .map_err(WasiRuntimeError::WasmMissingStartFn)?;
        let evaluation_result = start_fn.call(&mut store, ());

        // Dropping the store, this is no longer needed, plus it's keeping
        // references to the WritePipe(s) that we need exclusive access to.
        drop(store);

        let stderr = pipe_to_string("stderr", stderr_pipe)?;

        if let Err(err) = evaluation_result {
            if let Some(exit_error) = err.downcast_ref::<wasmtime_wasi::I32Exit>() {
                if exit_error.0 == EXIT_SUCCESS {
                    let stdout = pipe_to_string("stdout", stdout_pipe)?;
                    return Ok(RunResult { stdout, stderr });
                } else {
                    return Err(WasiRuntimeError::WasiEvaluation {
                        code: Some(exit_error.0),
                        stderr,
                        error: err,
                    });
                }
            }
            return Err(WasiRuntimeError::WasiEvaluation {
                code: None,
                stderr,
                error: err,
            });
        }

        let stdout = pipe_to_string("stdout", stdout_pipe)?;
        Ok(RunResult { stdout, stderr })
    }
}

fn pipe_to_string(
    name: &str,
    pipe: WritePipe<Cursor<Vec<u8>>>,
) -> std::result::Result<String, WasiRuntimeError> {
    match pipe.try_into_inner() {
        Ok(cursor) => {
            let buf = cursor.into_inner();
            String::from_utf8(buf).map_err(|e| WasiRuntimeError::PipeConversion {
                name: name.to_string(),
                error: format!("Cannot convert buffer to UTF8 string: {e}"),
            })
        }
        Err(_) => Err(WasiRuntimeError::PipeConversion {
            name: name.to_string(),
            error: "cannot convert pipe into inner".to_string(),
        }),
    }
}
