use std::io::Cursor;
use std::sync::{Arc, RwLock};
use wasi_common::pipe::{ReadPipe, WritePipe};
use wasi_common::WasiCtx;
use wasmtime_wasi::sync::WasiCtxBuilder;

use crate::evaluation_context::EvaluationContext;
use crate::runtimes::wasi_cli::{
    errors::WasiRuntimeError, stack_pre::StackPre, wasi_pipe::WasiPipe,
};

const EXIT_SUCCESS: i32 = 0;

pub(crate) struct Context {
    pub(crate) wasi_ctx: WasiCtx,
    pub(crate) stdin_pipe: Arc<RwLock<WasiPipe>>,
    pub(crate) eval_ctx: Arc<EvaluationContext>,
}

pub(crate) struct Stack {
    stack_pre: StackPre,
    eval_ctx: Arc<EvaluationContext>,
}

pub(crate) struct RunResult {
    pub stdout: String,
    pub stderr: String,
}

impl Stack {
    pub(crate) fn new_from_pre(stack_pre: &StackPre, eval_ctx: &EvaluationContext) -> Self {
        Self {
            stack_pre: stack_pre.to_owned(),
            eval_ctx: Arc::new(eval_ctx.to_owned()),
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
        let stdin_pipe: Arc<RwLock<WasiPipe>> = Arc::new(RwLock::new(WasiPipe::new(input)));

        let args: Vec<String> = args.iter().map(|s| s.to_string()).collect();

        let wasi_ctx = WasiCtxBuilder::new()
            .args(&args)
            .map_err(WasiRuntimeError::WasiCtxBuilder)?
            .stdin(Box::new(ReadPipe::from_shared(stdin_pipe.clone())))
            .stdout(Box::new(stdout_pipe.clone()))
            .stderr(Box::new(stderr_pipe.clone()))
            .build();
        let ctx = Context {
            wasi_ctx,
            stdin_pipe,
            eval_ctx: self.eval_ctx.clone(),
        };

        let mut store = self.stack_pre.build_store(ctx);
        let instance = self.stack_pre.rehydrate(&mut store)?;
        let start_fn = instance
            .get_typed_func::<(), ()>(&mut store, "_start")
            .map_err(WasiRuntimeError::WasmMissingStartFn)?;
        let evaluation_result = start_fn.call(&mut store, ());

        // Dropping the store, this is no longer needed, plus it's keeping
        // references to the WritePipe(s) that we need exclusive access to.
        drop(store);

        let stderr = pipe_to_string("stderr", stderr_pipe)?;

        if let Err(err) = evaluation_result {
            if let Some(exit_error) = err.downcast_ref::<wasi_common::I32Exit>() {
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
