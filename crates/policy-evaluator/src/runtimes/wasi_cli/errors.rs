use thiserror::Error;

#[derive(Error, Debug)]
pub enum WasiRuntimeError {
    #[error("cannot set wasi args")]
    WasiStringArray(#[from] wasi_common::StringArrayError),

    #[error("program exited with code {code:?}; stderr set to '{stderr}', error: '{error}'")]
    WasiEvaluation {
        code: Option<i32>,
        stderr: String,
        error: wasmtime::Error,
    },

    #[error("cannot instantiate module: {0}")]
    WasmInstantiate(wasmtime::Error),

    #[error("cannot find `_start` function inside of module: {0}")]
    WasmMissingStartFn(wasmtime::Error),

    #[error("{name} pipe conversion error: {error}")]
    PipeConversion { name: String, error: String },
}
