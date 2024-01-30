use thiserror::Error;

pub type Result<T> = std::result::Result<T, WasiRuntimeError>;

#[derive(Error, Debug)]
pub enum WasiRuntimeError {
    #[error("cannot set wasi args")]
    WasiStringArray(#[source] wasi_common::StringArrayError),

    #[error("program exited with code {code:?}; stderr set to '{stderr}', error: '{error}'")]
    WasiEvaluation {
        code: Option<i32>,
        stderr: String,
        #[source]
        error: wasmtime::Error,
    },

    #[error("cannot find `_start` function inside of module: {0}")]
    WasmMissingStartFn(#[source] wasmtime::Error),

    #[error("{name} pipe conversion error: {error}")]
    PipeConversion { name: String, error: String },

    #[error("cannot instantiate module: {0}")]
    WasmLinkerError(#[source] wasmtime::Error),

    #[error("cannot add to linker: {0}")]
    WasmInstantiate(#[source] wasmtime::Error),

    #[error("cannot find 'mem' export")]
    WasiMemExport,

    #[error("'mem' export cannot be converted into a Memory instance")]
    WasiMemExportCannotConvert,

    #[error("cannot build WasiCtxBuilder: {0}")]
    WasiCtxBuilder(#[source] wasi_common::StringArrayError),

    #[error("host_call: cannot convert bd to UTF8: {0}")]
    WasiMemOpToUtF8(#[source] std::str::Utf8Error),

    // corresponds to a PoisonError, whose error message is not particularly useful anyways
    #[error("host_call: cannot write to STDIN")]
    WasiCannotWriteStdin(),

    // corresponds to a PoisonError, whose error message is not particularly useful anyways
    #[error("host_call: cannot get write access to STDIN")]
    WasiWriteAccessStdin(),
}

impl From<std::convert::Infallible> for WasiRuntimeError {
    fn from(_: std::convert::Infallible) -> Self {
        unreachable!()
    }
}

// impl From<std::result::Result<std::convert::Infallible, wasmtime::Error>>
//     for std::result::Result<(), WasiRuntimeError>
// {
//     fn from(_: std::convert::Infallible) -> Self {
//         unreachable!()
//     }
// }

// impl Into<std::result::Result<(), WasiRuntimeError>>
//     for std::result::Result<std::convert::Infallible, wasmtime::Error>
// {
//     fn into(_: std::result::Result<(), WasiRuntimeError>) -> Self {
//         unreachable!()
//     }
// }
