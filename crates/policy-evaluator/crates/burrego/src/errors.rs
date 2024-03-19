use thiserror::Error;

pub type Result<T> = std::result::Result<T, BurregoError>;

#[derive(Error, Debug)]
pub enum BurregoError {
    #[error("Missing Rego builtins: {0}")]
    MissingRegoBuiltins(String),

    #[error("wasm engine error: {0}")]
    WasmEngineError(String),

    #[error("Rego wasm error: {0}")]
    RegoWasmError(String),

    #[error("{msg}: {source}")]
    JSONError {
        msg: String,
        source: serde_json::Error,
    },

    #[error("Evaluator builder error: {0}")]
    EvaluatorBuilderError(String),

    #[error("Builtin error [{name:?}]: {message:?}")]
    BuiltinError { name: String, message: String },

    #[error("Builtin not implemented: {0}")]
    BuiltinNotImplementedError(String),

    /// Wasmtime execution deadline exceeded
    #[error("guest code interrupted, execution deadline exceeded")]
    ExecutionDeadlineExceeded,
}
