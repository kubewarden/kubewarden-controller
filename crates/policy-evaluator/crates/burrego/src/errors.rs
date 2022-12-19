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

    #[error("JSON error: {0}")]
    JSONError(String),

    #[error("Evaluator builder error: {0}")]
    EvaluatorBuilderError(String),

    #[error("Builtin error [{name:?}]: {message:?}")]
    BuiltinError { name: String, message: String },

    #[error("Builtin not implemented: {0}")]
    BuiltinNotImplementedError(String),
}
