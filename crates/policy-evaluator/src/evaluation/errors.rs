use thiserror::Error;

pub type Result<T> = std::result::Result<T, EvaluationError>;

#[derive(Debug, Error)]
pub enum EvaluationError {
    #[error("unknown policy: {0}")]
    PolicyNotFound(String),

    #[error("bootstrap failure: {0}")]
    BootstrapFailure(String),

    #[error("WebAssembly failure: {0}")]
    WebAssemblyError(String),

    #[error("{0}")]
    InternalError(String),
}
