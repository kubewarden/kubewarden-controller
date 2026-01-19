use thiserror::Error;

pub type Result<T> = std::result::Result<T, EvaluationError>;

#[derive(Debug, Error)]
pub enum EvaluationError {
    #[error("Not a valid Policy ID: {0}")]
    InvalidPolicyId(String),

    #[error("{0}")]
    PolicyInitialization(String),

    #[error("unknown policy: {0}")]
    PolicyNotFound(String),

    #[error("bootstrap failure: {0}")]
    BootstrapFailure(String),

    #[error("WebAssembly failure: {0}")]
    WebAssemblyError(String),

    #[error("Attempted to rehydrated policy group '{0}'")]
    CannotRehydratePolicyGroup(String),
}
