use thiserror::Error;

use crate::errors::PolicyEvaluatorPreError;

pub type Result<T> = std::result::Result<T, EvaluationError>;

#[derive(Debug, Error)]
pub enum EvaluationError {
    #[error("EvaluatorPre not found: {0}")]
    EvaluatorPreNotFound(String),

    #[error("settings not found policy: {0}")]
    SettingsNotFound(String),

    #[error("settings not valid: {0}")]
    SettingsNotValid(String),

    #[error("unknown policy: {0}")]
    PolicyNotFound(String),

    #[error("Attempted to rehydrated policy '{0}': {1}")]
    CannotRehydratePolicyGroupMember(String, PolicyEvaluatorPreError),

    #[error("Policy group evaluation error: '{0}'")]
    PolicyGroupRuntimeError(#[from] Box<rhai::EvalAltResult>),
}
