use thiserror::Error;

pub type Result<T> = std::result::Result<T, WapcRuntimeError>;


#[derive(Error, Debug)]
pub enum WapcRuntimeError {
    #[error("invalid response format: {0}")]
    InvalidResponseFormat(#[source] anyhow::Error),

    #[error("invalid response from policy: {0}")]
    InvalidResponseWithError(#[source] serde_json::Error),

    #[error("cannot invoke 'protocol_version' waPC function : {0}")]
    InvokeProtocolVersion(#[source] wapc::errors::Error),
}
