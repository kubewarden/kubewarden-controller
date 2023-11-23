use thiserror::Error;

pub type Result<T> = std::result::Result<T, RegoRuntimeError>;

#[derive(Error, Debug)]
pub enum RegoRuntimeError {
    #[error("cannot build Rego context aware data: callback channel is not set")]
    CallbackChannelNotSet(),

    #[error("cannot convert callback response into a list of kubernetes objects: {0}")]
    CallbackConvertList(#[source] serde_json::Error),

    #[error("error sending request over callback channel: {0}")]
    CallbackSend(String), // TODO same as CallbackRequest?

    #[error("error obtaining response from callback channel: {0}")]
    CallbackResponse(String),

    #[error("cannot perform a request via callback channel: {0}")]
    CallbackRequest(#[source] wasmtime::Error),

    #[error("get plural name failure, cannot convert callback response: {0}")]
    CallbackGetPluralName(#[source] serde_json::Error),
}
