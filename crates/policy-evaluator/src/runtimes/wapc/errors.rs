use thiserror::Error;

pub type Result<T> = std::result::Result<T, WapcRuntimeError>;

#[derive(Error, Debug)]
pub enum WapcRuntimeError {
    #[error("invalid response format: {0}")]
    InvalidResponseFormat(#[source] anyhow::Error),

    #[error("invalid response from policy: {0}")]
    InvalidResponseWithError(#[source] serde_json::Error),

    #[error("cannot create ProtocolVersion object from {res:?}: {error}")]
    CreateProtocolVersion {
        res: std::vec::Vec<u8>,
        #[source]
        error: wasmtime::Error,
    },

    #[error("cannot invoke 'protocol_version' waPC function : {0}")]
    InvokeProtocolVersion(#[source] wapc::errors::Error),

    #[error("cannot build Wasmtime engine: {0}")]
    WasmtimeEngineBuilder(#[source] wasmtime_provider::errors::Error),

    #[error("cannot build Wapc host: {0}")]
    WapcHostBuilder(#[source] wapc::errors::Error),
}
