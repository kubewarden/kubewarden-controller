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

    #[error("DynamicObject does not have a name")]
    GatekeeperInventoryMissingName(),

    #[error("DynamicObject does not have a namespace")]
    GatekeeperInventoryMissingNamespace(),

    #[error("DynamicObject does not have a name")]
    OpaInventoryMissingName(),

    #[error("DynamicObject does not have a namespace")]
    OpaInventoryMissingNamespace(),

    #[error("trying to add a namespaced resource to a list of clusterwide resources")]
    OpaInventoryAddNamespacedRes(),

    #[error("trying to add a clusterwide resource to a list of namespaced resources")]
    OpaInventoryAddClusterwideRes(),

    #[error("cannot find plural name for resource {0}")]
    OpaInventoryMissingPluralName(String),

    #[error("invalid response from policy")]
    InvalidResponse(),

    #[error("invalid response from policy: {0}")]
    InvalidResponseWithError(#[source] serde_json::Error),
}
