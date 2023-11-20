use thiserror::Error;

pub type FetcherResult<T> = std::result::Result<T, FetcherError>;

#[derive(Error, Debug)]
pub enum FetcherError {
    #[error("cannot retrieve path from uri: {0}")]
    InvalidFilePathError(String),
    #[error("invalid wasm file")]
    InvalidWasmFileError,
    #[error("wasm module cannot be save to {0:?}: {1}")]
    CannotWriteWasmModuleFile(String, #[source] std::io::Error),
    #[error(transparent)]
    PolicyError(#[from] crate::policy::DigestError),
    #[error(transparent)]
    VerifyError(#[from] crate::verify::errors::VerifyError),
    #[error(transparent)]
    RegistryError(#[from] crate::registry::errors::RegistryError),
    #[error(transparent)]
    UrlParserError(#[from] url::ParseError),
    #[error(transparent)]
    SourceError(#[from] crate::sources::SourceError),
    #[error(transparent)]
    StoreError(#[from] crate::store::errors::StoreError),
    #[error(transparent)]
    InvalidURLError(#[from] InvalidURLError),
    #[error(transparent)]
    CannotCreateStoragePathError(#[from] CannotCreateStoragePathError),
}

#[derive(thiserror::Error, Debug)]
#[error("{0}")]
pub struct FailedToParseYamlDataError(#[from] pub serde_yaml::Error);

#[derive(thiserror::Error, Debug)]
#[error("invalid URL: {0}")]
pub struct CannotCreateStoragePathError(#[from] pub std::io::Error);

#[derive(thiserror::Error, Debug)]
#[error("invalid URL: {0}")]
pub struct InvalidURLError(pub String);
