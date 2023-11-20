use thiserror::Error;

use crate::{errors::FailedToParseYamlDataError, registry::errors::RegistryError};

pub type VerifyResult<T> = std::result::Result<T, VerifyError>;

#[derive(Error, Debug)]
pub enum VerifyError {
    #[error("faild to read verification file: {0}")]
    VerificationFileReadError(#[from] std::io::Error),
    #[error("{0}")]
    ChecksumVerificationError(String),
    #[error("{0}")]
    ImageVerificationError(String),
    #[error("{0}")]
    InvalidVerifyFileError(String),
    #[error("Verification only works with OCI images: Not a valid oci image: {0}")]
    InvalidOCIImageReferenceError(#[from] oci_distribution::ParseError),
    #[error("key verification failure: {0} ")]
    KeyVerificationError(#[source] sigstore::errors::SigstoreError),
    // The next error is more specialized error based on a sigstore error. It must
    // be used explicit. Otherwise, the KeyVerificationError will be used by default
    // due the implicit conversion.
    #[error("failed to get image trusted layers: {0}")]
    FailedToFetchTrustedLayersError(#[from] sigstore::errors::SigstoreError),
    #[error("Policy cannot be verified, local wasm file doesn't exist: {0}")]
    MissingWasmFileError(String),
    #[error(transparent)]
    DigestErrors(#[from] crate::policy::DigestError),
    #[error(transparent)]
    RegistryError(#[from] RegistryError),
    #[error("{0}")]
    GithubUrlParserError(String),
    #[error(transparent)]
    FailedToParseYamlDataError(#[from] FailedToParseYamlDataError),
}
