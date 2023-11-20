use thiserror::Error;

use crate::errors::InvalidURLError;

pub type RegistryResult<T> = std::result::Result<T, RegistryError>;

#[derive(Error, Debug)]
pub enum RegistryError {
    #[error("Fail to interact with OCI registry: {0}")]
    OCIRegistryError(#[from] oci_distribution::errors::OciDistributionError),
    #[error("Invalid OCI image reference: {0}")]
    InvalidOCIImageReferenceError(#[from] oci_distribution::ParseError),
    #[error("{0}")]
    BuildImmutableReferenceError(String),
    #[error("Invalid destination format")]
    InvalidDestinationError,
    #[error(transparent)]
    UrlParserError(#[from] url::ParseError),
    #[error(transparent)]
    InvalidURLError(#[from] InvalidURLError),
}
