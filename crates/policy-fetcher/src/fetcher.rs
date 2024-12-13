use std::fmt;

use async_trait::async_trait;
use url::Url;

use crate::{sources::Certificate, sources::SourceResult};

#[derive(Clone, Debug, PartialEq)]
pub(crate) enum ClientProtocol {
    Http,
    Https(TlsVerificationMode),
}

impl fmt::Display for ClientProtocol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ClientProtocol::Http => write!(f, "HTTP"),
            ClientProtocol::Https(mode) => write!(f, "HTTPS({})", mode),
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub(crate) enum TlsVerificationMode {
    CustomCaCertificates(Vec<Certificate>),
    SystemCa,
    NoTlsVerification,
}

impl fmt::Display for TlsVerificationMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TlsVerificationMode::CustomCaCertificates(_) => write!(f, "CustomCaCertificates"),
            TlsVerificationMode::SystemCa => write!(f, "SystemCa"),
            TlsVerificationMode::NoTlsVerification => write!(f, "NoTlsVerification"),
        }
    }
}

// Generic interface for all the operations related with obtaining
// a WASM module
#[async_trait]
pub(crate) trait PolicyFetcher {
    // Download and return the bytes of the WASM module
    async fn fetch(&self, url: &Url, client_protocol: ClientProtocol) -> SourceResult<Vec<u8>>;
}
