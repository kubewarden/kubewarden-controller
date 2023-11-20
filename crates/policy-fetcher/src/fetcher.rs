use async_trait::async_trait;
use url::Url;

use crate::{sources::Certificate, sources::SourceResult};

#[derive(Clone, Debug, PartialEq)]
pub(crate) enum ClientProtocol {
    Http,
    Https(TlsVerificationMode),
}

#[derive(Clone, Debug, PartialEq)]
pub(crate) enum TlsVerificationMode {
    CustomCaCertificates(Vec<Certificate>),
    SystemCa,
    NoTlsVerification,
}

// Generic interface for all the operations related with obtaining
// a WASM module
#[async_trait]
pub(crate) trait PolicyFetcher {
    // Download and return the bytes of the WASM module
    async fn fetch(&self, url: &Url, client_protocol: ClientProtocol) -> SourceResult<Vec<u8>>;
}
