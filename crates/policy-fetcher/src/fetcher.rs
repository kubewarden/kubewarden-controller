use anyhow::Result;
use async_trait::async_trait;
use bytes::Bytes;
use url::Url;

use crate::sources::Certificate;

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
    // Download the WASM module to the provided destination
    async fn fetch(&self, url: &Url, client_protocol: ClientProtocol) -> Result<Bytes>;
}
