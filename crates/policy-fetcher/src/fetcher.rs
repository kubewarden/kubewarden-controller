use anyhow::Result;
use async_trait::async_trait;
use std::path::Path;
use url::Url;

use crate::sources::Certificate;

#[derive(Clone, PartialEq)]
pub(crate) enum ClientProtocol {
    Http,
    Https(TlsVerificationMode),
}

#[derive(Clone, PartialEq)]
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
    async fn fetch(
        &self,
        url: &Url,
        client_protocol: ClientProtocol,
        destination: &Path,
    ) -> Result<()>;
}
