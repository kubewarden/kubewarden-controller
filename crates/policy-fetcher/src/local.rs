use anyhow::Result;
use async_trait::async_trait;
use std::path::Path;
use url::Url;

use crate::fetcher::{ClientProtocol, PolicyFetcher};

// Struct used to reference a WASM module that is already on the
// local file system
#[derive(Default)]
pub(crate) struct Local;

#[async_trait]
impl PolicyFetcher for Local {
    async fn fetch(
        &self,
        _url: &Url,
        _client_protocol: ClientProtocol,
        _destination: &Path,
    ) -> Result<()> {
        Ok(())
    }
}
