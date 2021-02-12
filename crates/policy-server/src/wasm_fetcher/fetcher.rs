use anyhow::Result;
use async_trait::async_trait;

// Generic interface for all the operations related with obtaining
// a WASM module
#[async_trait]
pub(crate) trait Fetcher {
    // Download, if needed, the WASM module and return the path to the
    // file on the local disk
    async fn fetch(&self) -> Result<String>;
}
