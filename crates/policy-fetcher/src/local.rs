use anyhow::Result;
use async_trait::async_trait;

use crate::fetcher::Fetcher;
use crate::sources::Sources;

use std::path::PathBuf;

// Struct used to reference a WASM module that is already on the
// local file system
pub(crate) struct Local {
    // full path to the WASM module
    local_path: PathBuf,
}

impl Local {
    // Allocates a LocalWASM instance starting from the user
    // provided URL
    pub(crate) fn new(path: PathBuf) -> Local {
        Local { local_path: path }
    }
}

#[async_trait]
impl Fetcher for Local {
    async fn fetch(&self, _sources: &Sources) -> Result<PathBuf> {
        Ok(self.local_path.clone())
    }
}
