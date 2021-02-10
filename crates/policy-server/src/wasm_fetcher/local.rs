use anyhow::Result;
use async_trait::async_trait;

use crate::wasm_fetcher::fetcher::Fetcher;

// Struct used to reference a WASM module that is already on the
// local file system
pub(crate) struct Local {
    // full path to the WASM module
    local_path: String,
}

impl Local {
    // Allocates a LocalWASM instance starting from the user
    // provided URL
    pub(crate) fn new(path: &str) -> Local {
        Local {
            local_path: String::from(path),
        }
    }
}

#[async_trait]
impl Fetcher for Local {
    async fn fetch(&self) -> Result<String> {
        Ok(self.local_path.clone())
    }
}
