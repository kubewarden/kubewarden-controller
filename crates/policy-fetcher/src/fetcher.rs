use anyhow::Result;
use async_trait::async_trait;
use std::path::Path;
use url::Url;

use crate::registry::config::DockerConfig;
use crate::sources::Sources;

// Generic interface for all the operations related with obtaining
// a WASM module
#[async_trait]
pub(crate) trait Fetcher {
    // Download the WASM module to the provided destination
    async fn fetch(
        &self,
        url: &Url,
        destination: &Path,
        sources: Option<&Sources>,
        docker_config: Option<&DockerConfig>,
    ) -> Result<()>;
}
