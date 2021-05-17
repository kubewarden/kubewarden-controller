use anyhow::Result;
use async_trait::async_trait;

use std::path::Path;
use url::Url;

use crate::fetcher::Fetcher;
use crate::registry::config::DockerConfig;
use crate::sources::Sources;

// Struct used to reference a WASM module that is already on the
// local file system
pub(crate) struct Local;

#[async_trait]
impl Fetcher for Local {
    async fn fetch(
        &self,
        _url: &Url,
        _destination: &Path,
        _sources: Option<&Sources>,
        _docker_config: Option<&DockerConfig>,
    ) -> Result<()> {
        Ok(())
    }
}
