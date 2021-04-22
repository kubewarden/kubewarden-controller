use anyhow::Result;
use policy_fetcher::registry::config::DockerConfig;
use policy_fetcher::{fetch_wasm_module, sources::Sources, storage::Storage};

use std::path::PathBuf;

pub(crate) enum PullDestination {
    MainStorage,
    LocalFile(PathBuf),
}

pub(crate) async fn pull(
    uri: &str,
    docker_config: Option<DockerConfig>,
    sources: Option<Sources>,
    destination: PullDestination,
) -> Result<PathBuf> {
    let destination = match destination {
        PullDestination::MainStorage => Storage::default().root,
        PullDestination::LocalFile(destination) => destination,
    };
    fetch_wasm_module(
        uri,
        &destination,
        docker_config,
        &sources.unwrap_or_default(),
    )
    .await
}
