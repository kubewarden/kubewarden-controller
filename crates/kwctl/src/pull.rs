use anyhow::Result;
use policy_fetcher::registry::config::DockerConfig;
use policy_fetcher::{fetch_policy, sources::Sources, PullDestination};

use std::path::PathBuf;

pub(crate) async fn pull(
    uri: &str,
    docker_config: Option<DockerConfig>,
    sources: Option<Sources>,
    destination: PullDestination,
) -> Result<PathBuf> {
    fetch_policy(uri, destination, docker_config, sources.as_ref()).await
}
