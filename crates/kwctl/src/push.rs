use anyhow::Result;

use policy_fetcher::{registry::config::DockerConfig, registry::Registry, sources::Sources};

pub(crate) async fn push(
    policy: &[u8],
    uri: &str,
    docker_config: Option<DockerConfig>,
    sources: Option<Sources>,
) -> Result<()> {
    Registry::push(&policy, uri, docker_config.as_ref(), sources.as_ref()).await
}
