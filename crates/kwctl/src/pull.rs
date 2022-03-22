use anyhow::Result;
use policy_evaluator::policy_fetcher::registry::config::DockerConfig;
use policy_evaluator::policy_fetcher::{
    fetch_policy, policy::Policy, sources::Sources, PullDestination,
};

pub(crate) async fn pull(
    uri: &str,
    docker_config: Option<&DockerConfig>,
    sources: Option<&Sources>,
    destination: PullDestination,
) -> Result<Policy> {
    fetch_policy(uri, destination, docker_config, sources).await
}
