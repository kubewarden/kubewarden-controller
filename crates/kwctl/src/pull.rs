use anyhow::Result;
use policy_evaluator::policy_fetcher::{
    fetch_policy, policy::Policy, sources::Sources, PullDestination,
};

pub(crate) async fn pull(
    uri: &str,
    sources: Option<&Sources>,
    destination: PullDestination,
) -> Result<Policy> {
    fetch_policy(uri, destination, sources)
        .await
        .map_err(anyhow::Error::new)
}
