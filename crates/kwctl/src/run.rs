use anyhow::Result;
use policy_evaluator::policy_evaluator::PolicyEvaluator;
use policy_fetcher::{registry::config::DockerConfig, sources::Sources};

use crate::pull;

pub(crate) async fn pull_and_run(
    uri: &str,
    docker_config: Option<DockerConfig>,
    sources: Option<Sources>,
    request: &str,
    settings: Option<&str>,
) -> Result<()> {
    let policy_path = pull::pull(
        uri,
        docker_config,
        sources,
        pull::PullDestination::MainStorage,
    )
    .await?;
    println!(
        "{}",
        serde_json::to_string(
            &PolicyEvaluator::new(
                policy_path.as_path(),
                serde_yaml::from_str(settings.unwrap_or_default())?,
            )?
            .validate(request.into())
        )?
    );
    Ok(())
}
