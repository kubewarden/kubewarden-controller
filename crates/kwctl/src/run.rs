use anyhow::Result;
use policy_evaluator::policy_evaluator::PolicyEvaluator;
use policy_fetcher::{registry::config::DockerConfig, sources::Sources};

use crate::pull;

pub(crate) async fn pull_and_run(
    uri: &str,
    docker_config: Option<DockerConfig>,
    sources: Option<Sources>,
    request: &str,
    settings: Option<String>,
) -> Result<()> {
    let policy_path = pull::pull(
        uri,
        docker_config,
        sources,
        policy_fetcher::PullDestination::MainStore,
    )
    .await?;
    println!(
        "{}",
        serde_json::to_string(
            &PolicyEvaluator::new(
                policy_path.as_path(),
                settings.map_or(Ok(None), |settings| serde_yaml::from_str(&settings))?,
            )?
            .validate(serde_json::from_str(&request)?)
        )?
    );
    Ok(())
}
