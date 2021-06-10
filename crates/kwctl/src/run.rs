use anyhow::{anyhow, Result};
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
    let uri = crate::utils::map_path_to_uri(uri)?;

    let policy_path = pull::pull(
        &uri,
        docker_config,
        sources,
        policy_fetcher::PullDestination::MainStore,
    )
    .await
    .map_err(|e| anyhow!("error pulling policy {}: {}", uri, e))?;

    let request = serde_json::from_str::<serde_json::Value>(&request)?;
    let policy_evaluator = PolicyEvaluator::new(
        policy_path.as_path(),
        settings.map_or(Ok(None), |settings| {
            if settings.is_empty() {
                Ok(None)
            } else {
                serde_yaml::from_str(&settings)
            }
        })?,
    )
    .map_err(|err| {
        anyhow!(
            "error creating policy evaluator for policy {}: {}",
            uri,
            err
        )
    })?;
    let req_obj = match request {
        serde_json::Value::Object(ref object) => {
            if object.get("kind").and_then(serde_json::Value::as_str) == Some("AdmissionReview") {
                object
                    .get("request")
                    .ok_or_else(|| anyhow!("invalid admission review object"))
            } else {
                Ok(&request)
            }
        }
        _ => Err(anyhow!("request to evaluate is invalid")),
    }?;

    // validate the settings given by the user
    let settings_validation_response = policy_evaluator.validate_settings();
    if !settings_validation_response.valid {
        println!("{}", serde_json::to_string(&settings_validation_response)?);
        return Err(anyhow!(
            "Provided settings are not valid: {:?}",
            settings_validation_response.message
        ));
    }

    // evaluate request
    let response = policy_evaluator.validate(req_obj.clone());
    println!("{}", serde_json::to_string(&response)?);

    Ok(())
}
