use anyhow::{anyhow, Result};
use kube::Client;
use policy_evaluator::{
    cluster_context::ClusterContext, policy_evaluator::PolicyEvaluator, policy_metadata::Metadata,
};
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
    let policy_path = policy_path.as_path();

    if let Some(metadata) = Metadata::from_path(policy_path)? {
        if metadata.context_aware {
            println!("Fetching Kubernetes context since this policy is context-aware");

            let kubernetes_client = Client::try_default()
                .await
                .map_err(|e| anyhow!("could not initialize a cluster context because a Kubernetes client could not be created: {}", e))?;

            ClusterContext::get()
                .refresh(&kubernetes_client)
                .await
                .map_err(|e| anyhow!("could not initialize a cluster context: {}", e))?;
        }
    }

    let request = serde_json::from_str::<serde_json::Value>(&request)?;
    let policy_evaluator = PolicyEvaluator::new(
        policy_path,
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
