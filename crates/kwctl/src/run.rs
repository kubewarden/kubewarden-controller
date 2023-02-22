use anyhow::{anyhow, Result};
use policy_evaluator::{
    callback_handler::{CallbackHandler, CallbackHandlerBuilder},
    constants::*,
    kube::Client,
    policy_evaluator::{Evaluator, PolicyEvaluator},
    policy_evaluator::{PolicyExecutionMode, ValidateRequest},
    policy_evaluator_builder::PolicyEvaluatorBuilder,
    policy_fetcher::{sources::Sources, verify::FulcioAndRekorData, PullDestination},
    policy_metadata::{ContextAwareResource, Metadata},
};
use std::{collections::HashSet, path::Path};
use tokio::sync::oneshot;
use tracing::{error, info, warn};

use crate::{backend::BackendDetector, pull, verify};

pub(crate) struct PullAndRunSettings {
    pub uri: String,
    pub user_execution_mode: Option<PolicyExecutionMode>,
    pub sources: Option<Sources>,
    pub request: String,
    pub settings: Option<String>,
    pub verified_manifest_digest: Option<String>,
    pub fulcio_and_rekor_data: Option<FulcioAndRekorData>,
    pub enable_wasmtime_cache: bool,
    pub allow_context_aware_resources: bool,
}

pub(crate) struct RunEnv {
    pub policy_evaluator: PolicyEvaluator,
    pub req_obj: serde_json::Value,
    pub callback_handler: CallbackHandler,
    pub callback_handler_shutdown_channel_tx: oneshot::Sender<()>,
}

pub(crate) async fn prepare_run_env(cfg: &PullAndRunSettings) -> Result<RunEnv> {
    let uri = crate::utils::map_path_to_uri(&cfg.uri)?;
    let sources = cfg.sources.as_ref();
    let fulcio_and_rekor_data = cfg.fulcio_and_rekor_data.as_ref();

    let policy = pull::pull(&uri, sources, PullDestination::MainStore)
        .await
        .map_err(|e| anyhow!("error pulling policy {}: {}", uri, e))?;

    if let Some(digest) = cfg.verified_manifest_digest.as_ref() {
        verify::verify_local_checksum(&policy, sources, digest, fulcio_and_rekor_data).await?
    }

    let metadata = Metadata::from_path(&policy.local_path)?;

    let policy_id =
        read_policy_title_from_metadata(metadata.as_ref()).unwrap_or_else(|| uri.clone());

    let request = serde_json::from_str::<serde_json::Value>(&cfg.request)?;

    let execution_mode = determine_execution_mode(
        metadata.clone(),
        cfg.user_execution_mode,
        BackendDetector::default(),
        &policy.local_path,
    )?;

    let context_aware_allowed_resources = metadata.as_ref().map_or_else(
        || {
            info!("Policy is not annotated, access to Kubernetes resources is not allowed");
            HashSet::new()
        },
        |m| compute_context_aware_resources(m, cfg),
    );

    let kube_client = if context_aware_allowed_resources.is_empty() {
        None
    } else {
        Client::try_default()
            .await
            .map(Some)
            .map_err(anyhow::Error::new)?
    };

    let policy_settings = cfg.settings.as_ref().map_or(Ok(None), |settings| {
        if settings.is_empty() {
            Ok(None)
        } else {
            serde_yaml::from_str(settings)
        }
    })?;

    // This is a channel used to stop the tokio task that is run
    // inside of the CallbackHandler
    let (callback_handler_shutdown_channel_tx, callback_handler_shutdown_channel_rx) =
        oneshot::channel();

    let mut callback_handler_builder =
        CallbackHandlerBuilder::new(callback_handler_shutdown_channel_rx)
            .registry_config(cfg.sources.clone())
            .fulcio_and_rekor_data(fulcio_and_rekor_data);
    if let Some(kc) = kube_client {
        callback_handler_builder = callback_handler_builder.kube_client(kc);
    }

    let callback_handler = callback_handler_builder.build()?;

    let callback_sender_channel = callback_handler.sender_channel();

    let mut policy_evaluator_builder = PolicyEvaluatorBuilder::new(policy_id)
        .policy_file(&policy.local_path)?
        .execution_mode(execution_mode)
        .settings(policy_settings)
        .callback_channel(callback_sender_channel)
        .context_aware_resources_allowed(context_aware_allowed_resources);
    if cfg.enable_wasmtime_cache {
        policy_evaluator_builder = policy_evaluator_builder.enable_wasmtime_cache();
    }
    let policy_evaluator = policy_evaluator_builder.build()?;

    let req_obj = match request {
        serde_json::Value::Object(ref object) => {
            if object.get("kind").and_then(serde_json::Value::as_str) == Some("AdmissionReview") {
                object
                    .get("request")
                    .cloned()
                    .ok_or_else(|| anyhow!("invalid admission review object"))
            } else {
                Ok(request)
            }
        }
        _ => Err(anyhow!("request to evaluate is invalid")),
    }?;

    Ok(RunEnv {
        policy_evaluator,
        req_obj,
        callback_handler,
        callback_handler_shutdown_channel_tx,
    })
}

pub(crate) async fn pull_and_run(cfg: &PullAndRunSettings) -> Result<()> {
    let run_env = prepare_run_env(cfg).await?;
    let mut policy_evaluator = run_env.policy_evaluator;
    let mut callback_handler = run_env.callback_handler;
    let callback_handler_shutdown_channel_tx = run_env.callback_handler_shutdown_channel_tx;
    let req_obj = run_env.req_obj;

    // validate the settings given by the user
    let settings_validation_response = policy_evaluator.validate_settings();
    if !settings_validation_response.valid {
        println!("{}", serde_json::to_string(&settings_validation_response)?);
        return Err(anyhow!(
            "Provided settings are not valid: {:?}",
            settings_validation_response.message
        ));
    }

    // Spawn the tokio task used by the CallbackHandler
    let callback_handle = tokio::spawn(async move {
        callback_handler.loop_eval().await;
    });

    // evaluate request
    let response = policy_evaluator.validate(ValidateRequest::new(req_obj));
    println!("{}", serde_json::to_string(&response)?);

    // The evaluation is done, we can shutdown the tokio task that is running
    // the CallbackHandler
    if callback_handler_shutdown_channel_tx.send(()).is_err() {
        error!("Cannot shut down the CallbackHandler task");
    } else if let Err(e) = callback_handle.await {
        error!(
            error = e.to_string().as_str(),
            "Error waiting for the CallbackHandler task"
        );
    }

    Ok(())
}

fn read_policy_title_from_metadata(metadata: Option<&Metadata>) -> Option<String> {
    match metadata {
        Some(metadata) => match metadata.annotations {
            Some(ref annotations) => annotations
                .get(KUBEWARDEN_ANNOTATION_POLICY_TITLE)
                .map(Clone::clone),
            None => None,
        },
        None => None,
    }
}

fn determine_execution_mode(
    metadata: Option<Metadata>,
    user_execution_mode: Option<PolicyExecutionMode>,
    backend_detector: BackendDetector,
    wasm_path: &Path,
) -> Result<PolicyExecutionMode> {
    // Desired behaviour, as documented here: https://github.com/kubewarden/kwctl/issues/58
    //
    // When a wasm file is annotated:
    // *  if the user didn't specify a runtime to be used: kwctl will use
    //    this information to pick the right runtime
    // *  if the user specified a runtime to be used: we error out if the
    //    value provided by the user does not match with the one
    //    inside of the wasm metadata
    //
    //When a wasm file is NOT annotated:
    // * If the user didn't specify a runtime to be used:
    //   - We do a quick heuristic to understand if the policy is Rego base:
    //      - If we do not find the OPA ABI constant -> we assume the policy is
    //        a kubewarden one
    //      - If we do find the policy was built using Rego, kwctl exists with
    //        an error because the user has to specify whether this is a OPA
    //        or Gatekeeper policy (that influences how kwctl builds the input and
    //        data variables)
    // * If the user does provide the --runtime-mode flag: we use the runtime
    //   the user specified

    match metadata {
        Some(metadata) => {
            // metadata is set
            match user_execution_mode {
                Some(usermode) => {
                    // metadata AND user execution mode are set
                    if usermode != metadata.execution_mode {
                        Err(anyhow!(
                        "The policy execution mode specified via CLI flag is different from the one reported inside of policy's metadata. Metadata reports {} instead of {}",
                        metadata.execution_mode,
                        usermode)
                    )
                    } else {
                        Ok(metadata.execution_mode)
                    }
                }
                None => {
                    // only metadata is set
                    Ok(metadata.execution_mode)
                }
            }
        }
        None => {
            // metadata is not set
            let is_rego_policy = backend_detector.is_rego_policy(wasm_path)?;
            match user_execution_mode {
                Some(PolicyExecutionMode::Opa) => {
                    if is_rego_policy {
                        Ok(PolicyExecutionMode::Opa)
                    } else {
                        Err(anyhow!("The policy has not been created with Rego, the policy execution mode specified via CLI flag is wrong"))
                    }
                }
                Some(PolicyExecutionMode::OpaGatekeeper) => {
                    if is_rego_policy {
                        Ok(PolicyExecutionMode::OpaGatekeeper)
                    } else {
                        Err(anyhow!("The policy has not been created with Rego, the policy execution mode specified via CLI flag is wrong"))
                    }
                }
                Some(PolicyExecutionMode::KubewardenWapc) => {
                    if !is_rego_policy {
                        Ok(PolicyExecutionMode::KubewardenWapc)
                    } else {
                        Err(anyhow!("The policy has been created with Rego, the policy execution mode specified via CLI flag is wrong"))
                    }
                }
                None => {
                    if is_rego_policy {
                        Err(anyhow!("The policy has been created with Rego, please specify which Opa runtime has to be used"))
                    } else {
                        Ok(PolicyExecutionMode::KubewardenWapc)
                    }
                }
            }
        }
    }
}

fn compute_context_aware_resources(
    metadata: &Metadata,
    cfg: &PullAndRunSettings,
) -> HashSet<ContextAwareResource> {
    if metadata.context_aware_resources.is_empty() {
        return HashSet::new();
    }

    if cfg.allow_context_aware_resources {
        warn!(
            "Policy has been granted access to the Kubernetes resources mentioned by its metadata"
        );
        metadata.context_aware_resources.clone()
    } else {
        warn!("Policy requires access to Kubernetes resources at evaluation time. During this execution the access to Kubernetes resources is denied. This can cause the policy to not behave properly");
        warn!("Carefully review which types of Kubernetes resources the policy needs via the `inspect` command, then run the policy using the `--allow-context-aware` flag.");

        HashSet::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use policy_evaluator::ProtocolVersion;
    use std::path::PathBuf;

    fn mock_protocol_version_detector_v1(_wasm_path: PathBuf) -> Result<ProtocolVersion> {
        Ok(ProtocolVersion::V1)
    }

    fn mock_rego_policy_detector_true(_wasm_path: PathBuf) -> Result<bool> {
        Ok(true)
    }

    fn mock_rego_policy_detector_false(_wasm_path: PathBuf) -> Result<bool> {
        Ok(false)
    }

    #[test]
    fn test_determine_execution_mode_metadata_and_user_mode_are_set_but_have_different_values() {
        let user_execution_mode = Some(PolicyExecutionMode::Opa);
        let metadata = Some(Metadata {
            execution_mode: PolicyExecutionMode::KubewardenWapc,
            ..Default::default()
        });

        let backend_detector = BackendDetector::new(
            mock_rego_policy_detector_true,
            mock_protocol_version_detector_v1,
        );

        let mode = determine_execution_mode(
            metadata,
            user_execution_mode,
            backend_detector,
            &PathBuf::from("irrelevant.wasm"),
        );
        assert!(mode.is_err());
    }

    #[test]
    fn test_determine_execution_mode_metadata_and_user_mode_are_set_and_have_same_value() {
        let user_execution_mode = Some(PolicyExecutionMode::Opa);
        let metadata = Some(Metadata {
            execution_mode: PolicyExecutionMode::Opa,
            ..Default::default()
        });

        let backend_detector = BackendDetector::new(
            mock_rego_policy_detector_true,
            mock_protocol_version_detector_v1,
        );

        let mode = determine_execution_mode(
            metadata,
            user_execution_mode,
            backend_detector,
            &PathBuf::from("irrelevant.wasm"),
        );
        assert!(mode.is_ok());
        assert_eq!(PolicyExecutionMode::Opa, mode.unwrap());
    }

    #[test]
    fn test_determine_execution_mode_metadata_is_set_and_user_mode_is_not_set() {
        let user_execution_mode = None;
        let expected_execution_mode = PolicyExecutionMode::Opa;
        let metadata = Some(Metadata {
            execution_mode: expected_execution_mode,
            ..Default::default()
        });

        let backend_detector = BackendDetector::new(
            mock_rego_policy_detector_true,
            mock_protocol_version_detector_v1,
        );

        let mode = determine_execution_mode(
            metadata,
            user_execution_mode,
            backend_detector,
            &PathBuf::from("irrelevant.wasm"),
        );
        assert!(mode.is_ok());
        assert_eq!(expected_execution_mode, mode.unwrap());
    }

    #[test]
    fn test_determine_execution_mode_metadata_is_not_set_and_user_mode_is_set_but_the_user_value_is_wrong(
    ) {
        for mode in vec![
            PolicyExecutionMode::Opa,
            PolicyExecutionMode::OpaGatekeeper,
            PolicyExecutionMode::KubewardenWapc,
        ] {
            let user_execution_mode = Some(mode.clone());
            let metadata = None;

            let backend_detector = match mode {
                PolicyExecutionMode::Opa => BackendDetector::new(
                    mock_rego_policy_detector_false,
                    mock_protocol_version_detector_v1,
                ),
                PolicyExecutionMode::OpaGatekeeper => BackendDetector::new(
                    mock_rego_policy_detector_false,
                    mock_protocol_version_detector_v1,
                ),
                PolicyExecutionMode::KubewardenWapc => BackendDetector::new(
                    mock_rego_policy_detector_true,
                    mock_protocol_version_detector_v1,
                ),
            };

            let actual = determine_execution_mode(
                metadata,
                user_execution_mode,
                backend_detector,
                &PathBuf::from("irrelevant.wasm").to_path_buf(),
            );
            assert!(
                actual.is_err(),
                "Expected to fail when user specified mode to be {}",
                mode
            );
        }
    }

    #[test]
    fn test_determine_execution_mode_metadata_is_not_set_and_user_mode_is_set_and_the_user_value_is_right(
    ) {
        for mode in vec![
            PolicyExecutionMode::Opa,
            PolicyExecutionMode::OpaGatekeeper,
            PolicyExecutionMode::KubewardenWapc,
        ] {
            let user_execution_mode = Some(mode.clone());
            let metadata = None;

            let backend_detector = match mode {
                PolicyExecutionMode::Opa => BackendDetector::new(
                    mock_rego_policy_detector_true,
                    mock_protocol_version_detector_v1,
                ),
                PolicyExecutionMode::OpaGatekeeper => BackendDetector::new(
                    mock_rego_policy_detector_true,
                    mock_protocol_version_detector_v1,
                ),
                PolicyExecutionMode::KubewardenWapc => BackendDetector::new(
                    mock_rego_policy_detector_false,
                    mock_protocol_version_detector_v1,
                ),
            };

            let actual = determine_execution_mode(
                metadata,
                user_execution_mode,
                backend_detector,
                &PathBuf::from("irrelevant.wasm").to_path_buf(),
            );
            assert!(
                actual.is_ok(),
                "Expected to be ok when user specified mode to be {}",
                mode
            );
            let actual = actual.unwrap();
            assert_eq!(
                actual, mode,
                "Expected to obtain {}, got {} instead",
                mode, actual,
            );
        }
    }

    #[test]
    fn test_determine_execution_mode_metadata_is_not_set_and_user_mode_is_not_set_and_policy_is_rego(
    ) {
        let user_execution_mode = None;
        let metadata = None;

        let backend_detector = BackendDetector::new(
            mock_rego_policy_detector_true,
            mock_protocol_version_detector_v1,
        );

        let actual = determine_execution_mode(
            metadata,
            user_execution_mode,
            backend_detector,
            &PathBuf::from("irrelevant.wasm").to_path_buf(),
        );
        assert!(actual.is_err());
    }

    #[test]
    fn test_determine_execution_mode_metadata_is_not_set_and_user_mode_is_not_set_and_policy_is_not_rego(
    ) {
        let user_execution_mode = None;
        let metadata = None;

        let backend_detector = BackendDetector::new(
            mock_rego_policy_detector_false,
            mock_protocol_version_detector_v1,
        );

        let actual = determine_execution_mode(
            metadata,
            user_execution_mode,
            backend_detector,
            &PathBuf::from("irrelevant.wasm").to_path_buf(),
        );
        assert!(actual.is_ok());
        assert_eq!(actual.unwrap(), PolicyExecutionMode::KubewardenWapc);
    }
}
