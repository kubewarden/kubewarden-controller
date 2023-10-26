use anyhow::{anyhow, Result};
use policy_evaluator::admission_request::AdmissionRequest;
use policy_evaluator::kube;
use policy_evaluator::{
    constants::*,
    policy_evaluator::{Evaluator, PolicyEvaluator},
    policy_evaluator::{PolicyExecutionMode, ValidateRequest},
    policy_evaluator_builder::PolicyEvaluatorBuilder,
    policy_fetcher::{sources::Sources, verify::FulcioAndRekorData, PullDestination},
    policy_metadata::{ContextAwareResource, Metadata, PolicyType},
};
use std::{
    collections::HashSet,
    net::{Ipv4Addr, Ipv6Addr},
    path::Path,
};
use tokio::sync::oneshot;
use tracing::{error, info, warn};

use crate::{
    backend::has_minimum_kubewarden_version,
    backend::BackendDetector,
    callback_handler::{CallbackHandler, ProxyMode},
    pull, verify,
};

#[derive(Default)]
pub(crate) enum HostCapabilitiesMode {
    #[default]
    Direct,
    Proxy(crate::callback_handler::ProxyMode),
}

#[derive(Default)]
pub(crate) struct PullAndRunSettings {
    pub uri: String,
    pub user_execution_mode: Option<PolicyExecutionMode>,
    pub sources: Option<Sources>,
    pub request: String,
    pub raw: bool,
    pub settings: Option<String>,
    pub verified_manifest_digest: Option<String>,
    pub fulcio_and_rekor_data: Option<FulcioAndRekorData>,
    pub enable_wasmtime_cache: bool,
    pub allow_context_aware_resources: bool,
    pub host_capabilities_mode: HostCapabilitiesMode,
}

pub(crate) struct RunEnv {
    pub policy_evaluator: PolicyEvaluator,
    pub request: ValidateRequest,
    pub callback_handler: CallbackHandler,
    pub callback_handler_shutdown_channel_tx: oneshot::Sender<()>,
}

pub(crate) async fn prepare_run_env(cfg: &PullAndRunSettings) -> Result<RunEnv> {
    let sources = cfg.sources.as_ref();
    let fulcio_and_rekor_data = cfg.fulcio_and_rekor_data.as_ref();

    let policy = pull::pull(&cfg.uri, sources, PullDestination::MainStore)
        .await
        .map_err(|e| anyhow!("error pulling policy {}: {}", &cfg.uri, e))?;

    if let Some(digest) = cfg.verified_manifest_digest.as_ref() {
        verify::verify_local_checksum(&policy, sources, digest, fulcio_and_rekor_data).await?
    }

    let metadata = Metadata::from_path(&policy.local_path)?;
    has_minimum_kubewarden_version(metadata.as_ref())?;

    let policy_id =
        read_policy_title_from_metadata(metadata.as_ref()).unwrap_or_else(|| cfg.uri.clone());

    let req_obj = serde_json::from_str::<serde_json::Value>(&cfg.request)?;

    let execution_mode = determine_execution_mode(
        metadata.clone(),
        cfg.user_execution_mode,
        BackendDetector::default(),
        &policy.local_path,
    )?;

    let context_aware_allowed_resources = compute_context_aware_resources(metadata.as_ref(), cfg);

    let kube_client = if context_aware_allowed_resources.is_empty() {
        None
    } else {
        match &cfg.host_capabilities_mode {
            HostCapabilitiesMode::Proxy(ProxyMode::Replay { source: _ }) => None,
            _ => Some(build_kube_client().await?),
        }
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

    let callback_handler =
        CallbackHandler::new(cfg, kube_client, callback_handler_shutdown_channel_rx).await?;

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

    let request = if cfg.raw || has_raw_policy_type(metadata.as_ref()) {
        ValidateRequest::Raw(req_obj)
    } else {
        let req_obj = match req_obj.clone() {
            serde_json::Value::Object(object) => {
                if object.get("kind").and_then(serde_json::Value::as_str) == Some("AdmissionReview")
                {
                    object
                        .get("request")
                        .cloned()
                        .ok_or_else(|| anyhow!("invalid admission review object"))
                } else {
                    Ok(req_obj)
                }
            }
            _ => Err(anyhow!("request to evaluate is invalid")),
        }?;
        let adm_req: AdmissionRequest = serde_json::from_value(req_obj)?;
        ValidateRequest::AdmissionRequest(adm_req)
    };

    Ok(RunEnv {
        policy_evaluator,
        request,
        callback_handler,
        callback_handler_shutdown_channel_tx,
    })
}

pub(crate) async fn pull_and_run(cfg: &PullAndRunSettings) -> Result<()> {
    let run_env = prepare_run_env(cfg).await?;
    let mut policy_evaluator = run_env.policy_evaluator;
    let mut callback_handler = run_env.callback_handler;
    let callback_handler_shutdown_channel_tx = run_env.callback_handler_shutdown_channel_tx;

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
    let response = policy_evaluator.validate(run_env.request);
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
                Some(PolicyExecutionMode::Wasi) => Ok(PolicyExecutionMode::Wasi),
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

fn has_raw_policy_type(metadata: Option<&Metadata>) -> bool {
    if let Some(metadata) = metadata {
        metadata.policy_type == PolicyType::Raw
    } else {
        false
    }
}

fn compute_context_aware_resources(
    metadata: Option<&Metadata>,
    cfg: &PullAndRunSettings,
) -> HashSet<ContextAwareResource> {
    match metadata {
        None => {
            info!("Policy is not annotated, access to Kubernetes resources is not allowed");
            HashSet::new()
        }
        Some(metadata) => {
            if metadata.context_aware_resources.is_empty() {
                return HashSet::new();
            }

            if cfg.allow_context_aware_resources {
                warn!("Policy has been granted access to the Kubernetes resources mentioned by its metadata");
                metadata.context_aware_resources.clone()
            } else {
                warn!("Policy requires access to Kubernetes resources at evaluation time. During this execution the access to Kubernetes resources is denied. This can cause the policy to not behave properly");
                warn!("Carefully review which types of Kubernetes resources the policy needs via the `inspect` command, then run the policy using the `--allow-context-aware` flag.");

                HashSet::new()
            }
        }
    }
}

/// kwctl is built using rustls enabled. Unfortunately rustls does not support validating IP addresses
/// yet (see https://github.com/kube-rs/kube/issues/1003).
///
/// This function provides a workaround to this limitation.
async fn build_kube_client() -> Result<kube::Client> {
    // This is the usual way of obtaining a kubeconfig
    let mut kube_config = kube::Config::infer().await.map_err(anyhow::Error::new)?;

    // Does the cluster_url have an host? This is probably true 99.999% of the times
    if let Some(host) = kube_config.cluster_url.host() {
        // is the host an IP or a hostname?
        let is_an_ip = host.parse::<Ipv4Addr>().is_ok() || host.parse::<Ipv6Addr>().is_ok();

        // if the host is an IP and no `tls_server_name` is set, then
        // set `tls_server_name` to `kubernetes.default.svc`. This is a FQDN
        // that is always associated to the certificate used by the API server.
        // This will make kwctl work against minikube and k3d, to name a few...
        if is_an_ip && kube_config.tls_server_name.is_none() {
            warn!(host, "The loaded kubeconfig connects to a server using an IP address instead of a FQDN. This is usually done by minikube, k3d and other local development solutions");
            warn!("Due to a limitation of rustls, certificate validation cannot be performed against IP addresses, the certificate validation will be made against `kubernetes.default.svc`");
            kube_config.tls_server_name = Some("kubernetes.default.svc".to_string());
        }
    }

    kube::Client::try_from(kube_config).map_err(anyhow::Error::new)
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
        for mode in [
            PolicyExecutionMode::Opa,
            PolicyExecutionMode::OpaGatekeeper,
            PolicyExecutionMode::KubewardenWapc,
        ] {
            let user_execution_mode = Some(mode);
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
                PolicyExecutionMode::Wasi => BackendDetector::new(
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
                actual.is_err(),
                "Expected to fail when user specified mode to be {}",
                mode
            );
        }
    }

    #[test]
    fn test_determine_execution_mode_metadata_is_not_set_and_user_mode_is_set_and_the_user_value_is_right(
    ) {
        for mode in [
            PolicyExecutionMode::Opa,
            PolicyExecutionMode::OpaGatekeeper,
            PolicyExecutionMode::KubewardenWapc,
        ] {
            let user_execution_mode = Some(mode);
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
                PolicyExecutionMode::Wasi => BackendDetector::new(
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

    #[test]
    fn prevent_access_to_kubernetes_resources_when_policy_is_not_annotated() {
        let cfg = PullAndRunSettings {
            allow_context_aware_resources: true,
            ..Default::default()
        };

        let resources = compute_context_aware_resources(None, &cfg);
        assert!(resources.is_empty());
    }

    #[test]
    fn prevent_access_to_kubernetes_resources_when_allow_context_aware_resources_is_disabled() {
        let mut context_aware_resources = HashSet::new();
        context_aware_resources.insert(ContextAwareResource {
            api_version: "v1".to_string(),
            kind: "Pod".to_string(),
        });

        let metadata = Metadata {
            context_aware_resources,
            ..Default::default()
        };

        let cfg = PullAndRunSettings {
            allow_context_aware_resources: false,
            ..Default::default()
        };

        let resources = compute_context_aware_resources(Some(&metadata), &cfg);
        assert!(resources.is_empty());
    }

    #[test]
    fn allow_access_to_kubernetes_resources_when_allow_context_aware_resources_is_enabled() {
        let mut context_aware_resources = HashSet::new();
        context_aware_resources.insert(ContextAwareResource {
            api_version: "v1".to_string(),
            kind: "Pod".to_string(),
        });

        let metadata = Metadata {
            context_aware_resources: context_aware_resources.clone(),
            ..Default::default()
        };

        let cfg = PullAndRunSettings {
            allow_context_aware_resources: true,
            ..Default::default()
        };

        let resources = compute_context_aware_resources(Some(&metadata), &cfg);
        assert_eq!(resources, context_aware_resources);
    }
}
