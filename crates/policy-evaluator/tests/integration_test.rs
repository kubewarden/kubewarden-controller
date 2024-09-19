#![allow(clippy::too_many_arguments)]
mod common;
mod k8s_mock;

use anyhow::Result;
use core::panic;
use hyper::{Request, Response};
use kube::client::Body;
use kube::Client;
use policy_evaluator::admission_response::PatchType;
use policy_fetcher::oci_client::manifest::OciImageManifest;
use rstest::*;
use serde_json::json;
use std::collections::BTreeSet;
use std::future::Future;
use tokio::sync::mpsc;
use tokio::sync::oneshot;
use tower_test::mock::Handle;

use policy_fetcher::oci_client::manifest::{OciDescriptor, OciManifest};

use policy_evaluator::{
    admission_request::AdmissionRequest,
    admission_response::AdmissionResponseStatus,
    callback_handler::CallbackHandlerBuilder,
    callback_requests::{CallbackRequest, CallbackRequestType, CallbackResponse},
    evaluation_context::EvaluationContext,
    policy_evaluator::PolicySettings,
    policy_evaluator::{PolicyExecutionMode, ValidateRequest},
    policy_metadata::ContextAwareResource,
};

use crate::common::{build_policy_evaluator, fetch_policy, load_request_data};
use crate::k8s_mock::{rego_scenario, wapc_and_wasi_scenario};

async fn setup_callback_handler(
    client: Option<Client>,
) -> (oneshot::Sender<()>, mpsc::Sender<CallbackRequest>) {
    let (callback_handler_shutdown_channel_tx, callback_handler_shutdown_channel_rx) =
        oneshot::channel();
    let mut callback_builder = CallbackHandlerBuilder::new(callback_handler_shutdown_channel_rx);
    if let Some(client) = client {
        callback_builder = callback_builder.kube_client(client);
    }
    let mut callback_handler = callback_builder
        .build()
        .await
        .expect("cannot build callback handler");
    let callback_handler_channel = callback_handler.sender_channel();

    tokio::spawn(async move {
        callback_handler.loop_eval().await;
    });
    (
        callback_handler_shutdown_channel_tx,
        callback_handler_channel,
    )
}

#[rstest]
#[case::wapc(
    PolicyExecutionMode::KubewardenWapc,
    "ghcr.io/kubewarden/tests/pod-privileged:v0.2.1",
    json!({}),
    "pod_with_privileged_containers.json",
    false,
    false,
    Some("Privileged container is not allowed".to_owned()),
    None,
    false
)]
#[case::gatekeeper(
    PolicyExecutionMode::OpaGatekeeper,
    "ghcr.io/kubewarden/tests/disallow-service-loadbalancer:v0.1.5",
    json!({}),
    "service_loadbalancer.json",
    false,
    false,
    Some("Service of type LoadBalancer are not allowed".to_owned()),
    None,
    false
)]
#[case::wasi(
    PolicyExecutionMode::Wasi,
    "ghcr.io/kubewarden/tests/go-wasi-template:v0.1.0",
    json!({
        "requiredAnnotations": {
            "fluxcd.io/cat": "felix"
        }
    }),
    "pod_creation_flux_cat.json",
    false,
    true,
    None,
    None,
    false
)]
#[case::wasi_mutating(
    PolicyExecutionMode::Wasi,
    "ghcr.io/kubewarden/tests/go-wasi-template:v0.1.0",
    json!({
        "requiredAnnotations": {
            "fluxcd.io/cat": "felix"
        }
    }),
    "service_clusterip.json",
    false,
    true,
    None,
    None,
    true
)]
#[case::wapc_raw(
    PolicyExecutionMode::KubewardenWapc,
    "ghcr.io/kubewarden/tests/raw-validation-policy:v0.1.0",
    json!({
        "validUsers": ["tonio", "wanda"],
        "validActions": ["eats", "likes"],
        "validResources": ["banana", "hay"],
    }),
    "raw_validation.json",
    true,
    true,
    None,
    None,
    false
)]
#[case::wapc_raw_mutating(
    PolicyExecutionMode::KubewardenWapc,
    "ghcr.io/kubewarden/tests/raw-mutation-policy:v0.1.0",
    json!({
        "forbiddenResources": ["banana", "carrot"],
        "defaultResource": "hay",
    }),
    "raw_mutation.json",
    true,
    true,
    None,
    None,
    true
)]
#[case::opa_raw(
    PolicyExecutionMode::Opa,
    "ghcr.io/kubewarden/tests/raw-validation-opa-policy:v0.1.0",
    json!({}),
    "raw_validation.json",
    true,
    true,
    None,
    None,
    false
)]
#[case::wasi_raw(
    PolicyExecutionMode::Wasi,
    "ghcr.io/kubewarden/tests/raw-validation-wasi-policy:v0.1.0",
    json!({
        "validUsers": ["tonio", "wanda"],
        "validActions": ["eats", "likes"],
        "validResources": ["banana", "hay"],
    }),
    "raw_validation.json",
    true,
    true,
    None,
    None,
    false
)]
#[case::wasi_raw_mutating(
    PolicyExecutionMode::Wasi,
    "ghcr.io/kubewarden/tests/raw-mutation-wasi-policy:v0.1.0",
    json!({
        "forbiddenResources": ["banana", "carrot"],
        "defaultResource": "hay",
    }),
    "raw_mutation.json",
    true,
    true,
    None,
    None,
    true
)]
#[tokio::test]
async fn test_policy_evaluator(
    #[case] execution_mode: PolicyExecutionMode,
    #[case] policy_uri: &str,
    #[case] settings: serde_json::Value,
    #[case] request_file_path: &str,
    #[case] raw: bool,
    #[case] allowed: bool,
    #[case] message: Option<String>,
    #[case] code: Option<u16>,
    #[case] mutating: bool,
) {
    let tempdir = tempfile::TempDir::new().expect("cannot create tempdir");
    let policy = fetch_policy(policy_uri, tempdir).await;

    let eval_ctx = EvaluationContext {
        policy_id: "test".to_owned(),
        callback_channel: None,
        ctx_aware_resources_allow_list: Default::default(),
    };

    let mut policy_evaluator = build_policy_evaluator(execution_mode, &policy, &eval_ctx);

    let request_data = load_request_data(request_file_path);
    let request_json = serde_json::from_slice(&request_data).expect("cannot deserialize request");

    let validation_request = if raw {
        ValidateRequest::Raw(request_json)
    } else {
        let admission_request: AdmissionRequest =
            serde_json::from_value(request_json).expect("cannot deserialize admission request");
        ValidateRequest::AdmissionRequest(admission_request)
    };

    let serde_json::Value::Object(settings) = settings else {
        panic!("settings must be an object")
    };
    let settings_validation_response = policy_evaluator.validate_settings(&settings);
    assert!(settings_validation_response.valid);

    let admission_response = policy_evaluator.validate(validation_request, &settings);

    assert_eq!(allowed, admission_response.allowed);
    if allowed {
        assert!(admission_response.status.is_none());
    } else {
        assert_eq!(
            Some(AdmissionResponseStatus {
                message,
                code,
                ..Default::default()
            }),
            admission_response.status
        );
    }

    if mutating {
        assert_eq!(Some(PatchType::JSONPatch), admission_response.patch_type);
        assert!(admission_response.patch.is_some());
    } else {
        assert!(admission_response.patch.is_none());
    }
}

#[test_log::test(rstest)]
#[case::wasi(
    PolicyExecutionMode::Wasi,
    "ghcr.io/kubewarden/tests/go-wasi-context-aware-test-policy:latest",
    "app_deployment.json",
    wapc_and_wasi_scenario
)]
#[case::wapc(
    PolicyExecutionMode::KubewardenWapc,
    "ghcr.io/kubewarden/tests/context-aware-test-policy:v0.1.0",
    "app_deployment.json",
    wapc_and_wasi_scenario
)]
#[case::opa(
    PolicyExecutionMode::Opa,
    "ghcr.io/kubewarden/tests/context-aware-test-opa-policy:v0.1.0",
    "app_deployment.json",
    rego_scenario
)]
#[case::gatekeeper(
    PolicyExecutionMode::OpaGatekeeper,
    "ghcr.io/kubewarden/tests/context-aware-test-gatekeeper-policy:v0.1.0",
    "app_deployment.json",
    rego_scenario
)]
#[tokio::test(flavor = "multi_thread")]
async fn test_runtime_context_aware<F, Fut>(
    #[case] execution_mode: PolicyExecutionMode,
    #[case] policy_uri: &str,
    #[case] request_file_path: &str,
    #[case] scenario: F,
) where
    F: FnOnce(Handle<Request<Body>, Response<Body>>) -> Fut,
    Fut: Future<Output = ()>,
{
    use kube::client::Body;

    let tempdir = tempfile::TempDir::new().expect("cannot create tempdir");
    let policy = fetch_policy(policy_uri, tempdir).await;

    let (mocksvc, handle) = tower_test::mock::pair::<Request<Body>, Response<Body>>();
    let client = Client::new(mocksvc, "default");
    scenario(handle).await;

    let (callback_handler_shutdown_channel_tx, callback_handler_channel) =
        setup_callback_handler(Some(client)).await;

    let eval_ctx = EvaluationContext {
        policy_id: "test".to_owned(),
        callback_channel: Some(callback_handler_channel),
        ctx_aware_resources_allow_list: BTreeSet::from([
            ContextAwareResource {
                api_version: "v1".to_owned(),
                kind: "Namespace".to_owned(),
            },
            ContextAwareResource {
                api_version: "apps/v1".to_owned(),
                kind: "Deployment".to_owned(),
            },
            ContextAwareResource {
                api_version: "v1".to_owned(),
                kind: "Service".to_owned(),
            },
        ]),
    };

    let request_data = load_request_data(request_file_path);
    let request: AdmissionRequest =
        serde_json::from_slice(&request_data).expect("cannot deserialize request");

    tokio::task::spawn_blocking(move || {
        let mut policy_evaluator = build_policy_evaluator(execution_mode, &policy, &eval_ctx);
        let admission_response = policy_evaluator.validate(
            ValidateRequest::AdmissionRequest(request),
            &PolicySettings::default(),
        );

        assert!(admission_response.allowed, "the admission request should have been accepted, it has been rejected with this details: {:?}", admission_response);
    }).await.unwrap();

    callback_handler_shutdown_channel_tx
        .send(())
        .expect("cannot send shutdown signal");
}

#[rstest]
#[case::policy(
    "ghcr.io/kubewarden/tests/context-aware-test-policy:latest",
    OciManifest::Image(Default::default())
)]
#[case::container_image("ghcr.io/kubewarden/policy-server:latest", OciManifest::ImageIndex(policy_fetcher::oci_client::manifest::OciImageIndex { schema_version:2, media_type: None, manifests: vec![], annotations: None }))]
#[tokio::test(flavor = "multi_thread")]
async fn test_oci_manifest_capability(
    #[case] policy_uri: &str,
    #[case] expected_manifest_type: OciManifest,
) {
    let (callback_handler_shutdown_channel_tx, callback_handler_channel) =
        setup_callback_handler(None).await;
    let (tx, rx) = oneshot::channel::<Result<CallbackResponse>>();
    let req = CallbackRequest {
        request: CallbackRequestType::OciManifest {
            image: policy_uri.to_owned(),
        },
        response_channel: tx,
    };

    let eval_ctx = EvaluationContext {
        policy_id: "test".to_owned(),
        callback_channel: Some(callback_handler_channel),
        ctx_aware_resources_allow_list: Default::default(),
    };

    let cb_channel: mpsc::Sender<CallbackRequest> = eval_ctx
        .callback_channel
        .clone()
        .expect("missing callback channel");
    assert!(cb_channel.try_send(req).is_ok());

    // wait for the response
    let response_raw = rx
        .await
        .expect("cannot receive response")
        .expect("cannot get response");
    let response: OciManifest = serde_json::from_slice(&response_raw.payload).unwrap();
    match (response, expected_manifest_type) {
        (OciManifest::Image { .. }, OciManifest::ImageIndex { .. }) => {
            panic!("Image index manifest expected. But got a single image manifest")
        }
        (OciManifest::ImageIndex { .. }, OciManifest::Image { .. }) => {
            panic!("Image manifest expected. But got a image index manifest")
        }
        _ => {}
    }
    callback_handler_shutdown_channel_tx
        .send(())
        .expect("cannot send shutdown signal");
}

#[rstest]
#[case::container_image("ghcr.io/kubewarden/tests/policy-server:v1.13.0", 
    policy_fetcher::oci_client::manifest::OciImageManifest {
        schema_version:2,
        media_type: Some("application/vnd.docker.distribution.manifest.v2+json".to_owned()),
        annotations: None,
        artifact_type:None,
        config: OciDescriptor{
            media_type:  "application/vnd.docker.container.image.v1+json".to_owned(),
            size: 1592,
            digest: "sha256:bc3511804cb29da6333f0187a333eba13a43a3a0a1737e9b50227a5cf057af74".to_owned(),
            annotations: None,
            urls: None,
        },
    layers: vec![]}, Some(serde_json::json!({
    "User": "65533:65533",
    "ExposedPorts": {
      "3000/tcp": {}
    },
    "Env": [
      "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
    ],
    "Entrypoint": [
      "/policy-server"
    ],
    "WorkingDir": "/"})))]
#[case::policy(
    "ghcr.io/kubewarden/tests/context-aware-test-policy:latest",
    policy_fetcher::oci_client::manifest::OciImageManifest {
        schema_version:2,
        media_type: None, annotations: None, artifact_type:None,
        config: OciDescriptor{
            media_type:  "application/vnd.wasm.config.v1+json".to_owned(),
            size: 2,
            digest: "sha256:44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a".to_owned(),
            annotations: None, urls: None,
        },
    layers: vec![]},
    None
)]
#[tokio::test(flavor = "multi_thread")]
async fn test_oci_manifest_and_config_capability(
    #[case] policy_uri: &str,
    #[case] expected_manifest: OciImageManifest,
    #[case] expected_config: Option<serde_json::Value>,
) {
    let (callback_handler_shutdown_channel_tx, callback_handler_channel) =
        setup_callback_handler(None).await;

    let (tx, rx) = oneshot::channel::<Result<CallbackResponse>>();
    let req = CallbackRequest {
        request: CallbackRequestType::OciManifestAndConfig {
            image: policy_uri.to_owned(),
        },
        response_channel: tx,
    };

    let eval_ctx = EvaluationContext {
        policy_id: "test".to_owned(),
        callback_channel: Some(callback_handler_channel),
        ctx_aware_resources_allow_list: Default::default(),
    };

    let cb_channel: mpsc::Sender<CallbackRequest> = eval_ctx
        .callback_channel
        .clone()
        .expect("missing callback channel");
    assert!(cb_channel.try_send(req).is_ok());

    // wait for the response
    let response_raw = rx
        .await
        .expect("cannot receive response")
        .expect("cannot get response");
    let response: serde_json::Value = serde_json::from_slice(&response_raw.payload).unwrap();
    if let Some(expected_config_json) = expected_config {
        assert!(response
            .get("config")
            .unwrap()
            .get("config")
            .unwrap()
            .eq(&expected_config_json));
    } else {
        assert!(response
            .get("config")
            .unwrap()
            .as_object()
            .unwrap()
            .is_empty());
    }
    let manifest: OciImageManifest =
        serde_json::from_value(response.get("manifest").unwrap().clone())
            .expect("cannot deserialize manifest");
    // The OciImageManifest does not implement the Eq trait. Therefore, we need to
    // compare the fields one by one. Thus, let's checks some of them only. We do not
    // need to validate all of them here.
    assert_eq!(manifest.media_type, expected_manifest.media_type);
    assert_eq!(manifest.schema_version, expected_manifest.schema_version);
    assert_eq!(
        manifest.config.to_string(),
        expected_manifest.config.to_string()
    );
    callback_handler_shutdown_channel_tx
        .send(())
        .expect("cannot send shutdown signal");
}
