#![allow(clippy::too_many_arguments)]

use rstest::*;
use serde_json::json;

use policy_evaluator::{
    admission_request::AdmissionRequest,
    admission_response::AdmissionResponseStatus,
    evaluation_context::EvaluationContext,
    policy_evaluator::{PolicyExecutionMode, ValidateRequest},
    policy_evaluator_builder::PolicyEvaluatorBuilder,
};
use policy_fetcher::PullDestination;

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
    let policy = policy_evaluator::policy_fetcher::fetch_policy(
        policy_uri,
        PullDestination::LocalFile(tempdir.into_path()),
        None,
    )
    .await
    .expect("cannot fetch policy");

    let eval_ctx = EvaluationContext {
        policy_id: "test".to_string(),
        callback_channel: None,
        ctx_aware_resources_allow_list: Default::default(),
    };

    let policy_evaluator_builder = PolicyEvaluatorBuilder::new()
        .execution_mode(execution_mode)
        .policy_file(&policy.local_path)
        .expect("cannot read policy file")
        .enable_wasmtime_cache()
        .enable_epoch_interruptions(1, 2);

    let policy_evaluator_pre = policy_evaluator_builder
        .build_pre()
        .expect("cannot build policy evaluator pre");
    let mut policy_evaluator = policy_evaluator_pre
        .rehydrate(&eval_ctx)
        .expect("cannot rehydrate policy evaluator");

    let request_file_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/data")
        .join(request_file_path);
    let request_data = std::fs::read(request_file_path).expect("cannot read request file");
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
            Some(AdmissionResponseStatus { message, code }),
            admission_response.status
        );
    }

    if mutating {
        assert_eq!(Some("JSONPatch".to_owned()), admission_response.patch_type);
        assert!(admission_response.patch.is_some());
    } else {
        assert!(admission_response.patch.is_none());
    }
}
