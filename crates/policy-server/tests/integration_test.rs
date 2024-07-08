mod common;

use std::collections::{BTreeSet, HashMap};

use common::app;

use axum::{
    body::Body,
    http::{self, header, Request},
};
use http_body_util::BodyExt;
use policy_evaluator::{
    admission_response::AdmissionResponseStatus,
    policy_fetcher::verify::config::VerificationConfigV1,
};
use policy_server::{
    api::admission_review::AdmissionReviewResponse,
    config::{PolicyMode, PolicyOrPolicyGroup},
};
use regex::Regex;
use rstest::*;
use tower::ServiceExt;

use crate::common::default_test_config;

#[tokio::test]
async fn test_validate() {
    let config = default_test_config();
    let app = app(config).await;

    let request = Request::builder()
        .method(http::Method::POST)
        .header(header::CONTENT_TYPE, "application/json")
        .uri("/validate/pod-privileged")
        .body(Body::from(include_str!(
            "data/pod_with_privileged_containers.json"
        )))
        .unwrap();

    let response = app.oneshot(request).await.unwrap();

    assert_eq!(response.status(), 200);

    let admission_review_response: AdmissionReviewResponse =
        serde_json::from_slice(&response.into_body().collect().await.unwrap().to_bytes()).unwrap();

    assert!(!admission_review_response.response.allowed);
    assert_eq!(
        admission_review_response.response.status,
        Some(
            policy_evaluator::admission_response::AdmissionResponseStatus {
                message: Some("Privileged container is not allowed".to_owned()),
                code: None
            }
        )
    )
}

#[tokio::test]
#[rstest]
#[case::pod_with_privileged_containers(
    include_str!("data/pod_with_privileged_containers.json"),
    false,
)]
#[case::pod_without_privileged_containers(
    include_str!("data/pod_without_privileged_containers.json"),
    true,
)]
async fn test_validate_policy_group(#[case] payload: &str, #[case] expected_allowed: bool) {
    let config = default_test_config();
    let app = app(config).await;

    let request = Request::builder()
        .method(http::Method::POST)
        .header(header::CONTENT_TYPE, "application/json")
        .uri("/validate/group-policy-just-pod-privileged")
        .body(Body::from(payload.to_owned()))
        .unwrap();

    let response = app.oneshot(request).await.unwrap();

    assert_eq!(response.status(), 200);

    let admission_review_response: AdmissionReviewResponse =
        serde_json::from_slice(&response.into_body().collect().await.unwrap().to_bytes()).unwrap();

    assert_eq!(expected_allowed, admission_review_response.response.allowed);

    if expected_allowed {
        assert_eq!(admission_review_response.response.status, None);
    } else {
        assert_eq!(
            admission_review_response.response.status,
            Some(
                policy_evaluator::admission_response::AdmissionResponseStatus {
                    message: Some("The group policy rejected your request".to_owned()),
                    code: None
                }
            )
        );
    }

    let warning_messages = &admission_review_response
        .response
        .warnings
        .expect("warning messages should always be filled by policy groups");
    assert_eq!(1, warning_messages.len());

    let warning_msg = &warning_messages[0];
    if expected_allowed {
        assert!(warning_msg.contains("ALLOWED"));
    } else {
        assert!(warning_msg.contains("DENIED"));
        assert!(warning_msg.contains("Privileged container is not allowed"));
    }
}

#[tokio::test]
async fn test_validate_policy_not_found() {
    let config = default_test_config();
    let app = app(config).await;

    let request = Request::builder()
        .method(http::Method::POST)
        .header(header::CONTENT_TYPE, "application/json")
        .uri("/validate/does_not_exist")
        .body(Body::from(include_str!(
            "data/pod_with_privileged_containers.json"
        )))
        .unwrap();

    let response = app.oneshot(request).await.unwrap();

    assert_eq!(response.status(), 404);
}

#[tokio::test]
async fn test_validate_invalid_payload() {
    let config = default_test_config();
    let app = app(config).await;

    let request = Request::builder()
        .method(http::Method::POST)
        .header(header::CONTENT_TYPE, "application/json")
        .uri("/validate/pod-privileged")
        .body(Body::from("{}"))
        .unwrap();

    let response = app.oneshot(request).await.unwrap();

    assert_eq!(response.status(), 422);
}

#[tokio::test]
async fn test_validate_raw() {
    let config = default_test_config();
    let app = app(config).await;

    let request = Request::builder()
        .method(http::Method::POST)
        .header(header::CONTENT_TYPE, "application/json")
        .uri("/validate_raw/raw-mutation")
        .body(Body::from(include_str!("data/raw_review.json")))
        .unwrap();

    let response = app.oneshot(request).await.unwrap();

    assert_eq!(response.status(), 200);

    let admission_review_response: AdmissionReviewResponse =
        serde_json::from_slice(&response.into_body().collect().await.unwrap().to_bytes()).unwrap();

    assert!(admission_review_response.response.allowed);
    assert_eq!(admission_review_response.response.status, None);
    assert!(admission_review_response.response.patch.is_some());
    assert_eq!(
        Some("JSONPatch".to_owned()),
        admission_review_response.response.patch_type
    );
}

#[tokio::test]
async fn test_validate_policy_group_does_not_do_mutation() {
    let config = default_test_config();
    let app = app(config).await;

    let request = Request::builder()
        .method(http::Method::POST)
        .header(header::CONTENT_TYPE, "application/json")
        .uri("/validate_raw/group-policy-just-raw-mutation")
        .body(Body::from(include_str!("data/raw_review.json")))
        .unwrap();

    let response = app.oneshot(request).await.unwrap();

    assert_eq!(response.status(), 200);

    let admission_review_response: AdmissionReviewResponse =
        serde_json::from_slice(&response.into_body().collect().await.unwrap().to_bytes()).unwrap();

    assert!(!admission_review_response.response.allowed);
    assert_eq!(
        admission_review_response.response.status,
        Some(
            policy_evaluator::admission_response::AdmissionResponseStatus {
                message: Some("The group policy rejected your request".to_owned()),
                code: None
            }
        )
    );
    assert!(admission_review_response.response.patch.is_none());

    let warning_messages = &admission_review_response
        .response
        .warnings
        .expect("warning messages should always be filled by policy groups");
    assert_eq!(1, warning_messages.len());
    let warning_msg = &warning_messages[0];
    assert!(warning_msg.contains("DENIED"));
    assert!(warning_msg.contains("mutation is not allowed inside of policy group"));
}

#[tokio::test]
async fn test_validate_raw_policy_not_found() {
    let config = default_test_config();
    let app = app(config).await;

    let request = Request::builder()
        .method(http::Method::POST)
        .header(header::CONTENT_TYPE, "application/json")
        .uri("/validate_raw/does_not_exist")
        .body(Body::from(include_str!(
            "data/pod_with_privileged_containers.json"
        )))
        .unwrap();

    let response = app.oneshot(request).await.unwrap();

    assert_eq!(response.status(), 404);
}

#[tokio::test]
async fn test_validate_raw_invalid_payload() {
    let config = default_test_config();
    let app = app(config).await;

    let request = Request::builder()
        .method(http::Method::POST)
        .header(header::CONTENT_TYPE, "application/json")
        .uri("/validate_raw/raw-mutation")
        .body(Body::from("{}"))
        .unwrap();

    let response = app.oneshot(request).await.unwrap();

    assert_eq!(response.status(), 422);
}

#[tokio::test]
async fn test_audit() {
    let config = default_test_config();
    let app = app(config).await;

    let request = Request::builder()
        .method(http::Method::POST)
        .header(header::CONTENT_TYPE, "application/json")
        .uri("/audit/pod-privileged")
        .body(Body::from(include_str!(
            "data/pod_with_privileged_containers.json"
        )))
        .unwrap();

    let response = app.oneshot(request).await.unwrap();

    assert_eq!(response.status(), 200);

    let admission_review_response: AdmissionReviewResponse =
        serde_json::from_slice(&response.into_body().collect().await.unwrap().to_bytes()).unwrap();

    assert!(!admission_review_response.response.allowed);
    assert_eq!(
        admission_review_response.response.status,
        Some(AdmissionResponseStatus {
            message: Some("Privileged container is not allowed".to_owned()),
            code: None
        })
    );
}

#[tokio::test]
async fn test_audit_policy_not_found() {
    let config = default_test_config();
    let app = app(config).await;

    let request = Request::builder()
        .method(http::Method::POST)
        .header(header::CONTENT_TYPE, "application/json")
        .uri("/audit/does_not_exist")
        .body(Body::from(include_str!(
            "data/pod_with_privileged_containers.json"
        )))
        .unwrap();

    let response = app.oneshot(request).await.unwrap();

    assert_eq!(response.status(), 404);
}

#[tokio::test]
async fn test_audit_invalid_payload() {
    let config = default_test_config();
    let app = app(config).await;

    let request = Request::builder()
        .method(http::Method::POST)
        .header(header::CONTENT_TYPE, "application/json")
        .uri("/audit/pod-privileged")
        .body(Body::from("{}"))
        .unwrap();

    let response = app.oneshot(request).await.unwrap();

    assert_eq!(response.status(), 422);
}

#[tokio::test]
async fn test_timeout_protection_accept() {
    let config = default_test_config();
    let app = app(config).await;

    let request = Request::builder()
        .method(http::Method::POST)
        .header(header::CONTENT_TYPE, "application/json")
        .uri("/validate/sleep")
        .body(Body::from(include_str!("data/pod_sleep_100ms.json")))
        .unwrap();

    let response = app.oneshot(request).await.unwrap();

    assert_eq!(response.status(), 200);

    let admission_review_response: AdmissionReviewResponse =
        serde_json::from_slice(&response.into_body().collect().await.unwrap().to_bytes()).unwrap();

    assert!(admission_review_response.response.allowed);
}

#[tokio::test]
async fn test_timeout_protection_reject() {
    let config = default_test_config();
    let app = app(config).await;

    let request = Request::builder()
        .method(http::Method::POST)
        .header(header::CONTENT_TYPE, "application/json")
        .uri("/validate/sleep")
        .body(Body::from(include_str!("data/pod_sleep_4s.json")))
        .unwrap();

    let response = app.oneshot(request).await.unwrap();

    assert_eq!(response.status(), 200);

    let admission_review_response: AdmissionReviewResponse =
        serde_json::from_slice(&response.into_body().collect().await.unwrap().to_bytes()).unwrap();

    assert!(!admission_review_response.response.allowed);
    assert_eq!(
        admission_review_response.response.status,
        Some(
            AdmissionResponseStatus {
                message: Some("internal server error: Guest call failure: guest code interrupted, execution deadline exceeded".to_owned()),
                code: Some(500)
            }
        )
    );
}

#[tokio::test]
async fn test_verified_policy() {
    let verification_cfg_yml = r#"---
    allOf:
      - kind: pubKey
        owner: pubkey1.pub
        key: |
              -----BEGIN PUBLIC KEY-----
              MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEQiTy5S+2JFvVlhUwWPLziM7iTM2j
              byLgh2IjpNQN0Uio/9pZOTP/CsJmXoUNshfpTUHd3OxgHgz/6adtf2nBwQ==
              -----END PUBLIC KEY-----
        annotations:
          env: prod
          stable: "true"
      - kind: pubKey
        owner: pubkey2.pub
        key: |
              -----BEGIN PUBLIC KEY-----
              MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEx0HuqSss8DUIIUg3I006b1EQjj3Q
              igsTrvZ/Q3+h+81DkNJg4LzID1rz0UJFUcdzI5NqlFLSTDIQw0gVKOiK7g==
              -----END PUBLIC KEY-----
        annotations:
          env: prod
        "#;
    let verification_config = serde_yaml::from_str::<VerificationConfigV1>(verification_cfg_yml)
        .expect("Cannot parse verification config");

    let mut config = default_test_config();
    config.policies = HashMap::from([(
        "pod-privileged".to_owned(),
        PolicyOrPolicyGroup::Policy {
            url: "ghcr.io/kubewarden/tests/pod-privileged:v0.2.1".to_owned(),
            policy_mode: PolicyMode::Protect,
            allowed_to_mutate: None,
            settings: None,
            context_aware_resources: BTreeSet::new(),
        },
    )]);
    config.verification_config = Some(verification_config);

    let app = app(config).await;

    let request = Request::builder()
        .method(http::Method::POST)
        .header(header::CONTENT_TYPE, "application/json")
        .uri("/validate/pod-privileged")
        .body(Body::from(include_str!(
            "data/pod_with_privileged_containers.json"
        )))
        .unwrap();

    let response = app.oneshot(request).await.unwrap();
    assert_eq!(response.status(), 200);
}

#[tokio::test]
async fn test_policy_with_invalid_settings() {
    let mut config = default_test_config();
    config.policies.insert(
        "invalid_settings".to_owned(),
        PolicyOrPolicyGroup::Policy {
            url: "ghcr.io/kubewarden/tests/sleeping-policy:v0.1.0".to_owned(),
            policy_mode: PolicyMode::Protect,
            allowed_to_mutate: None,
            settings: Some(HashMap::from([(
                "sleepMilliseconds".to_owned(),
                "abc".into(),
            )])),
            context_aware_resources: BTreeSet::new(),
        },
    );
    config.continue_on_errors = true;

    let app = app(config).await;

    let request = Request::builder()
        .method(http::Method::POST)
        .header(header::CONTENT_TYPE, "application/json")
        .uri("/validate/invalid_settings")
        .body(Body::from(include_str!("data/pod_sleep_100ms.json")))
        .unwrap();

    let response = app.oneshot(request).await.unwrap();

    assert_eq!(response.status(), 200);

    let admission_review_response: AdmissionReviewResponse =
        serde_json::from_slice(&response.into_body().collect().await.unwrap().to_bytes()).unwrap();

    assert!(!admission_review_response.response.allowed);

    let pattern =
        Regex::new(r"Policy settings are invalid:.*Error decoding validation payload.*invalid type: string.*expected u64.*")
            .unwrap();

    let status = admission_review_response.response.status.unwrap();

    assert_eq!(status.code, Some(500));
    assert!(pattern.is_match(&status.message.unwrap()));
}

#[tokio::test]
async fn test_policy_with_wrong_url() {
    let mut config = default_test_config();
    config.policies.insert(
        "wrong_url".to_owned(),
        PolicyOrPolicyGroup::Policy {
            url: "ghcr.io/kubewarden/tests/not_existing:v0.1.0".to_owned(),
            policy_mode: PolicyMode::Protect,
            allowed_to_mutate: None,
            settings: None,
            context_aware_resources: BTreeSet::new(),
        },
    );
    config.continue_on_errors = true;

    let app = app(config).await;

    let request = Request::builder()
        .method(http::Method::POST)
        .header(header::CONTENT_TYPE, "application/json")
        .uri("/audit/wrong_url")
        .body(Body::from(include_str!("data/pod_sleep_100ms.json")))
        .unwrap();

    let response = app.oneshot(request).await.unwrap();

    assert_eq!(response.status(), 200);

    let admission_review_response: AdmissionReviewResponse =
        serde_json::from_slice(&response.into_body().collect().await.unwrap().to_bytes()).unwrap();

    assert!(!admission_review_response.response.allowed);

    let pattern =
        Regex::new(r"Error while downloading policy 'wrong_url' from ghcr.io/kubewarden/tests/not_existing:v0.1.0.*")
            .unwrap();

    let status = admission_review_response.response.status.unwrap();

    assert_eq!(status.code, Some(500));
    assert!(pattern.is_match(&status.message.unwrap()));
}
