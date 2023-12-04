mod common;

use common::{setup, url};

use policy_server::{
    admission_review::AdmissionReview,
    raw_review::{RawReviewRequest, RawReviewResponse},
};
use reqwest::blocking::Client;

#[test]
fn test_validate() {
    setup();

    let body: AdmissionReview =
        serde_json::from_str(include_str!("data/pod_with_privileged_containers.json")).unwrap();

    let client = Client::new();
    let resp = client
        .post(url("/validate/pod-privileged"))
        .json(&body)
        .send()
        .unwrap();
    assert_eq!(resp.status(), 200);

    let admission_review: AdmissionReview = resp.json().expect("cannot deserialize response");
    let admission_response = admission_review.response.unwrap();

    assert!(!admission_response.allowed);
    assert_eq!(
        admission_response.status,
        Some(
            policy_evaluator::admission_response::AdmissionResponseStatus {
                message: Some("Privileged container is not allowed".to_owned()),
                code: None
            }
        )
    )
}

#[test]
fn test_validate_policy_not_found() {
    setup();

    let body: serde_json::Value =
        serde_json::from_str(include_str!("data/pod_with_privileged_containers.json")).unwrap();

    let client = Client::new();
    let resp = client
        .post(url("/validate/does_not_exist"))
        .json(&body)
        .send()
        .unwrap();

    assert_eq!(resp.status(), 404);
}

#[test]
fn test_validate_invalid_payload() {
    setup();

    let body: serde_json::Value = serde_json::from_str("{}").unwrap();

    let client = Client::new();
    let resp = client
        .post(url("/validate/pod-privileged"))
        .json(&body)
        .send()
        .unwrap();

    assert_eq!(resp.status(), 400);
}

#[test]
fn test_validate_raw() {
    setup();

    let body: RawReviewRequest =
        serde_json::from_str(include_str!("data/raw_review.json")).unwrap();

    let client = Client::new();
    let resp = client
        .post(url("/validate_raw/raw-mutation"))
        .json(&body)
        .send()
        .unwrap();

    assert_eq!(resp.status(), 200);

    let raw_review: RawReviewResponse = resp.json().expect("cannot deserialize response");

    assert!(raw_review.response.allowed);
    assert_eq!(raw_review.response.status, None);
    assert!(raw_review.response.patch.is_some());
    assert_eq!(Some("JSONPatch".to_owned()), raw_review.response.patch_type);
}

#[test]
fn test_validate_raw_policy_not_found() {
    setup();

    let body: RawReviewRequest =
        serde_json::from_str(include_str!("data/raw_review.json")).unwrap();

    let client = Client::new();
    let resp = client
        .post(url("/validate_raw/does_not_exist"))
        .json(&body)
        .send()
        .unwrap();

    assert_eq!(resp.status(), 404);
}

#[test]
fn test_validate_raw_invalid_payload() {
    setup();

    let body: serde_json::Value = serde_json::from_str("{}").unwrap();

    let client = Client::new();
    let resp = client
        .post(url("/validate_raw/raw-mutation"))
        .json(&body)
        .send()
        .unwrap();

    assert_eq!(resp.status(), 400);
}

#[test]
fn test_audit() {
    setup();

    let body: AdmissionReview =
        serde_json::from_str(include_str!("data/pod_with_privileged_containers.json")).unwrap();

    let client = Client::new();
    let resp = client
        .post(url("/audit/pod-privileged"))
        .json(&body)
        .send()
        .unwrap();
    assert_eq!(resp.status(), 200);

    let admission_review: AdmissionReview = resp.json().expect("cannot deserialize response");
    let admission_response = admission_review.response.unwrap();

    assert!(!admission_response.allowed);
}

#[test]
fn test_audit_policy_not_found() {
    setup();

    let body: serde_json::Value =
        serde_json::from_str(include_str!("data/pod_with_privileged_containers.json")).unwrap();

    let client = Client::new();
    let resp = client
        .post(url("/audit/does_not_exist"))
        .json(&body)
        .send()
        .unwrap();

    assert_eq!(resp.status(), 404);
}

#[test]
fn test_audit_invalid_payload() {
    setup();

    let body: serde_json::Value = serde_json::from_str("{}").unwrap();

    let client = Client::new();
    let resp = client
        .post(url("/audit/pod-privileged"))
        .json(&body)
        .send()
        .unwrap();

    assert_eq!(resp.status(), 400);
}
