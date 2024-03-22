mod common;

use common::app;

use axum::{
    body::Body,
    http::{self, header, Request},
};
use http_body_util::BodyExt;
use policy_evaluator::admission_response::AdmissionResponseStatus;
use policy_server::api::admission_review::AdmissionReviewResponse;
use regex::Regex;
use tower::ServiceExt;

#[tokio::test]
async fn test_validate() {
    let app = app().await;

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
async fn test_validate_policy_not_found() {
    let app = app().await;

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
    let app = app().await;

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
    let app = app().await;

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
async fn test_validate_raw_policy_not_found() {
    let app = app().await;

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
    let app = app().await;

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
    let app = app().await;

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
    let app = app().await;

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
    let app = app().await;

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
    let app = app().await;

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
    let app = app().await;

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
async fn test_policy_with_invalid_settings() {
    let app = app().await;

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
    let app = app().await;

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
