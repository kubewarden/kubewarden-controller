mod common;

use std::path::PathBuf;
use std::{
    collections::{BTreeSet, HashMap},
    time::Duration,
};
#[cfg(feature = "otel_tests")]
use std::{fs::File, io::BufRead};

use common::{app, setup};

use axum::{
    body::Body,
    http::{self, header, Request},
};
use backon::{ExponentialBuilder, Retryable};
use http_body_util::BodyExt;
use policy_evaluator::admission_response::{self, StatusCause, StatusDetails};
use policy_evaluator::{
    admission_response::AdmissionResponseStatus,
    admission_response_handler::policy_mode::PolicyMode, policy_evaluator::PolicySettings,
    policy_fetcher::verify::config::VerificationConfigV1,
};
use policy_server::{api::admission_review::AdmissionReviewResponse, config::PolicyOrPolicyGroup};
use regex::Regex;
use rstest::*;
use serde_json::json;
use tokio::fs;
use tower::ServiceExt;

use crate::common::default_test_config;

#[tokio::test]
async fn test_validate() {
    setup();

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
                code: None,
                ..Default::default()
            }
        )
    )
}

#[tokio::test]
async fn test_validate_custom_rejection_message() {
    setup();

    let mut config = default_test_config();
    config.policies.insert(
        "pod-privileged".to_owned(),
        PolicyOrPolicyGroup::Policy {
            module: "ghcr.io/kubewarden/tests/pod-privileged:v0.2.1".to_owned(),
            policy_mode: PolicyMode::Protect,
            allowed_to_mutate: None,
            settings: None,
            context_aware_resources: BTreeSet::new(),
            message: Some("Custom error message".to_owned()),
        },
    );
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
                message: Some("Custom error message".to_owned()),
                details: Some(StatusDetails {
                    causes: vec![StatusCause {
                        message: Some("Privileged container is not allowed".to_owned()),
                        ..Default::default()
                    }],
                    ..Default::default()
                }),
                ..Default::default()
            }
        )
    );
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
    setup();

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
            Some("The group policy rejected your request".to_string()),
            admission_review_response
                .response
                .status
                .clone()
                .expect("status should be filled")
                .message,
        );
    }
    assert_eq!(admission_review_response.response.warnings, None);

    if !expected_allowed {
        let causes = admission_review_response
            .response
            .status
            .expect("status should be filled")
            .details
            .expect("details should be filled")
            .causes;
        assert_eq!(1, causes.len());
        assert_eq!(
            Some("Privileged container is not allowed".to_string()),
            causes[0].message,
        );
    }
}

#[tokio::test]
async fn test_validate_policy_not_found() {
    setup();

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
    setup();

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
    setup();

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
        Some(admission_response::PatchType::JSONPatch),
        admission_review_response.response.patch_type
    );
}

#[tokio::test]
async fn test_validate_policy_group_does_not_do_mutation() {
    setup();

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
        Some("The group policy rejected your request".to_string()),
        admission_review_response
            .response
            .status
            .clone()
            .expect("status should be filled")
            .message,
    );
    assert!(admission_review_response.response.patch.is_none());

    assert_eq!(admission_review_response.response.warnings, None);

    let causes = admission_review_response
        .response
        .status
        .expect("status should be filled")
        .details
        .expect("details should be filled")
        .causes;
    assert_eq!(1, causes.len());
    assert_eq!(
        Some("mutation is not allowed inside of policy group".to_string()),
        causes[0].message,
    );
}

#[tokio::test]
async fn test_validate_raw_policy_not_found() {
    setup();

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
    setup();

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
    setup();

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
            code: None,
            ..Default::default()
        })
    );
}

#[tokio::test]
async fn test_audit_policy_not_found() {
    setup();

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
    setup();

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
    setup();

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
    setup();

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
                code: Some(500),
                ..Default::default()
            }
        )
    );
}

#[tokio::test]
async fn test_verified_policy() {
    setup();

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
            module: "ghcr.io/kubewarden/tests/pod-privileged:v0.2.1".to_owned(),
            policy_mode: PolicyMode::Protect,
            allowed_to_mutate: None,
            settings: None,
            context_aware_resources: BTreeSet::new(),
            message: None,
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
    setup();

    let mut config = default_test_config();
    config.policies.insert(
        "invalid_settings".to_owned(),
        PolicyOrPolicyGroup::Policy {
            module: "ghcr.io/kubewarden/tests/sleeping-policy:v0.1.0".to_owned(),
            policy_mode: PolicyMode::Protect,
            allowed_to_mutate: None,
            settings: Some(
                PolicySettings::try_from(&json!({
                    "sleepMilliseconds": "abc",
                }))
                .unwrap(),
            ),
            context_aware_resources: BTreeSet::new(),
            message: None,
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
    setup();

    let mut config = default_test_config();
    config.policies.insert(
        "wrong_url".to_owned(),
        PolicyOrPolicyGroup::Policy {
            module: "ghcr.io/kubewarden/tests/not_existing:v0.1.0".to_owned(),
            policy_mode: PolicyMode::Protect,
            allowed_to_mutate: None,
            settings: None,
            context_aware_resources: BTreeSet::new(),
            message: None,
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

// helper functions for certificate rotation test, which is a feature supported only on Linux
#[cfg(target_os = "linux")]
mod certificate_reload_helpers {
    use std::net::TcpStream;

    use anyhow::anyhow;
    use openssl::ssl::{SslConnector, SslMethod, SslVerifyMode};
    use rcgen::{generate_simple_self_signed, CertifiedKey};
    use reqwest::StatusCode;

    pub struct TlsData {
        pub key: String,
        pub cert: String,
    }

    pub fn create_cert(hostname: &str) -> TlsData {
        let subject_alt_names = vec![hostname.to_string()];

        let CertifiedKey { cert, signing_key } =
            generate_simple_self_signed(subject_alt_names).unwrap();

        TlsData {
            key: signing_key.serialize_pem(),
            cert: cert.pem(),
        }
    }

    pub async fn get_tls_san_names(domain_ip: &str, domain_port: &str) -> Vec<String> {
        let domain_ip = domain_ip.to_string();
        let domain_port = domain_port.to_string();

        tokio::task::spawn_blocking(move || {
            let mut builder = SslConnector::builder(SslMethod::tls()).unwrap();
            builder.set_verify(SslVerifyMode::NONE);
            let connector = builder.build();
            let stream = TcpStream::connect(format!("{domain_ip}:{domain_port}")).unwrap();
            let stream = connector.connect(&domain_ip, stream).unwrap();

            let cert = stream.ssl().peer_certificate().unwrap();
            cert.subject_alt_names()
                .expect("failed to get SAN names")
                .iter()
                .map(|name| {
                    name.dnsname()
                        .expect("failed to get DNS name from SAN entry")
                        .to_string()
                })
                .collect::<Vec<String>>()
        })
        .await
        .unwrap()
    }

    pub async fn check_tls_san_name(
        domain_ip: &str,
        domain_port: &str,
        hostname: &str,
    ) -> anyhow::Result<()> {
        let hostname = hostname.to_string();
        let san_names = get_tls_san_names(domain_ip, domain_port).await;
        if san_names.contains(&hostname) {
            Ok(())
        } else {
            Err(anyhow!(
                "SAN names do not contain the expected hostname ({}): {:?}",
                hostname,
                san_names
            ))
        }
    }

    pub async fn policy_server_is_ready(address: &str) -> anyhow::Result<StatusCode> {
        // wait for the server to start
        let client = reqwest::Client::builder().build().unwrap();

        let url = reqwest::Url::parse(&format!("http://{address}/readiness")).unwrap();
        let response = client.get(url).send().await?;
        Ok(response.status())
    }
}

#[cfg(target_os = "linux")]
#[tokio::test(flavor = "multi_thread")]
async fn test_detect_certificate_rotation() {
    use certificate_reload_helpers::*;

    setup();

    let certs_dir = tempfile::tempdir().unwrap();
    let cert_file = certs_dir.path().join("policy-server.pem");
    let key_file = certs_dir.path().join("policy-server-key.pem");
    let first_client_ca = certs_dir.path().join("client_cert1.pem");
    let second_client_ca = certs_dir.path().join("client_cert2.pem");

    let hostname1 = "cert1.example.com";
    let tls_data1 = create_cert(hostname1);
    let first_tls_data_client = create_cert(hostname1);
    let second_tls_data_client = create_cert(hostname1);

    fs::write(&cert_file, tls_data1.cert).await.unwrap();
    fs::write(&key_file, tls_data1.key).await.unwrap();
    fs::write(&first_client_ca, first_tls_data_client.cert.clone())
        .await
        .unwrap();
    fs::write(&second_client_ca, second_tls_data_client.cert.clone())
        .await
        .unwrap();

    let mut config = default_test_config();
    config.tls_config = Some(policy_server::config::TlsConfig {
        cert_file: cert_file.clone(),
        key_file: key_file.clone(),
        client_ca_file: vec![first_client_ca.clone(), second_client_ca.clone()],
    });

    let host = config.addr.ip().to_string();
    let port = config.addr.port().to_string();
    let readiness_probe_port = config.readiness_probe_addr.port().to_string();

    tokio::spawn(async move {
        let api_server = policy_server::PolicyServer::new_from_config(config)
            .await
            .unwrap();
        api_server.run().await.unwrap();
    });

    let exponential_backoff = ExponentialBuilder::default()
        .with_min_delay(Duration::from_secs(10))
        .with_max_delay(Duration::from_secs(30))
        .with_max_times(5);

    let status_code = (|| async {
        policy_server_is_ready(format!("{host}:{readiness_probe_port}").as_str()).await
    })
    .retry(exponential_backoff)
    .await
    .unwrap();
    assert_eq!(status_code, reqwest::StatusCode::OK);

    check_tls_san_name(&host, &port, hostname1)
        .await
        .expect("certificate served doesn't use the expected SAN name");

    // Generate a new certificate and key, and switch to them

    let hostname2 = "cert2.example.com";
    let tls_data2 = create_cert(hostname2);

    // write only the cert file
    fs::write(&cert_file, tls_data2.cert.clone()).await.unwrap();

    // give inotify some time to ensure it detected the cert change
    tokio::time::sleep(std::time::Duration::from_secs(4)).await;

    // the old certificate should still be in use, since we didn't change also the key
    check_tls_san_name(&host, &port, hostname1)
        .await
        .expect("certificate should not have been changed");

    // write only the key file
    fs::write(&key_file, tls_data2.key.clone()).await.unwrap();

    // give inotify some time to ensure it detected the cert change,
    // also give axum some time to complete the certificate reload
    tokio::time::sleep(std::time::Duration::from_secs(4)).await;
    check_tls_san_name(&host, &port, hostname2)
        .await
        .expect("certificate hasn't been reloaded");

    // Validate the client CA reload
    let first_tls_data_client2 = create_cert(hostname2);

    // write only the cert file
    fs::write(&first_client_ca, first_tls_data_client2.cert.clone())
        .await
        .unwrap();

    // give inotify some time to ensure it detected the cert change
    tokio::time::sleep(std::time::Duration::from_secs(4)).await;

    let second_tls_data_client2 = create_cert(hostname2);

    // write only the cert file
    fs::write(&second_client_ca, second_tls_data_client2.cert.clone())
        .await
        .unwrap();

    // give inotify some time to ensure it detected the cert change
    tokio::time::sleep(std::time::Duration::from_secs(4)).await;

    let exponential_backoff = ExponentialBuilder::default()
        .with_min_delay(Duration::from_secs(10))
        .with_max_delay(Duration::from_secs(30))
        .with_max_times(5);

    let status_code = (|| async {
        policy_server_is_ready(format!("{host}:{readiness_probe_port}").as_str()).await
    })
    .retry(exponential_backoff)
    .await
    .unwrap();
    assert_eq!(status_code, reqwest::StatusCode::OK);

    for tls_data_client in [&first_tls_data_client2, &second_tls_data_client2] {
        let client = build_request_client(
            Some(&tls_data2),
            Some(tls_data_client.cert.clone()),
            Some(tls_data_client.key.clone()),
            true,
        );

        let status_code = (|| async {
            send_validate_request(&client, format!("{host}:{port}"), Some(&tls_data2)).await
        })
        .retry(exponential_backoff)
        .await
        .expect("failed to send validation request");
        assert_eq!(status_code, reqwest::StatusCode::OK);
    }
}

// The OTEL test is behind a feature flag because it needs to ensure that the
// global OTEL configuration is not overwritten by other concurrent tests.
#[tokio::test]
#[cfg(feature = "otel_tests")]
async fn test_otel() {
    use policy_server::{metrics::setup_metrics, tracing::setup_tracing};
    use std::{
        fs::{set_permissions, Permissions},
        os::unix::fs::PermissionsExt,
    };
    use tempfile::NamedTempFile;
    use testcontainers::{
        core::{Mount, WaitFor},
        runners::AsyncRunner,
        GenericImage, ImageExt,
    };

    setup();

    let otelc_config_path =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/data/otel-collector-config.yaml");

    let (server_ca, server_cert, server_key) = generate_tls_certs();
    let (client_ca, client_cert, client_key) = generate_tls_certs();

    let server_ca_file = NamedTempFile::new().unwrap();
    let server_cert_file = NamedTempFile::new().unwrap();
    let server_key_file = NamedTempFile::new().unwrap();

    let client_ca_file = NamedTempFile::new().unwrap();
    let client_cert_file = NamedTempFile::new().unwrap();
    let client_key_file = NamedTempFile::new().unwrap();

    let files_and_contents = [
        (server_ca_file.path(), &server_ca),
        (server_cert_file.path(), &server_cert),
        (server_key_file.path(), &server_key),
        (client_ca_file.path(), &client_ca),
        (client_cert_file.path(), &client_cert),
        (client_key_file.path(), &client_key),
    ];

    for (file_path, content) in &files_and_contents {
        fs::write(file_path, content).await.unwrap();
    }

    let metrics_output_file = NamedTempFile::new().unwrap();
    let traces_output_file = NamedTempFile::new().unwrap();

    let permissions = Permissions::from_mode(0o666);
    let files_to_set_permissions = [
        metrics_output_file.path(),
        traces_output_file.path(),
        server_ca_file.path(),
        server_cert_file.path(),
        server_key_file.path(),
        client_ca_file.path(),
        client_cert_file.path(),
        client_key_file.path(),
    ];

    for file_path in &files_to_set_permissions {
        set_permissions(file_path, permissions.clone()).unwrap();
    }

    let otelc = GenericImage::new("otel/opentelemetry-collector", "0.120.0")
        .with_wait_for(WaitFor::message_on_stderr("Everything is ready"))
        .with_mount(Mount::bind_mount(
            otelc_config_path.to_str().unwrap(),
            "/etc/otel-collector-config.yaml",
        ))
        .with_mount(Mount::bind_mount(
            metrics_output_file.path().to_str().unwrap(),
            "/tmp/metrics.json",
        ))
        .with_mount(Mount::bind_mount(
            traces_output_file.path().to_str().unwrap(),
            "/tmp/traces.json",
        ))
        .with_mount(Mount::bind_mount(
            server_ca_file.path().to_str().unwrap(),
            "/certs/server-ca.pem",
        ))
        .with_mount(Mount::bind_mount(
            server_cert_file.path().to_str().unwrap(),
            "/certs/server-cert.pem",
        ))
        .with_mount(Mount::bind_mount(
            server_key_file.path().to_str().unwrap(),
            "/certs/server-key.pem",
        ))
        .with_mount(Mount::bind_mount(
            client_ca_file.path().to_str().unwrap(),
            "/certs/client-ca.pem",
        ))
        .with_mapped_port(1337, 4317.into())
        .with_cmd(vec!["--config=/etc/otel-collector-config.yaml"])
        .with_startup_timeout(Duration::from_secs(30))
        .start()
        .await
        .unwrap();

    std::env::set_var("OTEL_EXPORTER_OTLP_ENDPOINT", "https://localhost:1337");
    std::env::set_var(
        "OTEL_EXPORTER_OTLP_CERTIFICATE",
        server_ca_file.path().to_str().unwrap(),
    );
    std::env::set_var(
        "OTEL_EXPORTER_OTLP_CLIENT_CERTIFICATE",
        client_cert_file.path().to_str().unwrap(),
    );
    std::env::set_var(
        "OTEL_EXPORTER_OTLP_CLIENT_KEY",
        client_key_file.path().to_str().unwrap(),
    );

    let mut config = default_test_config();
    config.metrics_enabled = true;
    config.log_fmt = "otlp".to_string();

    setup_metrics().unwrap();
    setup_tracing(&config.log_level, &config.log_fmt, config.log_no_color).unwrap();

    let app = app(config).await;

    // one successful request
    let request = Request::builder()
        .method(http::Method::POST)
        .header(header::CONTENT_TYPE, "application/json")
        .uri("/validate/pod-privileged")
        .body(Body::from(include_str!(
            "data/pod_without_privileged_containers.json"
        )))
        .unwrap();
    let response = app.oneshot(request).await.unwrap();
    assert_eq!(response.status(), 200);

    let exponential_backoff = ExponentialBuilder::default()
        .with_min_delay(Duration::from_secs(10))
        .with_max_delay(Duration::from_secs(30))
        .with_max_times(5);

    let metrics_output_json =
        (|| async { parse_exporter_output(metrics_output_file.as_file()).await })
            .retry(exponential_backoff)
            .await
            .unwrap();
    let metrics = &metrics_output_json["resourceMetrics"][0]["scopeMetrics"][0];
    assert_eq!(metrics["scope"]["name"], "kubewarden");
    assert!(
        metrics["metrics"]
            .as_array()
            .unwrap()
            .iter()
            .any(|m| { m["name"] == "kubewarden_policy_evaluation_latency_milliseconds" }),
        "metrics_output_json: {}",
        serde_json::to_string_pretty(&metrics_output_json).unwrap()
    );
    assert!(
        metrics["metrics"]
            .as_array()
            .unwrap()
            .iter()
            .any(|m| { m["name"] == "kubewarden_policy_evaluations_total" }),
        "metrics_output_json: {}",
        serde_json::to_string_pretty(&metrics_output_json).unwrap()
    );

    let traces_output_json =
        (|| async { parse_exporter_output(traces_output_file.as_file()).await })
            .retry(exponential_backoff)
            .await
            .unwrap();
    let spans = &traces_output_json["resourceSpans"][0]["scopeSpans"][0];
    assert_eq!(spans["scope"]["name"], "kubewarden-policy-server");

    otelc.stop().await.unwrap();
}

#[cfg(feature = "otel_tests")]
async fn parse_exporter_output(
    exporter_output_file: &File,
) -> serde_json::Result<serde_json::Value> {
    use std::io::BufReader;

    let mut reader = BufReader::new(exporter_output_file);

    // read only the first entry in the output file
    let mut exporter_output = String::new();
    reader
        .read_line(&mut exporter_output)
        .expect("failed to read exporter output");

    serde_json::from_str(&exporter_output)
}

#[cfg(feature = "otel_tests")]
fn generate_tls_certs() -> (String, String, String) {
    use rcgen::{BasicConstraints, CertificateParams, DnType, IsCa, Issuer, KeyPair};

    let mut ca_params = CertificateParams::new(vec!["My Test CA".to_string()]).unwrap();
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    let ca_key_pair = KeyPair::generate().unwrap();
    let ca_cert = ca_params.self_signed(&ca_key_pair).unwrap();
    let issuer = Issuer::new(ca_params, ca_key_pair);

    let mut params = CertificateParams::new(vec!["localhost".to_string()]).unwrap();
    params
        .distinguished_name
        .push(DnType::OrganizationName, "Kubewarden");
    params
        .distinguished_name
        .push(DnType::CommonName, "kubewarden.io");

    let cert_key = KeyPair::generate().unwrap();
    let cert = params.signed_by(&cert_key, &issuer).unwrap();
    let key = cert_key.serialize_pem();

    (ca_cert.pem(), cert.pem(), key)
}

#[cfg(target_os = "linux")]
#[tokio::test(flavor = "multi_thread")]
#[rstest]
#[case::no_tls_config(None, None)]
#[case::with_server_tls_config(Some(certificate_reload_helpers::create_cert("127.0.0.1")), None)]
#[case::mtls_config(
    Some(certificate_reload_helpers::create_cert("127.0.0.1")),
    Some(vec![certificate_reload_helpers::create_cert("127.0.0.1"),certificate_reload_helpers::create_cert("127.0.0.1"),certificate_reload_helpers::create_cert("127.0.0.1")])
)]
async fn test_tls(
    #[case] server_tls_data: Option<certificate_reload_helpers::TlsData>,
    #[case] client_tls_data: Option<Vec<certificate_reload_helpers::TlsData>>,
) {
    use certificate_reload_helpers::*;

    setup();

    let certs_dir = tempfile::tempdir().unwrap();
    let cert_file = certs_dir.path().join("policy-server.pem");
    let key_file = certs_dir.path().join("policy-server-key.pem");

    if let Some(ref tls_data) = server_tls_data {
        fs::write(&cert_file, tls_data.cert.clone()).await.unwrap();
        fs::write(&key_file, tls_data.key.clone()).await.unwrap();
    }

    // Client CA pem file, cert data and key data
    let clients_cas_info: Vec<(PathBuf, String, String)> =
        if let Some(ref tls_data) = client_tls_data {
            let tls_data: Vec<(PathBuf, String, String)> = tls_data
                .iter()
                .enumerate()
                .map(|(i, tls_data)| {
                    let client_ca = certs_dir
                        .path()
                        .join(format!("client_cert_{}.pem", i))
                        .to_owned();

                    (client_ca, tls_data.cert.clone(), tls_data.key.clone())
                })
                .collect();

            for (client_ca, cert, _) in &tls_data {
                fs::write(&client_ca, cert.clone()).await.unwrap();
            }

            tls_data
        } else {
            vec![]
        };

    let mut config = default_test_config();
    config.tls_config = match (server_tls_data.as_ref(), client_tls_data.as_ref()) {
        (None, None) => None,
        (Some(_), Some(_)) => Some(policy_server::config::TlsConfig {
            cert_file: cert_file.clone(),
            key_file: key_file.clone(),
            client_ca_file: clients_cas_info
                .clone()
                .into_iter()
                .map(|it| it.0)
                .collect(),
        }),
        (Some(_), None) => Some(policy_server::config::TlsConfig {
            cert_file: cert_file.clone(),
            key_file: key_file.clone(),
            client_ca_file: vec![],
        }),
        _ => {
            panic!("Invalid test case")
        }
    };

    let host = config.addr.ip().to_string();
    let port = config.addr.port().to_string();
    let readiness_probe_port = config.readiness_probe_addr.port().to_string();

    tokio::spawn(async move {
        let api_server = policy_server::PolicyServer::new_from_config(config)
            .await
            .unwrap();
        api_server.run().await.unwrap();
    });

    // readiness probe should always return 200 no matter the tls configuration.
    // The probe should run in a different server on http
    let exponential_backoff = ExponentialBuilder::default()
        .with_min_delay(Duration::from_secs(10))
        .with_max_delay(Duration::from_secs(30))
        .with_max_times(5);

    let status_code = (|| async {
        policy_server_is_ready(format!("{host}:{readiness_probe_port}").as_str()).await
    })
    .retry(exponential_backoff)
    .await
    .expect("policy server is not ready");
    assert_eq!(status_code, reqwest::StatusCode::OK);

    // Test sending request to policy server using each of the client CA certificates
    let client_to_test = match client_tls_data {
        Some(_) => clients_cas_info
            .iter()
            .map(|(_, client_cert, client_key)| {
                build_request_client(
                    server_tls_data.as_ref(),
                    Some(client_cert.to_owned()),
                    Some(client_key.to_owned()),
                    false,
                )
            })
            .collect(),
        _ => vec![build_request_client(
            server_tls_data.as_ref(),
            None,
            None,
            false,
        )],
    };

    for client in client_to_test {
        let response =
            send_validate_request(&client, format!("{host}:{port}"), server_tls_data.as_ref())
                .await
                .expect("failed to get response status");
        assert_eq!(response, reqwest::StatusCode::OK);
    }
}

async fn send_validate_request(
    client: &reqwest::Client,
    address: String,
    server_tls_data: Option<&certificate_reload_helpers::TlsData>,
) -> anyhow::Result<reqwest::StatusCode> {
    let prefix = if server_tls_data.is_some() {
        "https"
    } else {
        "http"
    };
    let url = reqwest::Url::parse(&format!("{prefix}://{address}/validate/pod-privileged"))
        .expect("failed to format url");
    Ok(client
        .post(url.clone())
        .header(header::CONTENT_TYPE, "application/json")
        .body(include_str!("data/pod_without_privileged_containers.json"))
        .send()
        .await
        .expect("successful request")
        .status())
}

fn build_request_client(
    server_tls_data: Option<&certificate_reload_helpers::TlsData>,
    client_cert: Option<String>,
    client_key: Option<String>,
    ignore_hostname: bool,
) -> reqwest::Client {
    // Validate TLS communication
    let mut builder = reqwest::Client::builder().danger_accept_invalid_hostnames(ignore_hostname);

    if let Some(server_tls_data) = server_tls_data {
        let certificate = reqwest::Certificate::from_pem(server_tls_data.cert.clone().as_bytes())
            .expect("Invalid policy server certificate");
        builder = builder.add_root_certificate(certificate);
    }

    if let (Some(client_cert), Some(client_key)) = (client_cert, client_key) {
        let identity =
            reqwest::Identity::from_pem(format!("{}\n{}", client_cert, client_key).as_bytes())
                .expect("successful pem parsing");
        builder = builder.identity(identity)
    }
    builder.build().expect("failed to build client")
}
