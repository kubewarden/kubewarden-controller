mod common;

use std::io::BufReader;
use std::{
    collections::{BTreeSet, HashMap},
    fs::{set_permissions, File, Permissions},
    io::BufRead,
    os::unix::fs::PermissionsExt,
    path::PathBuf,
    time::Duration,
};

use common::app;

use axum::{
    body::Body,
    http::{self, header, Request},
};
use backon::{ExponentialBuilder, Retryable};
use http_body_util::BodyExt;
use policy_evaluator::admission_response;
use policy_evaluator::{
    admission_response::AdmissionResponseStatus,
    policy_fetcher::verify::config::VerificationConfigV1,
};
use policy_server::{
    api::admission_review::AdmissionReviewResponse,
    config::{PolicyMode, PolicyOrPolicyGroup},
    metrics::setup_metrics,
    tracing::setup_tracing,
};
use regex::Regex;
use rstest::*;
use tempfile::NamedTempFile;
use testcontainers::{
    core::{Mount, WaitFor},
    runners::AsyncRunner,
    GenericImage, ImageExt,
};
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
                code: None,
                ..Default::default()
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
            Some("The group policy rejected your request".to_string()),
            admission_review_response
                .response
                .status
                .clone()
                .expect("status should be filled")
                .message,
        );
    }

    let warning_messages = &admission_review_response
        .response
        .warnings
        .expect("warning messages should always be filled by policy groups");
    assert_eq!(1, warning_messages.len());

    let warning_msg = &warning_messages[0];
    if expected_allowed {
        assert!(warning_msg.contains("allowed"));
    } else {
        assert!(warning_msg.contains("rejected"));
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
        Some(admission_response::PatchType::JSONPatch),
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
        Some("The group policy rejected your request".to_string()),
        admission_review_response
            .response
            .status
            .clone()
            .expect("status should be filled")
            .message,
    );
    assert!(admission_review_response.response.patch.is_none());

    let warning_messages = &admission_review_response
        .response
        .warnings
        .expect("warning messages should always be filled by policy groups");
    assert_eq!(1, warning_messages.len());
    let warning_msg = &warning_messages[0];
    assert!(warning_msg.contains("rejected"));

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
            code: None,
            ..Default::default()
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
                code: Some(500),
                ..Default::default()
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

// helper functions for certificate rotation test, which is a feature supported only on Linux
#[cfg(target_os = "linux")]
mod certificate_reload_helpers {
    use openssl::ssl::{SslConnector, SslMethod, SslVerifyMode};
    use rcgen::{generate_simple_self_signed, CertifiedKey};
    use std::net::TcpStream;

    pub struct TlsData {
        pub key: String,
        pub cert: String,
    }

    pub fn create_cert(hostname: &str) -> TlsData {
        let subject_alt_names = vec![hostname.to_string()];

        let CertifiedKey { cert, key_pair } =
            generate_simple_self_signed(subject_alt_names).unwrap();

        TlsData {
            key: key_pair.serialize_pem(),
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

    pub async fn check_tls_san_name(domain_ip: &str, domain_port: &str, hostname: &str) -> bool {
        let sleep_interval = std::time::Duration::from_secs(1);
        let max_retries = 10;
        let mut failed_retries = 0;
        let hostname = hostname.to_string();
        loop {
            let san_names = get_tls_san_names(domain_ip, domain_port).await;
            if san_names.contains(&hostname) {
                return true;
            }
            failed_retries += 1;
            if failed_retries >= max_retries {
                return false;
            }
            tokio::time::sleep(sleep_interval).await;
        }
    }

    pub async fn wait_for_policy_server_to_be_ready(address: &str) {
        let sleep_interval = std::time::Duration::from_secs(1);
        let max_retries = 5;
        let mut failed_retries = 0;

        // wait for the server to start
        let client = reqwest::Client::builder()
            .danger_accept_invalid_certs(true)
            .build()
            .unwrap();

        loop {
            let url = reqwest::Url::parse(&format!("https://{address}/readiness")).unwrap();
            match client.get(url).send().await {
                Ok(_) => break,
                Err(e) => {
                    failed_retries += 1;
                    if failed_retries >= max_retries {
                        panic!("failed to start the server: {:?}", e);
                    }
                    tokio::time::sleep(sleep_interval).await;
                }
            }
        }
    }
}

#[cfg(target_os = "linux")]
#[tokio::test(flavor = "multi_thread")]
async fn test_detect_certificate_rotation() {
    use certificate_reload_helpers::*;

    // Starting from rustls 0.22, each application must set its default crypto provider.
    // This setup is done inside of the `main` function of the policy server,
    // which is not called in this test.
    // Hence we have to setup the crypto provider here.
    let crypto_provider = rustls::crypto::ring::default_provider();
    crypto_provider
        .install_default()
        .expect("Failed to install crypto provider");

    let certs_dir = tempfile::tempdir().unwrap();
    let cert_file = certs_dir.path().join("policy-server.pem");
    let key_file = certs_dir.path().join("policy-server-key.pem");

    let hostname1 = "cert1.example.com";
    let tls_data1 = create_cert(hostname1);

    std::fs::write(&cert_file, tls_data1.cert).unwrap();
    std::fs::write(&key_file, tls_data1.key).unwrap();

    let mut config = default_test_config();
    config.tls_config = Some(policy_server::config::TlsConfig {
        cert_file: cert_file.to_str().unwrap().to_string(),
        key_file: key_file.to_str().unwrap().to_string(),
    });
    config.policies = HashMap::new();

    let domain_ip = config.addr.ip().to_string();
    let domain_port = config.addr.port().to_string();

    tokio::spawn(async move {
        let api_server = policy_server::PolicyServer::new_from_config(config)
            .await
            .unwrap();
        api_server.run().await.unwrap();
    });
    wait_for_policy_server_to_be_ready(format!("{domain_ip}:{domain_port}").as_str()).await;

    assert!(check_tls_san_name(&domain_ip, &domain_port, hostname1).await);

    // Generate a new certificate and key, and switch to them

    let hostname2 = "cert2.example.com";
    let tls_data2 = create_cert(hostname2);

    // write only the cert file
    std::fs::write(&cert_file, tls_data2.cert).unwrap();

    // give inotify some time to ensure it detected the cert change
    tokio::time::sleep(std::time::Duration::from_secs(4)).await;

    // the old certificate should still be in use, since we didn't change also the key
    assert!(check_tls_san_name(&domain_ip, &domain_port, hostname1).await);

    // write only the key file
    std::fs::write(&key_file, tls_data2.key).unwrap();

    // give inotify some time to ensure it detected the cert change
    tokio::time::sleep(std::time::Duration::from_secs(4)).await;

    // the new certificate should be in use
    assert!(check_tls_san_name(&domain_ip, &domain_port, hostname2).await);
}

#[tokio::test]
async fn test_otel() {
    let mut otelc_config_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    otelc_config_path.push("tests/data/otel-collector-config.yaml");

    let metrics_output_file = NamedTempFile::new().unwrap();
    let metrics_output_file_path = metrics_output_file.path();

    let traces_output_file = NamedTempFile::new().unwrap();
    let traces_output_file_path = traces_output_file.path();

    let permissions = Permissions::from_mode(0o666);
    set_permissions(metrics_output_file_path, permissions.clone()).unwrap();
    set_permissions(traces_output_file_path, permissions).unwrap();

    let otelc = GenericImage::new("otel/opentelemetry-collector", "0.98.0")
        .with_wait_for(WaitFor::message_on_stderr("Everything is ready"))
        .with_mount(Mount::bind_mount(
            otelc_config_path.to_str().unwrap(),
            "/etc/otel-collector-config.yaml",
        ))
        .with_mount(Mount::bind_mount(
            metrics_output_file_path.to_str().unwrap(),
            "/tmp/metrics.json",
        ))
        .with_mount(Mount::bind_mount(
            traces_output_file_path.to_str().unwrap(),
            "/tmp/traces.json",
        ))
        .with_mapped_port(4317, 4317.into())
        .with_cmd(vec!["--config=/etc/otel-collector-config.yaml"])
        .with_startup_timeout(Duration::from_secs(30))
        .start()
        .await
        .unwrap();

    let mut config = default_test_config();
    config.metrics_enabled = true;
    config.log_fmt = "otlp".to_string();
    setup_metrics().unwrap();
    setup_tracing(&config.log_level, &config.log_fmt, config.log_no_color).unwrap();

    let app = app(config).await;

    // one succesful request
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
    assert!(metrics["metrics"]
        .as_array()
        .unwrap()
        .iter()
        .any(|m| { m["name"] == "kubewarden_policy_evaluation_latency_milliseconds" }));
    assert!(metrics["metrics"]
        .as_array()
        .unwrap()
        .iter()
        .any(|m| { m["name"] == "kubewarden_policy_evaluations_total" }));

    let traces_output_json =
        (|| async { parse_exporter_output(traces_output_file.as_file()).await })
            .retry(exponential_backoff)
            .await
            .unwrap();
    let spans = &traces_output_json["resourceSpans"][0]["scopeSpans"][0];
    assert_eq!(spans["scope"]["name"], "kubewarden-policy-server");

    otelc.stop().await.unwrap();
}

async fn parse_exporter_output(
    exporter_output_file: &File,
) -> serde_json::Result<serde_json::Value> {
    let mut reader = BufReader::new(exporter_output_file);

    // read only the first entry in the output file
    let mut exporter_output = String::new();
    reader
        .read_line(&mut exporter_output)
        .expect("failed to read exporter output");

    serde_json::from_str(&exporter_output)
}
