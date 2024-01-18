use axum::Router;
use policy_server::{
    config::{Config, Policy, PolicyMode},
    PolicyServer,
};
use std::{
    collections::{BTreeSet, HashMap},
    net::SocketAddr,
};
use tempfile::tempdir;

pub(crate) async fn app() -> Router {
    let policies = HashMap::from([
        (
            "pod-privileged".to_owned(),
            Policy {
                url: "ghcr.io/kubewarden/tests/pod-privileged:v0.2.1".to_owned(),
                policy_mode: PolicyMode::Protect,
                allowed_to_mutate: None,
                settings: None,
                context_aware_resources: BTreeSet::new(),
            },
        ),
        (
            "raw-mutation".to_owned(),
            Policy {
                url: "ghcr.io/kubewarden/tests/raw-mutation-policy:v0.1.0".to_owned(),
                policy_mode: PolicyMode::Protect,
                allowed_to_mutate: Some(true),
                settings: Some(HashMap::from([
                    (
                        "forbiddenResources".to_owned(),
                        vec!["banana", "carrot"].into(),
                    ),
                    ("defaultResource".to_owned(), "hay".into()),
                ])),
                context_aware_resources: BTreeSet::new(),
            },
        ),
        (
            "sleep".to_owned(),
            Policy {
                url: "ghcr.io/kubewarden/tests/sleeping-policy:v0.1.0".to_owned(),
                policy_mode: PolicyMode::Protect,
                allowed_to_mutate: None,
                settings: Some(HashMap::from([("sleepMilliseconds".to_owned(), 2.into())])),
                context_aware_resources: BTreeSet::new(),
            },
        ),
    ]);

    let config = Config {
        addr: SocketAddr::from(([127, 0, 0, 1], 3001)),
        sources: None,
        policies,
        policies_download_dir: tempdir().unwrap().into_path(),
        ignore_kubernetes_connection_failure: true,
        always_accept_admission_reviews_on_namespace: None,
        policy_evaluation_limit_seconds: Some(2),
        tls_config: None,
        pool_size: 2,
        metrics_enabled: true,
        sigstore_cache_dir: tempdir().unwrap().into_path(),
        verification_config: None,
        log_level: "info".to_owned(),
        log_fmt: "json".to_owned(),
        log_no_color: false,
        daemon: false,
        daemon_pid_file: "policy_server.pid".to_owned(),
        daemon_stdout_file: None,
        daemon_stderr_file: None,
    };

    let server = PolicyServer::new_from_config(config).await.unwrap();

    server.router()
}
