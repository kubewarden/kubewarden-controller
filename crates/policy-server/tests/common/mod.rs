use policy_server::config::{Config, Policy, PolicyMode};

use reqwest::blocking::Client;
use std::{
    collections::{BTreeSet, HashMap},
    net::SocketAddr,
    sync::Once,
    thread,
};
use tempfile::tempdir;

static INIT: Once = Once::new();
static URL: &str = "http://127.0.0.1:3001";

pub(crate) fn setup() {
    INIT.call_once(|| {
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
        ]);

        let config = Config {
            addr: SocketAddr::from(([127, 0, 0, 1], 3001)),
            sources: None,
            policies,
            policies_download_dir: tempdir().unwrap().into_path(),
            ignore_kubernetes_connection_failure: true,
            always_accept_admission_reviews_on_namespace: None,
            policy_evaluation_limit: None,
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

        thread::spawn(move || {
            policy_server::run(config).unwrap();
        });

        loop {
            let client = Client::new();
            if let Ok(resp) = client.get(format!("{}/readiness", URL)).send() {
                if resp.status().is_success() {
                    break;
                }
            }
        }
    });
}

pub(crate) fn url(path: &str) -> String {
    format!("{}{}", URL, path)
}
