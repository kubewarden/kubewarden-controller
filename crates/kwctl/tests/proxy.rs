use std::time::Duration;

use backon::{BlockingRetryable, ExponentialBuilder};
use predicates::str::contains;
use rstest::rstest;
use tempfile::tempdir;
use testcontainers::{
    Container, GenericImage,
    core::{IntoContainerPort, WaitFor},
    runners::SyncRunner,
};

use common::setup_command;
mod common;

const POLICY_URI: &str = "registry://ghcr.io/kubewarden/tests/pod-privileged:v0.2.5";
const LOCAL_POLICY_PATH: &str = "kubewarden/tests/pod-privileged:v0.2.5";

fn start_proxy() -> (Container<GenericImage>, u16) {
    let proxy_image = GenericImage::new("kalaksi/tinyproxy", "1.7")
        .with_wait_for(WaitFor::message_on_stdout("Starting main loop"))
        .with_exposed_port(8888.tcp());
    let container = proxy_image
        .start()
        .expect("Failed to start proxy container");
    let port = container
        .get_host_port_ipv4(8888)
        .expect("Failed to get proxy port");
    (container, port)
}

/// Used to verify that traffic was (or was not) routed through the proxy.
/// Returns true if the proxy container's logs (stdout or stderr) contain `needle`.
/// Retries with exponential backoff because tinyproxy may not flush its log immediately.
fn proxy_log_contains(container: &Container<GenericImage>, needle: &str) -> bool {
    let check = || {
        let stdout =
            String::from_utf8(container.stdout_to_vec().unwrap_or_default()).unwrap_or_default();
        let stderr =
            String::from_utf8(container.stderr_to_vec().unwrap_or_default()).unwrap_or_default();
        if stdout.contains(needle) || stderr.contains(needle) {
            Ok(())
        } else {
            Err(())
        }
    };
    check
        .retry(
            ExponentialBuilder::default()
                .with_min_delay(Duration::from_millis(100))
                .with_max_times(5),
        )
        .call()
        .is_ok()
}

/// Tests that HTTPS traffic is routed through the proxy when HTTPS_PROXY is set.
/// Verifies by inspecting the proxy container logs for the target hostname.
#[rstest]
#[case::both_http_https_proxy("HTTP_PROXY", "HTTPS_PROXY")]
#[case::https_proxy_only("", "HTTPS_PROXY")]
fn test_kwctl_pull_with_https_proxy(#[case] http_var: &str, #[case] https_var: &str) {
    let tempdir = tempdir().expect("cannot create tempdir");
    let (proxy_container, proxy_port) = start_proxy();
    let proxy_url = format!("http://127.0.0.1:{proxy_port}");

    let mut cmd = setup_command(tempdir.path());
    cmd.arg("pull").arg(POLICY_URI);
    if !http_var.is_empty() {
        cmd.env(http_var, &proxy_url);
    }
    cmd.env(https_var, &proxy_url);
    cmd.assert().success();

    // Verify the policy is now in the local store
    setup_command(tempdir.path())
        .arg("policies")
        .assert()
        .success()
        .stdout(contains(POLICY_URI));

    // Verify traffic actually went through the proxy
    assert!(
        proxy_log_contains(&proxy_container, "ghcr.io"),
        "Expected 'ghcr.io' in proxy logs, indicating HTTPS traffic was routed through the proxy"
    );
}

/// Tests that HTTP traffic is routed through the proxy when HTTP_PROXY is set.
///
/// Since our official images are hosted over HTTPS, a local insecure OCI registry is used as the
/// HTTP policy source. The policy is first pulled from ghcr.io, pushed to the local registry, then
/// pulled again through the proxy. Both containers share the default docker bridge network so the
/// proxy can forward requests to the registry by its bridge IP.
#[test]
fn test_kwctl_pull_with_http_proxy() {
    let tempdir = tempdir().expect("cannot create tempdir");

    // Start local insecure OCI registry
    let registry_container = GenericImage::new("docker.io/library/registry", "2")
        .with_wait_for(WaitFor::message_on_stderr("listening on "))
        .start()
        .expect("Failed to start registry container");
    let registry_bridge_ip = registry_container
        .get_bridge_ip_address()
        .expect("Failed to get registry bridge IP");
    let registry_addr = format!("{registry_bridge_ip}:5000");
    let local_policy_uri = format!("registry://{registry_addr}/{LOCAL_POLICY_PATH}");

    // Configure kwctl to accept insecure (HTTP) connections to the local registry
    let sources_yaml = format!("insecure_sources:\n  - \"{registry_addr}\"\n");
    let sources_path = tempdir.path().join("sources.yml");
    std::fs::write(&sources_path, &sources_yaml).expect("Failed to write sources.yml");

    // Pull the policy from ghcr.io to populate the local store
    setup_command(tempdir.path())
        .arg("pull")
        .arg(POLICY_URI)
        .assert()
        .success();

    // Push the policy to the local insecure registry
    setup_command(tempdir.path())
        .arg("push")
        .arg(POLICY_URI)
        .arg(&local_policy_uri)
        .arg("--sources-path")
        .arg(&sources_path)
        .assert()
        .success();

    // Start proxy
    let (proxy_container, proxy_port) = start_proxy();
    let proxy_url = format!("http://127.0.0.1:{proxy_port}");

    // Pull from the local registry via the HTTP proxy.
    // The proxy and registry are on the same docker bridge network, so the proxy can reach the
    // registry at its bridge IP on port 5000.
    setup_command(tempdir.path())
        .arg("pull")
        .arg(&local_policy_uri)
        .arg("--sources-path")
        .arg(&sources_path)
        .env("HTTP_PROXY", &proxy_url)
        .assert()
        .success();

    // Verify traffic actually went through the proxy
    assert!(
        proxy_log_contains(&proxy_container, &registry_bridge_ip.to_string()),
        "Expected registry IP '{registry_bridge_ip}' in proxy logs, \
         indicating HTTP traffic was routed through the proxy"
    );
}

/// Tests that NO_PROXY bypasses the proxy for matching hosts.
///
/// A real tinyproxy is started and set as HTTPS_PROXY. With NO_PROXY=ghcr.io the pull should
/// succeed and the proxy logs must not contain any reference to ghcr.io, confirming that traffic
/// was not routed through the proxy.
#[test]
fn test_kwctl_pull_with_no_proxy() {
    let tempdir = tempdir().expect("cannot create tempdir");
    let (proxy_container, proxy_port) = start_proxy();
    let proxy_url = format!("http://127.0.0.1:{proxy_port}");

    setup_command(tempdir.path())
        .arg("pull")
        .arg(POLICY_URI)
        .env("HTTPS_PROXY", &proxy_url)
        .env("NO_PROXY", "ghcr.io")
        .assert()
        .success();

    // Verify traffic did NOT go through the proxy
    assert!(
        !proxy_log_contains(&proxy_container, "ghcr.io"),
        "Expected 'ghcr.io' to be absent from proxy logs, \
         indicating traffic bypassed the proxy via NO_PROXY"
    );
}
