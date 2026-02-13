use common::setup_command;
use predicates::str::contains;
use rstest::rstest;
use tempfile::tempdir;
use testcontainers::{
    core::{IntoContainerPort, WaitFor},
    runners::SyncRunner,
};

mod common;

const POLICY_URI: &str = "registry://ghcr.io/kubewarden/tests/pod-privileged:v0.2.5";

#[rstest]
#[case::uppercase("HTTP_PROXY", "HTTPS_PROXY")]
#[case::https_proxy_only("", "HTTPS_PROXY")]
#[case::lowercase("http_proxy", "https_proxy")]
fn test_kwctl_pull_with_proxy(#[case] http_var: &str, #[case] https_var: &str) {
    let tempdir = tempdir().expect("cannot create tempdir");

    // start proxy container
    let proxy_image = testcontainers::GenericImage::new("kalaksi/tinyproxy", "1.7")
        .with_wait_for(WaitFor::message_on_stdout("Starting main loop"))
        .with_exposed_port(8888.tcp());
    let container = proxy_image
        .start()
        .expect("Failed to start proxy container");
    let proxy_port = container
        .get_host_port_ipv4(8888)
        .expect("Failed to get proxy port");
    let proxy_url = format!("http://127.0.0.1:{}", proxy_port);

    // this should download the policy through the proxy
    let mut cmd = setup_command(tempdir.path());
    cmd.arg("pull").arg(POLICY_URI);
    if !http_var.is_empty() {
        cmd.env(http_var, &proxy_url);
    }
    cmd.env(https_var, &proxy_url);

    cmd.assert().success();

    // verify the policy was pulled
    let mut cmd = setup_command(tempdir.path());
    cmd.arg("policies");

    cmd.assert().success();
    cmd.assert().stdout(contains(POLICY_URI));
}
