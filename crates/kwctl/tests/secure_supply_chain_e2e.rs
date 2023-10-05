use assert_cmd::Command;
use common::{setup_command, test_data};
use predicates::{prelude::*, str::contains};
use rstest::rstest;
use std::{fs, path::Path};
use tempfile::tempdir;

pub mod common;

fn cosign_initialize(path: &Path) {
    let mut cmd = Command::new("cosign");
    cmd.env("HOME", path).arg("initialize");
    cmd.assert().success();
}

#[test]
fn test_verify_tuf_integration() {
    let tempdir = tempdir().unwrap();
    let mut cmd = setup_command(tempdir.path());

    cmd.arg("verify")
        .arg("--verification-config-path")
        .arg(test_data("sigstore/verification-config-keyless.yml"))
        .arg("registry://ghcr.io/kubewarden/tests/capabilities-psp:v0.1.9");

    cmd.assert().success();

    let fulcio_and_rekor_data_path = Path::new(tempdir.path())
        .join(".config")
        .join("kubewarden")
        .join("fulcio_and_rekor_data");

    assert!(std::fs::metadata(fulcio_and_rekor_data_path.join("fulcio.crt.pem")).is_ok());
    assert!(std::fs::metadata(fulcio_and_rekor_data_path.join("fulcio_v1.crt.pem")).is_ok());
    assert!(std::fs::metadata(fulcio_and_rekor_data_path.join("rekor.pub")).is_ok());
}

#[test]
fn test_verify_fulcio_cert_path() {
    let tempdir = tempdir().unwrap();
    cosign_initialize(tempdir.path());

    let mut cmd = setup_command(tempdir.path());
    cmd.arg("verify")
        .arg("--fulcio-cert-path")
        .arg(".sigstore/root/targets/fulcio.crt.pem")
        .arg("--fulcio-cert-path")
        .arg(".sigstore/root/targets/fulcio_v1.crt.pem")
        .arg("--rekor-public-key-path")
        .arg(".sigstore/root/targets/rekor.pub")
        .arg("--verification-config-path")
        .arg(test_data("sigstore/verification-config.yml"))
        .arg("registry://ghcr.io/kubewarden/tests/pod-privileged:v0.1.9");

    cmd.assert().success();
}

#[test]
fn test_verify_fulcio_cert_path_no_rekor_public_key() {
    let tempdir = tempdir().unwrap();
    cosign_initialize(tempdir.path());

    let mut cmd = setup_command(tempdir.path());
    cmd.arg("verify")
        .arg("--fulcio-cert-path")
        .arg(".sigstore/root/targets/fulcio.crt.pem")
        .arg("--verification-config-path")
        .arg(test_data("sigstore/verification-config.yml"))
        .arg("registry://ghcr.io/kubewarden/tests/pod-privileged:v0.1.9");

    cmd.assert().failure();
    cmd.assert().stderr(contains(
        "both a fulcio certificate and a rekor public key are required",
    ));
}

#[test]
fn test_verify_rekor_public_key_no_certs() {
    let tempdir = tempdir().unwrap();
    cosign_initialize(tempdir.path());

    let mut cmd = setup_command(tempdir.path());
    cmd.arg("verify")
        .arg("--rekor-public-key-path")
        .arg(".sigstore/root/targets/rekor.pub")
        .arg("--verification-config-path")
        .arg(test_data("sigstore/verification-config.yml"))
        .arg("registry://ghcr.io/kubewarden/tests/pod-privileged:v0.1.9");

    cmd.assert().failure();
    cmd.assert().stderr(contains(
        "both a fulcio certificate and a rekor public key are required",
    ));
}

#[test]
fn test_verify_missing_signatures() {
    let tempdir = tempdir().unwrap();
    cosign_initialize(tempdir.path());

    let mut cmd = setup_command(tempdir.path());
    cmd.arg("verify")
        .arg("--fulcio-cert-path")
        .arg(".sigstore/root/targets/fulcio.crt.pem")
        .arg("--fulcio-cert-path")
        .arg(".sigstore/root/targets/fulcio_v1.crt.pem")
        .arg("--rekor-public-key-path")
        .arg(".sigstore/root/targets/rekor.pub")
        .arg("--verification-config-path")
        .arg(test_data("sigstore/verification-config.yml"))
        .arg("registry://ghcr.io/kubewarden/tests/capabilities-psp:v0.1.9");

    cmd.assert().failure();
    cmd.assert()
        .stderr(contains("Image verification failed: missing signatures"));
}

#[test]
fn test_verify_keyless() {
    let tempdir = tempdir().unwrap();
    cosign_initialize(tempdir.path());

    let mut cmd = setup_command(tempdir.path());
    cmd.arg("verify")
        .arg("--fulcio-cert-path")
        .arg(".sigstore/root/targets/fulcio.crt.pem")
        .arg("--fulcio-cert-path")
        .arg(".sigstore/root/targets/fulcio_v1.crt.pem")
        .arg("--rekor-public-key-path")
        .arg(".sigstore/root/targets/rekor.pub")
        .arg("--verification-config-path")
        .arg(test_data("sigstore/verification-config.yml"))
        .arg("registry://ghcr.io/kubewarden/tests/capabilities-psp:v0.1.9");

    cmd.assert().failure();
    cmd.assert()
        .stderr(contains("Image verification failed: missing signatures"));
}

#[test]
fn test_verify_scaffolded_verification_config() {
    let tempdir = tempdir().unwrap();
    cosign_initialize(tempdir.path());

    let mut cmd = setup_command(tempdir.path());
    cmd.arg("scaffold").arg("verification-config");
    cmd.assert().success();

    let kubwarden_config_path = Path::new(tempdir.path()).join(".config").join("kubewarden");
    fs::create_dir_all(&kubwarden_config_path).unwrap();

    let verification_config = cmd.output().unwrap().stdout;
    let verification_config_path = Path::new(tempdir.path())
        .join(&kubwarden_config_path)
        .join("verification-config.yml");
    fs::write(&verification_config_path, verification_config).unwrap();

    let mut cmd = setup_command(tempdir.path());
    cmd.arg("verify")
        .arg("--fulcio-cert-path")
        .arg(".sigstore/root/targets/fulcio.crt.pem")
        .arg("--fulcio-cert-path")
        .arg(".sigstore/root/targets/fulcio_v1.crt.pem")
        .arg("--rekor-public-key-path")
        .arg(".sigstore/root/targets/rekor.pub")
        .arg("--verification-config-path")
        .arg(&verification_config_path)
        .arg("registry://ghcr.io/kubewarden/tests/capabilities-psp:v0.1.9");

    cmd.assert().success();
}

#[rstest]
#[case(
    &["sigstore/cosign1.pub"],
    &["env=prod", "stable=true"],
    true,
    contains("Policy successfully verified")
)]
#[case(
    &["sigstore/cosign1.pub", "sigstore/cosign2.pub"],
    &["env=prod"],
    true,
    contains("Policy successfully verified")
)]
#[case::no_keys(
    &[],
    &["env=prod"],
    false,
    contains("Intending to verify annotations, but no verification keys, OIDC issuer or GitHub owner were passed")
)]
#[case::non_existing_key(
    &["non_existing_key.pub"],
    &["env=prod", "stable=true"],
    false,
    contains("No such file or directory")
)]
#[case::missing_signatures(
    &["sigstore/cosign2.pub"],
    &["env=prod", "stable=true"],
    false,
    contains("Image verification failed: missing signatures")
)]
fn test_verify_oci_registry(
    #[case] keys: &[&str],
    #[case] annotations: &[&str],
    #[case] success: bool,
    #[case] predicate: impl PredicateStrExt,
) {
    let tempdir = tempdir().unwrap();
    let mut cmd = setup_command(tempdir.path());

    cmd.arg("verify");
    for annotation in annotations {
        cmd.arg("-a").arg(annotation);
    }
    for key in keys {
        cmd.arg("-k").arg(test_data(key));
    }
    cmd.arg("registry://ghcr.io/kubewarden/tests/pod-privileged:v0.1.9");

    if success {
        cmd.assert().success();
    } else {
        cmd.assert().failure();
    }

    cmd.assert().stderr(predicate);
}

#[rstest]
#[case(
    &["sigstore/cosign1.pub"],
    true,
    contains("Policy successfully verified")
)]
#[case::no_keys(
    &[],
    false,
    contains("Intending to verify annotations, but no verification keys, OIDC issuer or GitHub owner were passed")
)]
#[case::missing_signatures(
    &["sigstore/cosign2.pub"],
    false,contains("Image verification failed: missing signatures")
)]
fn test_pull_signed_policy(
    #[case] keys: &[&str],
    #[case] success: bool,
    #[case] predicate: impl PredicateStrExt,
) {
    let tempdir = tempdir().unwrap();
    let mut cmd = setup_command(tempdir.path());

    cmd.arg("pull")
        .arg("-a")
        .arg("env=prod")
        .arg("-a")
        .arg("stable=true");
    for key in keys {
        cmd.arg("-k").arg(test_data(key));
    }
    cmd.arg("registry://ghcr.io/kubewarden/tests/pod-privileged:v0.1.9");

    if success {
        cmd.assert().success();
    } else {
        cmd.assert().failure();
    }

    cmd.assert().stderr(predicate);
}

#[rstest]
#[case(
    &["sigstore/cosign1.pub", "sigstore/cosign2.pub"],
    true,
    contains("Policy successfully verified")
)]
#[case::wrong_key(
    &["sigstore/cosign1.pub", "sigstore/cosign3.pub"],
    false,
    contains("Image verification failed: missing signatures"))
]
fn test_run_signed_policy(
    #[case] keys: &[&str],
    #[case] success: bool,
    #[case] predicate: impl PredicateStrExt,
) {
    let tempdir = tempdir().unwrap();
    let mut cmd = setup_command(tempdir.path());

    cmd.arg("run")
        .arg("-a")
        .arg("env=prod")
        .arg("--request-path")
        .arg(test_data("privileged-pod.json"));
    for key in keys {
        cmd.arg("-k").arg(test_data(key));
    }
    cmd.arg("registry://ghcr.io/kubewarden/tests/pod-privileged:v0.1.9");

    if success {
        cmd.assert().success();
    } else {
        cmd.assert().failure();
    }

    cmd.assert().stderr(predicate);
}

#[rstest]
#[case(
    "registry://ghcr.io/kubewarden/tests/pod-privileged:v0.1.9",
    true,
    contains("Policy successfully verified")
)]
#[case::missing_signatures(
    "registry://ghcr.io/kubewarden/tests/capabilities-psp:v0.1.9",
    false,
    contains("Image verification failed: missing signatures")
)]
fn test_run_signed_policy_verification_config(
    #[case] uri: &str,
    #[case] success: bool,
    #[case] predicate: impl PredicateStrExt,
) {
    let tempdir = tempdir().unwrap();
    cosign_initialize(tempdir.path());

    let mut cmd = setup_command(tempdir.path());
    cmd.arg("run")
        .arg("--fulcio-cert-path")
        .arg(".sigstore/root/targets/fulcio.crt.pem")
        .arg("--fulcio-cert-path")
        .arg(".sigstore/root/targets/fulcio_v1.crt.pem")
        .arg("--rekor-public-key-path")
        .arg(".sigstore/root/targets/rekor.pub")
        .arg("--verification-config-path")
        .arg(test_data("sigstore/verification-config.yml"))
        .arg("--request-path")
        .arg(test_data("privileged-pod.json"))
        .arg(uri);

    if success {
        cmd.assert().success();
    } else {
        cmd.assert().failure();
    }

    cmd.assert().stderr(predicate);
}
