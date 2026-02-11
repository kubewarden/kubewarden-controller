#[cfg(feature = "sigstore-testing")]
use common::setup_command;
#[cfg(feature = "sigstore-testing")]
use tempfile::tempdir;

mod common;

/// This test is behind a feature flag because it requires a sigstore testing environment to run
/// properly. In CI this is done by the sigstore/scaffolding/actions/setup action and some
/// additional configuration. Locally, one can use the script and documentation available in the
/// same repository.
///
/// Furthermore, this test expects that there is a policy
/// "registry.local:5000/policies/testing:latest" is signed with cosign in the local sigstore
/// instance. It also expects that the sigstore trust_config.json and verification_config.yaml files
/// are available in the workspace root directory. The trust_config.json file should contain all the
/// information to find the local sigstore instance. It follows the ClientTrustConfig format. See the
/// spec here:
/// https://github.com/sigstore/protobuf-specs/blob/4d38e4482bf67c7ab86bf2f61e8d79010ac0974e/protos/sigstore_trustroot.proto#L341
/// The verification_config.yaml file should contain the verification configuration for the policy,
/// it can be generated using `kwctl scaffold verification-config` command. The verification
/// options in the file should match the way the policy was signed in the local sigstore instance.
/// The test also checks if there is a sources.yaml files. If it exists, it is copied to the temp
/// directory and the command is run with the --sources-path argument.
#[test]
#[cfg(feature = "sigstore-testing")]
fn test_sigstore_trust_config() {
    // Find workspace root by traversing up from CARGO_MANIFEST_DIR
    let manifest_dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let workspace_root = manifest_dir
        .parent()
        .and_then(|p| p.parent())
        .expect("cannot find workspace root");

    let tempdir = tempdir().unwrap();
    let trust_config_file = tempdir.path().join("trust_config.json");
    let source_trust_config = workspace_root.join("trust_config.json");
    std::fs::copy(&source_trust_config, &trust_config_file)
        .expect("cannot copy trust_config.json from the root of the repository");

    let verification_config_file = tempdir.path().join("verification_config.yaml");
    let source_verification_config = workspace_root.join("verification_config.yaml");
    std::fs::copy(&source_verification_config, &verification_config_file)
        .expect("cannot copy verification_config.yaml from the root of the repository");

    let mut cmd = setup_command(tempdir.path());
    cmd.arg("verify")
        .arg("--sigstore-trust-config")
        .arg("trust_config.json")
        .arg("--verification-config-path")
        .arg("verification_config.yaml");

    // if there is a sources.yaml file, the test consider that the registry does not support https
    // request. Therefore, the sources file should be copied to the tempdir as well and the command
    // should be run with the --sources-path argument.
    let source_sources_yaml = workspace_root.join("sources.yaml");
    if source_sources_yaml.exists() {
        let sources_file = tempdir.path().join("sources.yaml");
        std::fs::copy(&source_sources_yaml, &sources_file)
            .expect("cannot copy sources.yaml from the root of the repository");
        cmd.arg("--sources-path").arg("sources.yaml");
    }

    cmd.arg("registry://registry.local:5000/policies/testing:latest");
    cmd.assert().success();
}
