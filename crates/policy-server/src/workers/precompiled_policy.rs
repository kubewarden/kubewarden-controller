use anyhow::{anyhow, Result};
use lazy_static::lazy_static;
use policy_evaluator::{
    policy_evaluator::PolicyExecutionMode, policy_metadata::Metadata, wasmtime,
};
use semver::{BuildMetadata, Prerelease, Version};
use std::{collections::HashMap, fs, path::Path, vec::Vec};

lazy_static! {
    static ref KUBEWARDEN_VERSION: Version = {
        let mut version = Version::parse(env!("CARGO_PKG_VERSION")).expect("Cannot parse CARGO_PKG_VERSION version");
        // Remove the patch, prerelease and build information to avoid rejections
        // like this: v1.6.0-rc4 < v1.6.0
        version.patch = 0;
        version.pre = Prerelease::EMPTY;
        version.build = BuildMetadata::EMPTY;
        version
    };
}

/// This structure holds a precompiled WebAssembly module
/// representing a policy.
///
/// Compiling a WebAssembly module is an expensive operation. Each
/// worker thread needs to do that, for each policy defined by the user.
///
/// Precompiling the policies ahead of time reduces the bootstrap time by a lot.
///
/// **Warning:** when "rehydrating" the module, you have to use a `wasmtime::Engine`
/// that has been created with the same `wasmtime::Config` used at compilation time.
#[derive(Clone)]
pub(crate) struct PrecompiledPolicy {
    /// A precompiled [`wasmtime::Module`]
    pub precompiled_module: Vec<u8>,

    /// The execution mode of the policy
    pub execution_mode: PolicyExecutionMode,
}

impl PrecompiledPolicy {
    /// Load a WebAssembly module from the disk and compiles it
    pub fn new(engine: &wasmtime::Engine, wasm_module_path: &Path) -> Result<Self> {
        let policy_contents = fs::read(wasm_module_path)?;
        let policy_metadata = Metadata::from_contents(&policy_contents)?;
        let metadata = policy_metadata.unwrap_or_default();
        let execution_mode = metadata.execution_mode;
        has_minimum_kubewarden_version(&metadata)?;

        let precompiled_module = engine.precompile_module(&policy_contents)?;

        Ok(Self {
            precompiled_module,
            execution_mode,
        })
    }
}

/// A dictionary with:
/// * Key: the URL of the WebAssembly module
/// * value: the PrecompiledPolicy
pub(crate) type PrecompiledPolicies = HashMap<String, PrecompiledPolicy>;

/// Check if policy server version is compatible with  minimum kubewarden
/// version required by the policy
fn has_minimum_kubewarden_version(metadata: &Metadata) -> Result<()> {
    if let Some(minimum_kubewarden_version) = &metadata.minimum_kubewarden_version {
        let sanitized_minimum_kubewarden_version = Version {
            major: minimum_kubewarden_version.major,
            minor: minimum_kubewarden_version.minor,
            // Kubewarden stack version ignore patch, prerelease and build version numbers
            patch: 0,
            pre: Prerelease::EMPTY,
            build: BuildMetadata::EMPTY,
        };
        if *KUBEWARDEN_VERSION < sanitized_minimum_kubewarden_version {
            return Err(anyhow!(
                "Policy required Kubewarden version {} but is running on {}",
                sanitized_minimum_kubewarden_version,
                KUBEWARDEN_VERSION.to_string(),
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    fn generate_metadata(major: u64, minor: u64, patch: u64) -> Metadata {
        let minimum_kubewarden_version = Version {
            major,
            minor,
            patch,
            pre: Prerelease::EMPTY,
            build: BuildMetadata::EMPTY,
        };
        Metadata {
            minimum_kubewarden_version: Some(minimum_kubewarden_version),
            ..Default::default()
        }
    }

    #[rstest]
    #[case(generate_metadata(KUBEWARDEN_VERSION.major -1, KUBEWARDEN_VERSION.minor, KUBEWARDEN_VERSION.patch))]
    #[case(generate_metadata(KUBEWARDEN_VERSION.major, KUBEWARDEN_VERSION.minor - 1, KUBEWARDEN_VERSION.patch))]
    fn recent_kubewarden_versions_test(#[case] metadata: Metadata) {
        assert!(has_minimum_kubewarden_version(&metadata).is_ok())
    }

    #[rstest]
    #[case(generate_metadata(KUBEWARDEN_VERSION.major +1, KUBEWARDEN_VERSION.minor, KUBEWARDEN_VERSION.patch))]
    #[case(generate_metadata(KUBEWARDEN_VERSION.major, KUBEWARDEN_VERSION.minor + 1, KUBEWARDEN_VERSION.patch))]
    fn old_kubewarden_versions_test(#[case] metadata: Metadata) {
        assert!(has_minimum_kubewarden_version(&metadata).is_err())
    }

    #[test]
    fn no_mininum_kubewarden_version_is_valid_test() {
        let metadata = Metadata {
            minimum_kubewarden_version: None,
            ..Default::default()
        };
        assert!(has_minimum_kubewarden_version(&metadata).is_ok())
    }

    #[rstest]
    #[case(generate_metadata(KUBEWARDEN_VERSION.major, KUBEWARDEN_VERSION.minor, KUBEWARDEN_VERSION.patch + 1))]
    fn ignore_patch_version_test(#[case] metadata: Metadata) {
        assert!(has_minimum_kubewarden_version(&metadata).is_ok())
    }
}
