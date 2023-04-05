use anyhow::{anyhow, Result};
use lazy_static::lazy_static;
use policy_evaluator::{
    policy_evaluator::{Evaluator, PolicyExecutionMode},
    policy_evaluator_builder::PolicyEvaluatorBuilder,
    policy_metadata::Metadata,
    ProtocolVersion,
};
use semver::{BuildMetadata, Prerelease, Version};
use std::path::{Path, PathBuf};
lazy_static! {
    static ref KUBEWARDEN_VERSION: Version = Version::parse(env!("CARGO_PKG_VERSION")).unwrap();
}

pub(crate) enum Backend {
    Opa,
    OpaGatekeeper,
    KubewardenWapc(ProtocolVersion),
}

type KubewardenProtocolDetectorFn = fn(PathBuf) -> Result<ProtocolVersion>;
type RegoDetectorFn = fn(PathBuf) -> Result<bool>;

// Looks at the Wasm module pointed by `wasm_path` and return whether it was generaed by a Rego
// policy
//
// The code looks at the export symbols offered by the Wasm module.
// Having at least one symbol that starts with the `opa_` prefix leads
// the policy to be considered a Rego-based one.
fn rego_policy_detector(wasm_path: PathBuf) -> Result<bool> {
    let data: Vec<u8> = std::fs::read(wasm_path)?;
    for payload in wasmparser::Parser::new(0).parse_all(&data) {
        if let wasmparser::Payload::ExportSection(s) = payload? {
            for export in s {
                if export?.name.starts_with("opa_") {
                    return Ok(true);
                }
            }
        }
    }

    Ok(false)
}

fn kubewarden_protocol_detector(wasm_path: PathBuf) -> Result<ProtocolVersion> {
    PolicyEvaluatorBuilder::new("".to_string())
        .policy_file(&wasm_path)?
        .execution_mode(PolicyExecutionMode::KubewardenWapc)
        .build()?
        .protocol_version()
        .map_err(|e| anyhow!("Cannot compute ProtocolVersion used by the policy: {:?}", e))
}

pub(crate) struct BackendDetector {
    kubewarden_protocol_detector_func: KubewardenProtocolDetectorFn,
    rego_detector_func: RegoDetectorFn,
}

impl Default for BackendDetector {
    fn default() -> Self {
        BackendDetector {
            kubewarden_protocol_detector_func: kubewarden_protocol_detector,
            rego_detector_func: rego_policy_detector,
        }
    }
}

impl BackendDetector {
    #[allow(dead_code)]
    /// This method is intended to be used by unit tests
    pub(crate) fn new(
        rego_detector_func: RegoDetectorFn,
        kubewarden_protocol_detector_func: KubewardenProtocolDetectorFn,
    ) -> Self {
        BackendDetector {
            kubewarden_protocol_detector_func,
            rego_detector_func,
        }
    }

    pub(crate) fn is_rego_policy(&self, wasm_path: &Path) -> Result<bool> {
        (self.rego_detector_func)(wasm_path.to_path_buf()).map_err(|e| {
            anyhow!(
                "Error while checking if the policy has been created using Opa/Gatekeeper: {}",
                e
            )
        })
    }

    pub(crate) fn detect(&self, wasm_path: PathBuf, metadata: &Metadata) -> Result<Backend> {
        let is_rego_policy = self.is_rego_policy(&wasm_path)?;
        match metadata.execution_mode {
            PolicyExecutionMode::Opa => {
                if is_rego_policy {
                    Ok(Backend::Opa)
                } else {
                    Err(anyhow!(
                        "Wrong value inside of policy's metatada for 'executionMode'. The policy has not been created using Rego"
                    ))
                }
            }
            PolicyExecutionMode::OpaGatekeeper => {
                if is_rego_policy {
                    Ok(Backend::OpaGatekeeper)
                } else {
                    Err(anyhow!(
                        "Wrong value inside of policy's metatada for 'executionMode'. The policy has not been created using Rego"
                    ))
                }
            }
            PolicyExecutionMode::KubewardenWapc => {
                if is_rego_policy {
                    Err(anyhow!(
                        "Wrong value inside of policy's metatada for 'executionMode'. This policy has been created using Rego"
                    ))
                } else {
                    let protocol_version = (self.kubewarden_protocol_detector_func)(wasm_path)
                        .map_err(|e| {
                            anyhow!("Error while detecting Kubewarden protocol version: {:?}", e)
                        })?;
                    Ok(Backend::KubewardenWapc(protocol_version))
                }
            }
        }
    }
}

/// Check if policy server version is compatible with  minimum kubewarden
/// version required by the policy
pub fn has_minimum_kubewarden_version(opt_metadata: Option<&Metadata>) -> Result<()> {
    if let Some(metadata) = opt_metadata {
        if let Some(minimum_kubewarden_version) = &metadata.minimum_kubewarden_version {
            let sanitized_minimum_kubewarden_version = Version {
                major: minimum_kubewarden_version.major,
                minor: minimum_kubewarden_version.minor,
                // Kubewarden stack version ignore patch version number
                patch: 0,
                pre: Prerelease::EMPTY,
                build: BuildMetadata::EMPTY,
            };
            if *KUBEWARDEN_VERSION < sanitized_minimum_kubewarden_version {
                return Err(anyhow!(
                    "Policy required Kubewarden version {} or greater. But it's running on {}",
                    sanitized_minimum_kubewarden_version,
                    KUBEWARDEN_VERSION.to_string(),
                ));
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mock_protocol_version_detector_v1(_wasm_path: PathBuf) -> Result<ProtocolVersion> {
        Ok(ProtocolVersion::V1)
    }

    fn mock_rego_policy_detector_true(_wasm_path: PathBuf) -> Result<bool> {
        Ok(true)
    }

    fn mock_rego_policy_detector_false(_wasm_path: PathBuf) -> Result<bool> {
        Ok(false)
    }

    #[test]
    fn test_execution_mode_cannot_be_kubewarden_for_a_rego_policy() {
        let metadata = Metadata {
            execution_mode: PolicyExecutionMode::KubewardenWapc,
            ..Default::default()
        };

        let backend_detector = BackendDetector::new(
            mock_rego_policy_detector_true,
            mock_protocol_version_detector_v1,
        );
        let backend = backend_detector.detect(PathBuf::from("irrelevant.wasm"), &metadata);
        assert!(backend.is_err());
    }

    #[test]
    fn test_execution_mode_cannot_be_opa_or_gatekeeper_for_a_kubewarden_policy() {
        for execution_mode in vec![PolicyExecutionMode::Opa, PolicyExecutionMode::OpaGatekeeper] {
            let metadata = Metadata {
                execution_mode,
                ..Default::default()
            };

            let backend_detector = BackendDetector::new(
                mock_rego_policy_detector_false,
                mock_protocol_version_detector_v1,
            );
            let backend = backend_detector.detect(PathBuf::from("irrelevant.wasm"), &metadata);
            assert!(backend.is_err());
        }
    }
}
