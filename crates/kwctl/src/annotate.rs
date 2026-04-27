use std::{
    collections::BTreeSet,
    fs::{self, File},
    path::PathBuf,
};

use anyhow::{Result, anyhow};
use policy_evaluator::{
    ProtocolVersion, constants::*, policy_metadata::Metadata, validator::Validate,
};
use tracing::warn;

use crate::{
    backend::{Backend, BackendDetector},
    wasm_scanner,
};

pub(crate) fn write_annotation(
    wasm_path: PathBuf,
    metadata_path: PathBuf,
    destination: PathBuf,
    usage_path: Option<PathBuf>,
) -> Result<()> {
    let usage = usage_path
        .map(|path| {
            fs::read_to_string(path).map_err(|e| anyhow!("Error reading usage file: {}", e))
        })
        .transpose()?;

    let wasm_bytes =
        std::fs::read(&wasm_path).map_err(|e| anyhow!("Error reading wasm file: {}", e))?;

    let mut module = walrus::Module::from_buffer(&wasm_bytes)
        .map_err(|e| anyhow!("Error parsing wasm module: {}", e))?;

    let detected_capabilities =
        wasm_scanner::scan(&module).map_err(|e| anyhow!("Error scanning wasm module: {}", e))?;

    let backend_detector = BackendDetector::default();
    let metadata = prepare_metadata(wasm_path, metadata_path, backend_detector, usage.as_deref())?;
    write_annotated_wasm_file(&mut module, destination, metadata, &detected_capabilities)
}

fn prepare_metadata(
    wasm_path: PathBuf,
    metadata_path: PathBuf,
    backend_detector: BackendDetector,
    usage: Option<&str>,
) -> Result<Metadata> {
    let metadata_file =
        File::open(metadata_path).map_err(|e| anyhow!("Error opening metadata file: {}", e))?;
    let mut metadata: Metadata = serde_yaml::from_reader(&metadata_file)
        .map_err(|e| anyhow!("Error unmarshalling metadata {}", e))?;

    let backend = backend_detector.detect(wasm_path, &metadata)?;

    match backend {
        Backend::Opa | Backend::OpaGatekeeper | Backend::Wasi => {
            metadata.protocol_version = Some(ProtocolVersion::Unknown)
        }
        Backend::KubewardenWapc(protocol_version) => {
            metadata.protocol_version = Some(protocol_version)
        }
    };

    let mut annotations = metadata.annotations.unwrap_or_default();
    annotations.insert(
        String::from(KUBEWARDEN_ANNOTATION_KWCTL_VERSION),
        String::from(env!("CARGO_PKG_VERSION")),
    );
    if let Some(s) = usage {
        annotations.insert(
            String::from(KUBEWARDEN_ANNOTATION_POLICY_USAGE),
            String::from(s),
        );
    }
    metadata.annotations = Some(annotations);

    metadata
        .validate()
        .map_err(|e| anyhow!("Metadata is invalid: {:?}", e))
        .and(Ok(metadata))
}

fn warn_on_capabilities_mismatch(
    detected: &[wasm_scanner::DetectedHostCapability],
    metadata: &Metadata,
) {
    let detected_set: BTreeSet<String> = detected
        .iter()
        .map(|c| format!("{}/{}", c.namespace, c.operation))
        .collect();

    let declared_set: BTreeSet<String> = metadata
        .host_capabilities
        .as_ref()
        .cloned()
        .unwrap_or_default();

    let used_but_undeclared: BTreeSet<&String> = detected_set.difference(&declared_set).collect();
    let declared_but_unused: BTreeSet<&String> = declared_set.difference(&detected_set).collect();

    if !used_but_undeclared.is_empty() {
        warn!(
            capabilities = ?used_but_undeclared,
            "host capabilities used by the policy but not declared in metadata"
        );
    }

    if !declared_but_unused.is_empty() {
        warn!(
            capabilities = ?declared_but_unused,
            "host capabilities declared in metadata but not detected in the policy"
        );
    }
}

fn write_annotated_wasm_file(
    module: &mut walrus::Module,
    output_path: PathBuf,
    metadata: Metadata,
    detected_capabilities: &[wasm_scanner::DetectedHostCapability],
) -> Result<()> {
    warn_on_capabilities_mismatch(detected_capabilities, &metadata);

    let metadata_json = serde_json::to_vec(&metadata)?;

    let custom_section = walrus::RawCustomSection {
        name: String::from(KUBEWARDEN_CUSTOM_SECTION_METADATA),
        data: metadata_json,
    };
    module.customs.add(custom_section);

    // Rewrite the import from `kubewarden:javy/host` to just `host` so that the
    // runtime can provide the right implementation.
    //
    // This is needed to make JavaScript/TypeScript WASI policies work out
    // of the box.
    module.imports.iter_mut().for_each(|import| {
        if let walrus::ImportKind::Function(_) = import.kind
            && import.module == "kubewarden:javy/host"
            && import.name == "call"
        {
            import.module = "host".to_string();
        }
    });

    module.emit_wasm_file(output_path)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::tempdir;

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
    fn test_kwctl_version_is_added_to_already_populated_annotations() -> Result<()> {
        let dir = tempdir()?;

        let file_path = dir.path().join("metadata.yml");
        let mut file = File::create(file_path.clone())?;

        let expected_policy_title = "psp-test";
        let raw_metadata = format!(
            r#"
        rules:
        - apiGroups: [""]
          apiVersions: ["v1"]
          resources: ["pods"]
          operations: ["CREATE", "UPDATE"]
        mutating: false
        backgroundAudit: true
        annotations:
          io.kubewarden.policy.title: {}
        "#,
            expected_policy_title
        );

        write!(file, "{}", raw_metadata)?;

        let backend_detector = BackendDetector::new(
            mock_rego_policy_detector_false,
            mock_protocol_version_detector_v1,
        );
        let metadata = prepare_metadata(
            PathBuf::from("irrelevant.wasm"),
            file_path,
            backend_detector,
            None,
        )?;
        let annotations = metadata.annotations.unwrap();

        assert_eq!(
            annotations.get(KUBEWARDEN_ANNOTATION_POLICY_TITLE),
            Some(&String::from(expected_policy_title))
        );

        assert_eq!(
            annotations.get(KUBEWARDEN_ANNOTATION_KWCTL_VERSION),
            Some(&String::from(env!("CARGO_PKG_VERSION"))),
        );

        Ok(())
    }

    #[test]
    fn test_kwctl_version_is_overwrote_when_user_accidentally_provides_it() -> Result<()> {
        let dir = tempdir()?;

        let file_path = dir.path().join("metadata.yml");
        let mut file = File::create(file_path.clone())?;

        let expected_policy_title = "psp-test";
        let raw_metadata = format!(
            r#"
        rules:
        - apiGroups: [""]
          apiVersions: ["v1"]
          resources: ["pods"]
          operations: ["CREATE", "UPDATE"]
        mutating: false
        backgroundAudit: true
        annotations:
          io.kubewarden.policy.title: {}
          {}: NOT_VALID
        "#,
            expected_policy_title, KUBEWARDEN_ANNOTATION_KWCTL_VERSION,
        );

        write!(file, "{}", raw_metadata)?;

        let backend_detector = BackendDetector::new(
            mock_rego_policy_detector_false,
            mock_protocol_version_detector_v1,
        );
        let metadata = prepare_metadata(
            PathBuf::from("irrelevant.wasm"),
            file_path,
            backend_detector,
            None,
        )?;
        let annotations = metadata.annotations.unwrap();

        assert_eq!(
            annotations.get(KUBEWARDEN_ANNOTATION_POLICY_TITLE),
            Some(&String::from(expected_policy_title))
        );

        assert_eq!(
            annotations.get(KUBEWARDEN_ANNOTATION_KWCTL_VERSION),
            Some(&String::from(env!("CARGO_PKG_VERSION"))),
        );

        Ok(())
    }

    #[test]
    fn test_kwctl_version_is_added_when_annotations_is_none() -> Result<()> {
        let dir = tempdir()?;

        let file_path = dir.path().join("metadata.yml");
        let mut file = File::create(file_path.clone())?;

        let raw_metadata = r#"
        rules:
        - apiGroups: [""]
          apiVersions: ["v1"]
          resources: ["pods"]
          operations: ["CREATE", "UPDATE"]
        mutating: false
        backgroundAudit: true
        executionMode: kubewarden-wapc
        "#;

        write!(file, "{}", raw_metadata)?;

        let backend_detector = BackendDetector::new(
            mock_rego_policy_detector_false,
            mock_protocol_version_detector_v1,
        );
        let metadata = prepare_metadata(
            PathBuf::from("irrelevant.wasm"),
            file_path,
            backend_detector,
            None,
        )?;
        let annotations = metadata.annotations.unwrap();

        assert_eq!(
            annotations.get(KUBEWARDEN_ANNOTATION_KWCTL_VERSION),
            Some(&String::from(env!("CARGO_PKG_VERSION"))),
        );

        Ok(())
    }

    #[test]
    fn test_kwctl_usage_is_added_when_annotations_is_none() -> Result<()> {
        let dir = tempdir()?;

        let file_path = dir.path().join("metadata.yml");
        let mut file = File::create(file_path.clone())?;

        let raw_metadata = r#"
        rules:
        - apiGroups: [""]
          apiVersions: ["v1"]
          resources: ["pods"]
          operations: ["CREATE", "UPDATE"]
        mutating: false
        backgroundAudit: true
        executionMode: kubewarden-wapc
        "#;

        write!(file, "{}", raw_metadata)?;

        let backend_detector = BackendDetector::new(
            mock_rego_policy_detector_false,
            mock_protocol_version_detector_v1,
        );
        let metadata = prepare_metadata(
            PathBuf::from("irrelevant.wasm"),
            file_path,
            backend_detector,
            Some("readme contents"),
        )?;
        let annotations = metadata.annotations.unwrap();

        assert_eq!(
            annotations.get(KUBEWARDEN_ANNOTATION_POLICY_USAGE),
            Some(&String::from("readme contents")),
        );

        Ok(())
    }

    #[test]
    fn test_final_metadata_for_a_rego_policy() -> Result<()> {
        let dir = tempdir()?;

        let file_path = dir.path().join("metadata.yml");
        let mut file = File::create(file_path.clone())?;

        let raw_metadata = String::from(
            r#"
        rules:
        - apiGroups: [""]
          apiVersions: ["v1"]
          resources: ["pods"]
          operations: ["CREATE", "UPDATE"]
        mutating: false
        backgroundAudit: true
        executionMode: opa
        "#,
        );

        write!(file, "{}", raw_metadata)?;

        let backend_detector = BackendDetector::new(
            mock_rego_policy_detector_true,
            mock_protocol_version_detector_v1,
        );
        let metadata = prepare_metadata(
            PathBuf::from("irrelevant.wasm"),
            file_path,
            backend_detector,
            None,
        );
        assert!(metadata.is_ok());
        assert_eq!(
            metadata.unwrap().protocol_version,
            Some(ProtocolVersion::Unknown)
        );

        Ok(())
    }
}
