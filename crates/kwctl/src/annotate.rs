use crate::backend::{Backend, BackendDetector};
use anyhow::{anyhow, Result};
use policy_evaluator::validator::Validate;
use policy_evaluator::{constants::*, policy_metadata::Metadata, ProtocolVersion};
use std::fs::File;
use std::path::PathBuf;

pub(crate) fn write_annotation(
    wasm_path: PathBuf,
    metadata_path: PathBuf,
    destination: PathBuf,
) -> Result<()> {
    let backend_detector = BackendDetector::default();
    let metadata = prepare_metadata(wasm_path.clone(), metadata_path, backend_detector)?;
    write_annotated_wasm_file(wasm_path, destination, metadata)
}

fn prepare_metadata(
    wasm_path: PathBuf,
    metadata_path: PathBuf,
    backend_detector: BackendDetector,
) -> Result<Metadata> {
    let metadata_file =
        File::open(metadata_path).map_err(|e| anyhow!("Error opening metadata file: {}", e))?;
    let mut metadata: Metadata = serde_yaml::from_reader(&metadata_file)
        .map_err(|e| anyhow!("Error unmarshalling metadata {}", e))?;

    let backend = backend_detector.detect(wasm_path, &metadata)?;

    match backend {
        Backend::Opa => metadata.protocol_version = Some(ProtocolVersion::Unknown),
        Backend::OpaGatekeeper => metadata.protocol_version = Some(ProtocolVersion::Unknown),
        Backend::KubewardenWapc(protocol_version) => {
            metadata.protocol_version = Some(protocol_version)
        }
    };

    let mut annotations = metadata.annotations.unwrap_or_default();
    annotations.insert(
        String::from(KUBEWARDEN_ANNOTATION_KWCTL_VERSION),
        String::from(env!("CARGO_PKG_VERSION")),
    );
    metadata.annotations = Some(annotations);

    metadata
        .validate()
        .map_err(|e| anyhow!("Metadata is invalid: {:?}", e))
        .and(Ok(metadata))
}

fn write_annotated_wasm_file(
    input_path: PathBuf,
    output_path: PathBuf,
    metadata: Metadata,
) -> Result<()> {
    let buf: Vec<u8> = std::fs::read(input_path)?;
    let metadata_json = serde_json::to_vec(&metadata)?;

    let mut module = walrus::Module::from_buffer(buf.as_slice())?;

    let custom_section = walrus::RawCustomSection {
        name: String::from(KUBEWARDEN_CUSTOM_SECTION_METADATA),
        data: metadata_json,
    };
    module.customs.add(custom_section);

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

        let raw_metadata = format!(
            r#"
        rules:
        - apiGroups: [""]
          apiVersions: ["v1"]
          resources: ["pods"]
          operations: ["CREATE", "UPDATE"]
        mutating: false
        backgroundAudit: true
        executionMode: kubewarden-wapc
        "#
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
        )?;
        let annotations = metadata.annotations.unwrap();

        assert_eq!(
            annotations.get(KUBEWARDEN_ANNOTATION_KWCTL_VERSION),
            Some(&String::from(env!("CARGO_PKG_VERSION"))),
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
        );
        assert!(metadata.is_ok());
        assert_eq!(
            metadata.unwrap().protocol_version,
            Some(ProtocolVersion::Unknown)
        );

        Ok(())
    }
}
