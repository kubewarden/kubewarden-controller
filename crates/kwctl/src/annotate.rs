use anyhow::{anyhow, Result};
use kubewarden_policy_sdk::metadata::ProtocolVersion;
use policy_evaluator::{
    constants::KUBEWARDEN_CUSTOM_SECTION_METADATA, policy_evaluator::PolicyEvaluator,
    policy_metadata::Metadata,
};
use std::fs::File;
use std::path::PathBuf;
use validator::Validate;

use crate::constants;

pub(crate) fn write_annotation(
    wasm_path: PathBuf,
    metadata_path: PathBuf,
    destination: PathBuf,
) -> Result<()> {
    let metadata = prepare_metadata(wasm_path.clone(), metadata_path, protocol_detector)?;
    write_annotated_wasm_file(wasm_path, destination, metadata)
}

fn protocol_detector(wasm_path: PathBuf) -> Result<ProtocolVersion> {
    let policy_evaluator = PolicyEvaluator::new(wasm_path.as_path(), None)?;
    policy_evaluator
        .protocol_version()
        .map_err(|e| anyhow!("Cannot compute ProtocolVersion used by the policy: {:?}", e))
}

fn prepare_metadata(
    wasm_path: PathBuf,
    metadata_path: PathBuf,
    detect_protocol_func: impl Fn(PathBuf) -> Result<ProtocolVersion>,
) -> Result<Metadata> {
    let metadata_file = File::open(metadata_path)?;
    let mut metadata: Metadata = serde_yaml::from_reader(&metadata_file)?;

    let protocol_version = detect_protocol_func(wasm_path)?;

    metadata.protocol_version = Some(protocol_version);

    let mut annotations = metadata.annotations.unwrap_or_default();
    annotations.insert(
        String::from(constants::ANNOTATION_KWCTL_VERSION),
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
        annotations:
          io.kubewarden.policy.title: {}
        "#,
            expected_policy_title
        );

        write!(file, "{}", raw_metadata)?;

        let metadata = prepare_metadata(
            PathBuf::from("irrelevant.wasm"),
            file_path,
            mock_protocol_version_detector_v1,
        )?;
        let annotations = metadata.annotations.unwrap();

        assert_eq!(
            annotations.get(crate::constants::ANNOTATION_POLICY_TITLE),
            Some(&String::from(expected_policy_title))
        );

        assert_eq!(
            annotations.get(crate::constants::ANNOTATION_KWCTL_VERSION),
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
        annotations:
          io.kubewarden.policy.title: {}
          {}: NOT_VALID
        "#,
            expected_policy_title,
            crate::constants::ANNOTATION_KWCTL_VERSION,
        );

        write!(file, "{}", raw_metadata)?;

        let metadata = prepare_metadata(
            PathBuf::from("irrelevant.wasm"),
            file_path,
            mock_protocol_version_detector_v1,
        )?;
        let annotations = metadata.annotations.unwrap();

        assert_eq!(
            annotations.get(crate::constants::ANNOTATION_POLICY_TITLE),
            Some(&String::from(expected_policy_title))
        );

        assert_eq!(
            annotations.get(crate::constants::ANNOTATION_KWCTL_VERSION),
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
        "#
        );

        write!(file, "{}", raw_metadata)?;

        let metadata = prepare_metadata(
            PathBuf::from("irrelevant.wasm"),
            file_path,
            mock_protocol_version_detector_v1,
        )?;
        let annotations = metadata.annotations.unwrap();

        assert_eq!(
            annotations.get(crate::constants::ANNOTATION_KWCTL_VERSION),
            Some(&String::from(env!("CARGO_PKG_VERSION"))),
        );

        Ok(())
    }
}
