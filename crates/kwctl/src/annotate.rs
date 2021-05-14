use anyhow::{anyhow, Result};
use std::fs::File;
use std::path::PathBuf;
use validator::Validate;

use policy_evaluator::policy_evaluator::PolicyEvaluator;
use policy_evaluator::policy_metadata::Metadata;

use crate::constants::KUBEWARDEN_CUSTOM_SECTION_METADATA;

pub(crate) fn write_annotation(
    wasm_path: PathBuf,
    metadata_path: PathBuf,
    destination: PathBuf,
) -> Result<()> {
    let metadata = prepare_metadata(wasm_path.clone(), metadata_path)?;
    write_annotated_wasm_file(wasm_path, destination, metadata)
}

fn prepare_metadata(wasm_path: PathBuf, metadata_path: PathBuf) -> Result<Metadata> {
    let metadata_file = File::open(metadata_path)?;
    let mut metadata: Metadata = serde_yaml::from_reader(&metadata_file)?;

    let policy_evaluator = PolicyEvaluator::new(wasm_path.as_path(), None)?;
    let protocol_version = policy_evaluator
        .protocol_version()
        .map_err(|e| anyhow!("Cannot compute ProtocolVersion used by the policy: {:?}", e))?;

    metadata.protocol_version = Some(protocol_version);

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
