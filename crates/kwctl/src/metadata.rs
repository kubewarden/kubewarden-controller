use anyhow::Result;
use policy_evaluator::policy_metadata::Metadata;
use std::path::PathBuf;
use wasmparser::{Parser, Payload};

use crate::constants::KUBEWARDEN_CUSTOM_SECTION_METADATA;

pub(crate) fn get_metadata(wasm_path: PathBuf) -> Result<Option<Metadata>> {
    let mut result: Option<Metadata> = None;
    let buf: Vec<u8> = std::fs::read(wasm_path)?;
    for payload in Parser::new(0).parse_all(&buf) {
        match payload? {
            Payload::CustomSection {
                name,
                data,
                data_offset: _,
                range: _,
            } => {
                if name == KUBEWARDEN_CUSTOM_SECTION_METADATA {
                    let metadata: Metadata = serde_json::from_slice(data)?;
                    result = Some(metadata);
                }
            }
            _other => {}
        }
    }

    Ok(result)
}
