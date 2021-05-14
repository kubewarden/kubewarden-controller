use anyhow::{anyhow, Result};
use std::path::PathBuf;
use url::Url;
use wasmparser::{Parser, Payload};

use policy_evaluator::policy_metadata::Metadata;
use policy_fetcher::store::Store;

use crate::constants::KUBEWARDEN_CUSTOM_SECTION_METADATA;

pub(crate) fn inspect(uri: &str) -> Result<()> {
    let url = Url::parse(uri)?;
    let wasm_path = match url.scheme() {
        "file" => url
            .to_file_path()
            .map_err(|err| anyhow!("cannot retrieve path from uri {}: {:?}", url, err)),
        "http" | "https" | "registry" => {
            let policies = Store::default().list()?;
            let policy = policies.iter().find(|policy| policy.uri == uri).ok_or_else(|| anyhow!("Cannot find policy '{uri}' inside of the local store.\nTry executing `kwctl pull {uri}`", uri = uri))?;
            Ok(policy.local_path.clone())
        }
        _ => Err(anyhow!("unknown scheme: {}", url.scheme())),
    }?;

    match get_metadata(wasm_path)? {
        Some(metadata) => {
            let metadata_yaml = serde_yaml::to_string(&metadata)?;
            println!("Metadata:\n{}", metadata_yaml);
            Ok(())
        }
        None => Err(anyhow!(
            "No Kubewarden metadata found inside of '{}'.\nPolicies can be annotated with the `kwctl annotate` command.",
            uri
        )),
    }
}

fn get_metadata(wasm_path: PathBuf) -> Result<Option<Metadata>> {
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
