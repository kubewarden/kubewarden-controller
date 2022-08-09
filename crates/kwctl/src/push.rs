use anyhow::{anyhow, Result};
use policy_evaluator::policy_fetcher::{registry::Registry, sources::Sources};
use policy_evaluator::policy_metadata::Metadata;
use std::{fs, path::PathBuf};

use crate::backend::BackendDetector;

pub(crate) async fn push(
    wasm_path: PathBuf,
    uri: &str,
    sources: Option<&Sources>,
    force: bool,
) -> Result<String> {
    match Metadata::from_path(&wasm_path)? {
        Some(_) => {}
        None => {
            if force {
                let backend_detector = BackendDetector::default();
                if can_be_force_pushed_without_metadata(backend_detector, wasm_path.clone())? {
                    eprintln!("Warning: pushing a non-annotated policy!");
                } else {
                    return Err(anyhow!("Rego policies cannot be pushed without metadata"));
                }
            } else {
                return Err(anyhow!("Cannot push a policy that is not annotated. Use `annotate` command or `push --force`"));
            }
        }
    };

    let policy = fs::read(&wasm_path).map_err(|e| anyhow!("Cannot open policy file: {:?}", e))?;
    Registry::new().push(&policy, uri, sources).await
}

fn can_be_force_pushed_without_metadata(
    backend_detector: BackendDetector,
    wasm_path: PathBuf,
) -> Result<bool> {
    let is_rego = backend_detector
        .is_rego_policy(&wasm_path)
        .map_err(|e| anyhow!("Cannot understand if the policy is based on Rego: {:?}", e))?;

    Ok(!is_rego)
}
