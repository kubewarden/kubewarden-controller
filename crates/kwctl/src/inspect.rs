use anyhow::{anyhow, Result};
use policy_evaluator::policy_metadata::Metadata;

pub(crate) fn inspect(uri: &str) -> Result<()> {
    let wasm_path = crate::utils::wasm_path(uri)?;

    match Metadata::from_path(&wasm_path)? {
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
