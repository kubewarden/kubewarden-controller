use anyhow::{anyhow, Result};

pub(crate) fn inspect(uri: &str) -> Result<()> {
    let wasm_path = crate::utils::wasm_path(uri)?;

    match crate::metadata::get_metadata(wasm_path)? {
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
