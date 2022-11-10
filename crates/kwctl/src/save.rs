use anyhow::Result;
use flate2::write::GzEncoder;
use flate2::Compression;
use policy_evaluator::policy_fetcher::store::{PolicyPath, Store};
use std::fs::File;

// saves all policies in a tarball with the name provided as output.
// policies must be inside the default store.
pub(crate) fn save(images: Vec<&String>, output: &str) -> Result<()> {
    let tar_gz = File::create(output)?;
    let enc = GzEncoder::new(tar_gz, Compression::default());
    let mut tar = tar::Builder::new(enc);

    for image in images {
        let store = Store::default();
        let wasm_path = crate::utils::wasm_path(image.as_str())?;
        let mut file = File::open(wasm_path)?;
        let policy_path = store.policy_path(image, PolicyPath::PrefixAndFilename)?;
        tar.append_file(policy_path, &mut file)?;
    }

    Ok(())
}
