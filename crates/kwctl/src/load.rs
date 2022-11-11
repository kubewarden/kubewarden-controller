use anyhow::{anyhow, Result};
use flate2::read::GzDecoder;
use policy_evaluator::policy_fetcher::store::Store;
use std::fs::File;
use tar::Archive;

// load policies inside the tarball provided by source_path into the default store
pub(crate) fn load(source_path: &str) -> Result<()> {
    let default_store = Store::default();
    let destination_path = default_store.root;
    let tar_gz = File::open(source_path).map_err(|e| anyhow!("cannot open file {}: {}", source_path, e))?;
    let tar = GzDecoder::new(tar_gz);
    let mut archive = Archive::new(tar);
    archive.unpack(destination_path).map_err(|e| anyhow!("cannot unpack file {}: {}", source_path, e))?;

    Ok(())
}
