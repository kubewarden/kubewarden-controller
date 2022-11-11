use anyhow::{anyhow, Result};
use flate2::write::GzEncoder;
use flate2::Compression;
use policy_evaluator::policy_fetcher::store::{PolicyPath, Store};
use std::fs::File;

// saves all policies in a tarball with the name provided as output.
// policies must be inside the default store.
pub(crate) fn save(policies: Vec<&String>, output: &str) -> Result<()> {
    let tar_gz =
        File::create(output).map_err(|e| anyhow!("cannot create file {}: {}", output, e))?;
    let enc = GzEncoder::new(tar_gz, Compression::default());
    let mut tar = tar::Builder::new(enc);

    for policy in policies {
        let store = Store::default();
        let wasm_path = crate::utils::wasm_path(policy.as_str())
            .map_err(|e| anyhow!("cannot find policy {}: {}", policy, e))?;
        let mut file = File::open(wasm_path)
            .map_err(|e| anyhow!("cannot open policy file {}: {}", policy, e))?;
        let policy_path = store
            .policy_path(policy, PolicyPath::PrefixAndFilename)
            .map_err(|e| anyhow!("cannot find path for policy {}: {}", policy, e))?;
        tar.append_file(policy_path, &mut file)
            .map_err(|e| anyhow!("cannot append policy {} to tar file: {}", policy, e))?;
    }

    Ok(())
}
