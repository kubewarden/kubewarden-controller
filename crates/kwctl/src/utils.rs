use anyhow::{anyhow, Result};
use policy_fetcher::store::Store;
use std::path::PathBuf;
use url::Url;

pub(crate) fn wasm_path(uri: &str) -> Result<PathBuf> {
    let url = Url::parse(uri)?;
    match url.scheme() {
        "file" => url
            .to_file_path()
            .map_err(|err| anyhow!("cannot retrieve path from uri {}: {:?}", url, err)),
        "http" | "https" | "registry" => {
            let policies = Store::default().list()?;
            let policy = policies.iter().find(|policy| policy.uri == uri).ok_or_else(|| anyhow!("Cannot find policy '{uri}' inside of the local store.\nTry executing `kwctl pull {uri}`", uri = uri))?;
            Ok(policy.local_path.clone())
        }
        _ => Err(anyhow!("unknown scheme: {}", url.scheme())),
    }
}
