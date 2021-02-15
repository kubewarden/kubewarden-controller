use anyhow::{anyhow, Result};
use std::boxed::Box;
use url::Url;

pub mod fetcher;
mod https;
mod local;
mod registry;

use crate::wasm_fetcher::fetcher::Fetcher;
use crate::wasm_fetcher::https::Https;
use crate::wasm_fetcher::local::Local;
use crate::wasm_fetcher::registry::Registry;

// Helper function, takes the URL of the WASM module and allocates
// the right struct to interact with it
pub(crate) fn parse_wasm_url(
    url: &str,
    remote_insecure: bool,
    remote_non_tls: bool,
    docker_config_json_path: Option<String>,
    download_dir: &str,
) -> Result<Box<dyn Fetcher>> {
    // we have to use url::Url instead of hyper::Uri because the latter one can't
    // parse urls like file://
    let parsed_url: Url = match url::Url::parse(url) {
        Ok(u) => u,
        Err(e) => {
            return Err(anyhow!("Invalid WASI url: {}", e));
        }
    };

    match parsed_url.scheme() {
        "file" => Ok(Box::new(Local::new(parsed_url.path()))),
        "http" | "https" => Ok(Box::new(Https::new(
            url.parse::<Url>()?,
            remote_insecure,
            download_dir,
        )?)),
        "registry" => Ok(Box::new(Registry::new(
            parsed_url,
            remote_non_tls,
            docker_config_json_path,
            download_dir,
        )?)),
        _ => Err(anyhow!("unknown scheme: {}", parsed_url.scheme())),
    }
}

pub(crate) async fn fetch_wasm_module(
    url: &str,
    download_dir: &str,
    docker_config_json_path: Option<String>,
) -> Result<String> {
    parse_wasm_url(&url, false, false, docker_config_json_path, download_dir)?
        .fetch()
        .await
}
