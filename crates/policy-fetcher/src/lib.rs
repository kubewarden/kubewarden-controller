extern crate home;
extern crate walkdir;

use anyhow::{anyhow, Result};
use std::boxed::Box;
use url::Url;

pub mod fetcher;
mod https;
mod local;
pub mod policy;
pub mod registry;
pub mod sources;
pub mod store;

use crate::registry::config::DockerConfig;

use crate::fetcher::Fetcher;
use crate::https::Https;
use crate::local::Local;
use crate::registry::Registry;
use crate::sources::Sources;

use std::path::{Path, PathBuf};

// Helper function, takes the URL of the WASM module and allocates
// the right struct to interact with it
pub(crate) fn url_fetcher(
    url: &str,
    docker_config: Option<DockerConfig>,
    download_dir: &Path,
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
        "file" => Ok(Box::new(Local::new(PathBuf::from(parsed_url.path())))),
        "http" | "https" => Ok(Box::new(Https::new(
            url.parse::<Url>()?,
            download_dir.to_path_buf(),
        )?)),
        "registry" => Ok(Box::new(Registry::new(
            parsed_url,
            docker_config,
            download_dir.to_path_buf(),
        )?)),
        _ => Err(anyhow!("unknown scheme: {}", parsed_url.scheme())),
    }
}

pub async fn fetch_wasm_module(
    url: &str,
    download_dir: &Path,
    docker_config: Option<DockerConfig>,
    sources: &Sources,
) -> Result<PathBuf> {
    let url = Url::parse(url)?;
    let scheme = match url.scheme() {
        "registry" | "http" | "https" => Ok(url.scheme()),
        "file" => return Ok(PathBuf::from(url.path())),
        _ => Err(anyhow!("unknown scheme: {}", url.scheme())),
    }?;
    let host = url.host_str().unwrap_or_default();
    let element_count = url.path().split("/").count();
    let elements = url.path().split("/");
    let path = elements
        .skip(1)
        .take(element_count - 2)
        .collect::<Vec<&str>>()
        .join("/");
    let download_dir = download_dir.join(scheme).join(host).join(path);
    std::fs::create_dir_all(&download_dir)?;
    url_fetcher(url.as_str(), docker_config, &download_dir)?
        .fetch(sources)
        .await
}
