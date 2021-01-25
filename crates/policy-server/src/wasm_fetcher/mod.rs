use anyhow::{anyhow, Result};
use url::Url;
use std::boxed::Box;

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
    "file" => Ok(Box::new(Local::new(parsed_url.path())?)),
    "http" | "https" => Ok(Box::new(Https::new(url.parse::<Url>()?, remote_insecure)?)),
    "registry" => Ok(Box::new(Registry::new(parsed_url, remote_non_tls)?)),
    _ => Err(anyhow!("unknown scheme: {}", parsed_url.scheme())),
  }
}
