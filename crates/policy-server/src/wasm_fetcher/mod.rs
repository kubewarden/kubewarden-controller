use anyhow::{anyhow, Result};
use hyper::Uri;
use std::boxed::Box;

pub mod fetcher;
mod https;
mod local;

use crate::wasm_fetcher::fetcher::Fetcher;
use crate::wasm_fetcher::https::Https;
use crate::wasm_fetcher::local::Local;

// Helper function, takes the URL of the WASM module and allocates
// the right struct to interact with it
pub(crate) fn parse_wasm_url(
  url: &str,
  remote_insecure: bool,
  remote_non_tls: bool,
) -> Result<Box<dyn Fetcher>> {
  // we have to use url::Url instead of hyper::Uri because the latter one can't
  // parse urls like file://
  let parsed_url = match url::Url::parse(url) {
    Ok(u) => u,
    Err(e) => {
      return Err(anyhow!("Invalid WASI url: {}", e));
    }
  };

  match parsed_url.scheme() {
    "file" => Ok(Box::new(Local::new(parsed_url.path())?)),
    "http" => Ok(Box::new(Https::new(url.parse::<Uri>()?, remote_insecure)?)),
    "https" => Ok(Box::new(Https::new(url.parse::<Uri>()?, remote_insecure)?)),
    _ => Err(anyhow!("unknown scheme: {}", parsed_url.scheme())),
  }
}
