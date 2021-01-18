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
  let parsed_url = match url.parse::<Uri>() {
    Ok(u) => u,
    Err(e) => {
      return Err(anyhow!("Invalid WASI url: {}", e));
    }
  };

  let scheme = match parsed_url.scheme_str() {
    Some(s) => s,
    None => return Err(anyhow!("Cannot extract scheme from {}", url)),
  };

  match scheme {
    "file" => Ok(Box::new(Local::new(parsed_url)?)),
    "http" => Ok(Box::new(Https::new(parsed_url, remote_insecure)?)),
    "https" => Ok(Box::new(Https::new(parsed_url, remote_insecure)?)),
    _ => Err(anyhow!("unknown scheme: {}", scheme)),
  }
}
