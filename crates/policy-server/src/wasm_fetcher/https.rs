use anyhow::{anyhow, Result};
use async_std::fs::File;
use async_std::prelude::*;
use async_trait::async_trait;
use hyper::{client::HttpConnector, Client, StatusCode};
use hyper_tls::HttpsConnector;
use native_tls::TlsConnector;
use std::{boxed::Box, path::Path};
use url::Url;

use crate::wasm_fetcher::fetcher::Fetcher;

// Struct used to reference a WASM module that is hosted on a HTTP(s) server
pub(crate) struct Https {
    // full path to the WASM module
    destination: String,
    // url of the remote WASM module
    wasm_url: Url,
    // do not verify the remote TLS certificate
    insecure: bool,
}

impl Https {
    // Allocates a LocalWASM instance starting from the user
    // provided URL
    pub(crate) fn new(url: Url, remote_insecure: bool, download_dir: &str) -> Result<Https> {
        let file_name = match url.path().rsplit('/').next() {
            Some(f) => f,
            None => {
                return Err(anyhow!(
                    "Cannot infer name of the remote file by looking at {}",
                    url.path()
                ))
            }
        };

        let dest = Path::new(download_dir).join(file_name);

        Ok(Https {
            destination: String::from(
                dest.to_str()
                    .ok_or_else(|| anyhow!("Cannot build final path destination"))?,
            ),
            wasm_url: url,
            insecure: remote_insecure,
        })
    }
}

#[async_trait]
impl Fetcher for Https {
    async fn fetch(&self) -> Result<String> {
        let mut tls_connector_builder = TlsConnector::builder();
        if self.insecure {
            tls_connector_builder.danger_accept_invalid_certs(true);
        }

        let mut http = HttpConnector::new();
        http.enforce_http(false);
        let tls = tls_connector_builder.build()?;
        let https = HttpsConnector::from((http, tls.into()));
        let client = Client::builder().build::<_, hyper::Body>(https);

        // not well: the hyper-tls connector handles both http and https scheme
        let res = client
            .get(self.wasm_url.clone().into_string().parse()?)
            .await?;
        if res.status() != StatusCode::OK {
            return Err(anyhow!(
                "Error while downloading remote WASM module from {}, got HTTP status {}",
                self.wasm_url,
                res.status()
            ));
        }

        let buf = hyper::body::to_bytes(res).await?;
        let mut file = File::create(self.destination.clone()).await?;
        file.write_all(&buf).await?;

        Ok(self.destination.clone())
    }
}
