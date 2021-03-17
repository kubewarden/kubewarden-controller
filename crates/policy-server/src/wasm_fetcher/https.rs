use anyhow::{anyhow, Result};
use async_std::fs::File;
use async_std::prelude::*;
use async_trait::async_trait;
use hyper::{client::HttpConnector, Client, StatusCode};
use hyper_tls::HttpsConnector;
use native_tls::{Certificate, TlsConnector};
use std::{boxed::Box, path::Path};
use url::Url;

use crate::sources::Sources;
use crate::wasm_fetcher::fetcher::Fetcher;

// Struct used to reference a WASM module that is hosted on a HTTP(s) server
pub(crate) struct Https {
    // full path to the WASM module
    destination: String,
    // url of the remote WASM module
    wasm_url: Url,
}

enum TLSFetchMode {
    CustomCA(Certificate),
    SystemCA,
    NoTLSVerification,
}

impl Https {
    // Allocates a LocalWASM instance starting from the user
    // provided URL
    pub(crate) fn new(url: Url, download_dir: &str) -> Result<Https> {
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
        })
    }

    async fn fetch_https(&self, fetch_mode: TLSFetchMode) -> Result<String> {
        let mut tls_connector_builder = TlsConnector::builder();

        match fetch_mode {
            TLSFetchMode::CustomCA(certificate) => {
                tls_connector_builder.add_root_certificate(certificate);
            }
            TLSFetchMode::SystemCA => (),
            TLSFetchMode::NoTLSVerification => {
                tls_connector_builder.danger_accept_invalid_certs(true);
            }
        };

        let mut http = HttpConnector::new();
        http.enforce_http(false);
        let tls = tls_connector_builder.build()?;
        let https = HttpsConnector::from((http, tls.into()));
        let client = Client::builder().build::<_, hyper::Body>(https);

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

    async fn fetch_http(&self) -> Result<String> {
        let http = HttpConnector::new();
        let client = Client::builder().build::<_, hyper::Body>(http);

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

#[async_trait]
impl Fetcher for Https {
    async fn fetch(&self, sources: &Sources) -> Result<String> {
        // 1. If CA's provided, download with provided CA's
        // 2. If no CA's provided, download with system CA's
        //   2.1. If it fails and if insecure is enabled for that host,
        //     2.1.1. Download from HTTPs ignoring certificate errors
        //     2.1.2. Download from HTTP

        if self.wasm_url.scheme() == "https" {
            let host = match self.wasm_url.host_str() {
                Some(host) => Ok(host),
                None => Err(anyhow!("cannot parse URI {}", self.wasm_url)),
            }?;

            if let Some(host_ca_certificate) = sources.source_authority(host) {
                if let Ok(module_contents) = self
                    .fetch_https(TLSFetchMode::CustomCA(host_ca_certificate))
                    .await
                {
                    return Ok(module_contents);
                } else if !sources.is_insecure_source(host) {
                    return Err(anyhow!("could not download Wasm module from {} using provided CA certificate; aborting since host is not set as insecure", self.wasm_url));
                }
            }
            if let Ok(module_contents) = self.fetch_https(TLSFetchMode::SystemCA).await {
                return Ok(module_contents);
            }
            if !sources.is_insecure_source(host) {
                return Err(anyhow!("could not download Wasm module from {} using system CA certificates; aborting since host is not set as insecure", self.wasm_url));
            }
            if let Ok(module_contents) = self.fetch_https(TLSFetchMode::NoTLSVerification).await {
                return Ok(module_contents);
            }
        }

        self.fetch_http().await
    }
}
