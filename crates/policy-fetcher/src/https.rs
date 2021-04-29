#![allow(clippy::upper_case_acronyms)]

use anyhow::{anyhow, Result};
use async_std::fs::File;
use async_std::prelude::*;
use async_trait::async_trait;
use rustls::Certificate;
use std::{boxed::Box, path::PathBuf};
use url::Url;

use crate::fetcher::Fetcher;
use crate::sources::Sources;

// Struct used to reference a WASM module that is hosted on a HTTP(s) server
pub(crate) struct Https {
    // full path to the WASM module
    destination: PathBuf,
    // url of the remote WASM module
    wasm_url: Url,
}

enum TlsFetchMode {
    CustomCa(Vec<Certificate>),
    SystemCa,
    NoTlsVerification,
}

impl Https {
    // Allocates a LocalWASM instance starting from the user
    // provided URL
    pub(crate) fn new(wasm_url: Url, destination: PathBuf) -> Https {
        Https {
            destination,
            wasm_url,
        }
    }

    async fn fetch_https(&self, tls_fetch_mode: TlsFetchMode) -> Result<PathBuf> {
        let mut client_builder = reqwest::Client::builder().https_only(true);

        match tls_fetch_mode {
            TlsFetchMode::SystemCa => (),
            TlsFetchMode::CustomCa(certificates) => {
                for certificate in certificates {
                    let certificate = reqwest::Certificate::from_pem(certificate.as_ref())
                        .or_else(|_| reqwest::Certificate::from_der(certificate.as_ref()))
                        .map_err(|_| anyhow!("could not import certificate as PEM nor DER"))?;
                    client_builder = client_builder.add_root_certificate(certificate);
                }
            }
            TlsFetchMode::NoTlsVerification => {
                client_builder = client_builder.danger_accept_invalid_certs(true);
            }
        }

        let client = client_builder.build()?;
        let buf = client
            .get(self.wasm_url.as_ref())
            .send()
            .await?
            .bytes()
            .await?;
        let mut file = File::create(self.destination.clone()).await?;
        file.write_all(&buf).await?;

        Ok(self.destination.clone())
    }

    async fn fetch_http(&self) -> Result<PathBuf> {
        let buf = reqwest::get(self.wasm_url.as_ref()).await?.bytes().await?;
        let mut file = File::create(self.destination.clone()).await?;
        file.write_all(&buf).await?;

        Ok(self.destination.clone())
    }
}

#[async_trait]
impl Fetcher for Https {
    async fn fetch(&self, sources: &Sources) -> Result<PathBuf> {
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
                    .fetch_https(TlsFetchMode::CustomCa(host_ca_certificate))
                    .await
                {
                    return Ok(module_contents);
                } else if !sources.is_insecure_source(host) {
                    return Err(anyhow!("could not download Wasm module from {} using provided CA certificate; aborting since host is not set as insecure", self.wasm_url));
                }
            }
            if let Ok(module_contents) = self.fetch_https(TlsFetchMode::SystemCa).await {
                return Ok(module_contents);
            }
            if !sources.is_insecure_source(host) {
                return Err(anyhow!("could not download Wasm module from {} using system CA certificates; aborting since host is not set as insecure", self.wasm_url));
            }
            if let Ok(module_contents) = self.fetch_https(TlsFetchMode::NoTlsVerification).await {
                return Ok(module_contents);
            }
        }

        self.fetch_http().await
    }
}
