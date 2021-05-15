#![allow(clippy::upper_case_acronyms)]

use anyhow::{anyhow, Result};
use async_std::fs::File;
use async_std::prelude::*;
use async_trait::async_trait;
use rustls::Certificate;
use std::{boxed::Box, path::Path};
use url::Url;

use crate::fetcher::Fetcher;
use crate::registry::config::DockerConfig;
use crate::sources::Sources;

// Struct used to reference a WASM module that is hosted on a HTTP(s) server
pub(crate) struct Https;

enum TlsFetchMode {
    CustomCa(Vec<Certificate>),
    SystemCa,
    NoTlsVerification,
}

impl Https {
    async fn fetch_https(
        &self,
        url: &Url,
        tls_fetch_mode: TlsFetchMode,
        destination: &Path,
    ) -> Result<()> {
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
        let buf = client.get(url.as_ref()).send().await?.bytes().await?;
        let mut file = File::create(destination).await?;
        file.write_all(&buf).await?;

        Ok(())
    }

    async fn fetch_http(&self, url: &Url, destination: &Path) -> Result<()> {
        let buf = reqwest::get(url.as_ref()).await?.bytes().await?;
        let mut file = File::create(destination).await?;
        file.write_all(&buf).await?;

        Ok(())
    }
}

#[async_trait]
impl Fetcher for Https {
    async fn fetch(
        &self,
        url: &Url,
        destination: &Path,
        sources: Option<&Sources>,
        _docker_config: Option<&DockerConfig>,
    ) -> Result<()> {
        // 1. If CA's provided, download with provided CA's
        // 2. If no CA's provided, download with system CA's
        //   2.1. If it fails and if insecure is enabled for that host,
        //     2.1.1. Download from HTTPs ignoring certificate errors
        //     2.1.2. Download from HTTP

        if url.scheme() == "https" {
            let host_and_port = crate::host_and_port(&url)?;

            if let Some(host_ca_certificate) =
                sources.and_then(|sources| sources.source_authority(&host_and_port))
            {
                if let Ok(module_contents) = self
                    .fetch_https(
                        url,
                        TlsFetchMode::CustomCa(host_ca_certificate),
                        destination,
                    )
                    .await
                {
                    return Ok(module_contents);
                } else if sources.map(|sources| sources.is_insecure_source(&host_and_port))
                    != Some(true)
                {
                    return Err(anyhow!("could not download Wasm module from {} using provided CA certificate; aborting since host is not set as insecure", url));
                }
            }

            if let Ok(module_contents) = self
                .fetch_https(url, TlsFetchMode::SystemCa, destination)
                .await
            {
                return Ok(module_contents);
            }

            if sources.map(|sources| sources.is_insecure_source(&host_and_port)) != Some(true) {
                return Err(anyhow!("could not download Wasm module from {} using system CA certificates; aborting since host is not set as insecure", url));
            }

            if let Ok(module_contents) = self
                .fetch_https(url, TlsFetchMode::NoTlsVerification, destination)
                .await
            {
                return Ok(module_contents);
            }
        }

        self.fetch_http(url, destination).await
    }
}
