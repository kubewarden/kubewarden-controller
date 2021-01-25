use anyhow::{anyhow, Result};
use async_std::fs::File;
use async_std::prelude::*;
use async_trait::async_trait;
use oci_distribution::Reference;
use oci_distribution::client::{Client, ClientConfig, ClientProtocol};
use oci_distribution::secrets::RegistryAuth;
use std::str::FromStr;
use tokio_compat_02::FutureExt;
use url::Url;

use crate::wasm_fetcher::fetcher::Fetcher;

// Struct used to reference a WASM module that is hosted on an OCI registry
pub(crate) struct Registry {
  // full path to the WASM module
  destination: String,
  // url of the remote WASM module
  wasm_url: String,
  // whether TLS should be skipped
  skip_tls: bool,
}

impl Registry {
    pub(crate) fn new(url: Url, skip_tls: bool) -> Result<Registry> {
        match url.path().rsplit('/').next() {
            Some(image_ref) => {
                let wasm_url = url.to_string();
                Ok(Registry{
                    destination: image_ref.into(),
                    wasm_url: wasm_url
                        .strip_prefix("registry://")
                        .map_or(Default::default(), |url| url.into()),
                    skip_tls: skip_tls,
                })
            },
            None => Err(anyhow!(
                "Cannot infer name of the remote file by looking at {}",
                url.path()
            )),
        }
    }
}

#[async_trait]
impl Fetcher for Registry {
    async fn fetch(&self) -> Result<String> {
        let mut client = Client::new(ClientConfig{
            protocol: if self.skip_tls { ClientProtocol::Http } else { ClientProtocol::Https },
        });
        let reference = Reference::from_str(self.wasm_url.as_str())?;
        let image_content = client
            .pull_image(&reference, &RegistryAuth::Anonymous)
            // We need to call to `compat()` provided by the `tokio-compat-02` crate
            // so that the Future returned by the `oci-distribution` crate can be
            // executed by a newer Tokio runtime.
            .compat()
            .await?
            .content;

        let mut file = File::create(self.destination.clone()).await?;
        file.write_all(&image_content[..]).await?;

        Ok(self.destination.clone())
    }
}
