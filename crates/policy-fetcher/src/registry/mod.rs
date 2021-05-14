use anyhow::{anyhow, Result};
use async_std::fs::File;
use async_std::prelude::*;
use async_trait::async_trait;
use oci_distribution::{
    client::{Client, ClientConfig, ClientProtocol},
    manifest,
    secrets::RegistryAuth,
    Reference,
};
use std::{path::PathBuf, str::FromStr};
use tokio_compat_02::FutureExt;
use url::Url;

use crate::fetcher::Fetcher;
use crate::registry::config::{DockerConfig, RegistryAuth as OwnRegistryAuth};
use crate::sources::Sources;

pub mod config;

// Struct used to reference a WASM module that is hosted on an OCI registry
pub(crate) struct Registry {
    // full path to the WASM module
    destination: PathBuf,
    // url of the remote WASM module
    url: Url,
    // configuration resembling `~/.docker/config.json` to some extent
    docker_config: Option<DockerConfig>,
}

impl Registry {
    pub(crate) fn new(
        url: Url,
        docker_config: Option<DockerConfig>,
        destination: PathBuf,
    ) -> Registry {
        Registry {
            destination,
            url,
            docker_config,
        }
    }

    fn client(&self, client_protocol: ClientProtocol) -> Client {
        Client::new(ClientConfig {
            protocol: client_protocol,
        })
    }

    fn auth(&self, registry: &Reference) -> RegistryAuth {
        self.docker_config
            .as_ref()
            .and_then(|docker_config| {
                docker_config.auths.get(registry.registry()).map(|auth| {
                    let OwnRegistryAuth::BasicAuth(username, password) = auth;
                    RegistryAuth::Basic(
                        String::from_utf8(username.clone()).unwrap_or_default(),
                        String::from_utf8(password.clone()).unwrap_or_default(),
                    )
                })
            })
            .unwrap_or(RegistryAuth::Anonymous)
    }
}

impl Registry {
    async fn do_fetch(
        &self,
        mut client: Client,
        reference: &Reference,
        registry_auth: &RegistryAuth,
    ) -> Result<Vec<u8>> {
        client
            .pull(
                reference,
                registry_auth,
                vec![manifest::WASM_LAYER_MEDIA_TYPE],
            )
            // We need to call to `compat()` provided by the `tokio-compat-02` crate
            // so that the Future returned by the `oci-distribution` crate can be
            // executed by a newer Tokio runtime.
            .compat()
            .await?
            .layers
            .into_iter()
            .next()
            .map(|layer| layer.data)
            .ok_or_else(|| anyhow!("could not download WASM module"))
    }

    async fn fetch_tls(
        &self,
        reference: &Reference,
        registry_auth: &RegistryAuth,
    ) -> Result<Vec<u8>> {
        let https_client = self.client(ClientProtocol::Https);
        self.do_fetch(https_client, reference, registry_auth).await
    }

    async fn fetch_plain(
        &self,
        reference: &Reference,
        registry_auth: &RegistryAuth,
    ) -> Result<Vec<u8>> {
        let http_client = self.client(ClientProtocol::Http);
        self.do_fetch(http_client, reference, registry_auth).await
    }
}

#[async_trait]
impl Fetcher for Registry {
    async fn fetch(&self, sources: &Sources) -> Result<PathBuf> {
        let reference = Reference::from_str(
            self.url
                .as_ref()
                .strip_prefix("registry://")
                .unwrap_or_default(),
        )?;
        let registry_auth = self.auth(&reference);

        let mut image_content = self.fetch_tls(&reference, &registry_auth).await;
        if let Err(err) = image_content {
            if !sources
                .is_insecure_source(self.url.host_str().ok_or_else(|| anyhow!("invalid host"))?)
            {
                return Err(anyhow!("could not download Wasm module: {}", err));
            }
            image_content = self.fetch_plain(&reference, &registry_auth).await;
        }

        match image_content {
            Ok(image_content) => {
                let mut file = File::create(self.destination.clone()).await?;
                file.write_all(&image_content[..]).await?;
                Ok(self.destination.clone())
            }
            Err(err) => Err(anyhow!("could not download Wasm module: {}", err)),
        }
    }
}
