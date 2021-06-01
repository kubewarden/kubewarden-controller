use anyhow::{anyhow, Result};
use async_std::fs::File;
use async_std::prelude::*;
use async_trait::async_trait;
use oci_distribution::{
    client::{Client, ClientConfig, ClientProtocol, ImageData, ImageLayer},
    manifest,
    secrets::RegistryAuth,
    Reference,
};
use std::{path::Path, str::FromStr};
use tokio_compat_02::FutureExt;
use url::Url;

use crate::fetcher::Fetcher;
use crate::registry::config::{DockerConfig, RegistryAuth as OwnRegistryAuth};
use crate::sources::Sources;

pub mod config;

// Struct used to reference a WASM module that is hosted on an OCI registry
pub struct Registry;

impl Registry {
    fn client(client_protocol: ClientProtocol) -> Client {
        Client::new(ClientConfig {
            protocol: client_protocol,
            ..Default::default()
        })
    }

    fn auth(registry: &str, docker_config: Option<&DockerConfig>) -> RegistryAuth {
        docker_config
            .as_ref()
            .and_then(|docker_config| {
                docker_config.auths.get(registry).map(|auth| {
                    let OwnRegistryAuth::BasicAuth(username, password) = auth;
                    RegistryAuth::Basic(
                        String::from_utf8(username.clone()).unwrap_or_default(),
                        String::from_utf8(password.clone()).unwrap_or_default(),
                    )
                })
            })
            .unwrap_or(RegistryAuth::Anonymous)
    }

    pub async fn push(
        policy: &[u8],
        url: &str,
        docker_config: Option<&DockerConfig>,
        sources: Option<&Sources>,
    ) -> Result<()> {
        let url = Url::parse(url)?;
        let reference =
            Reference::from_str(url.as_ref().strip_prefix("registry://").unwrap_or_default())?;
        let registry_auth = Registry::auth(reference.registry(), docker_config);

        if let Err(err) = Registry::push_tls(policy, &reference, &registry_auth).await {
            let host_and_port = crate::host_and_port(&url)?;
            if sources.map(|sources| sources.is_insecure_source(host_and_port)) != Some(true) {
                return Err(anyhow!("could not push Wasm module: {}", err));
            }
        }

        Registry::push_plain(policy, &reference, &registry_auth).await
    }

    pub async fn pull(
        url: &Url,
        destination: &Path,
        docker_config: Option<&DockerConfig>,
        sources: Option<&Sources>,
    ) -> Result<()> {
        let reference =
            Reference::from_str(url.as_ref().strip_prefix("registry://").unwrap_or_default())?;
        let registry_auth = Registry::auth(reference.registry(), docker_config);

        let mut image_content = Registry::fetch_tls(&reference, &registry_auth).await;
        if let Err(err) = image_content {
            let host_and_port = crate::host_and_port(&url)?;
            if sources.map(|sources| sources.is_insecure_source(host_and_port)) != Some(true) {
                return Err(anyhow!("could not download Wasm module: {}", err));
            }
            image_content = Registry::fetch_plain(&reference, &registry_auth).await;
        }

        match image_content {
            Ok(image_content) => {
                let mut file = File::create(destination).await?;
                file.write_all(&image_content[..]).await?;
                Ok(())
            }
            Err(err) => Err(anyhow!("could not download Wasm module: {}", err)),
        }
    }

    async fn do_push(
        mut client: Client,
        policy: &[u8],
        reference: &Reference,
        registry_auth: &RegistryAuth,
    ) -> Result<()> {
        client
            .push(
                reference,
                &ImageData {
                    layers: vec![ImageLayer::new(
                        policy.to_vec(),
                        manifest::WASM_LAYER_MEDIA_TYPE.to_string(),
                    )],
                    digest: None,
                },
                &b"{}".to_vec(),
                manifest::WASM_CONFIG_MEDIA_TYPE,
                registry_auth,
                None,
            )
            .await?;

        Ok(())
    }

    async fn do_fetch(
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

    async fn push_tls(
        policy: &[u8],
        reference: &Reference,
        registry_auth: &RegistryAuth,
    ) -> Result<()> {
        let https_client = Registry::client(ClientProtocol::Https);
        Registry::do_push(https_client, policy, reference, registry_auth).await
    }

    async fn push_plain(
        policy: &[u8],
        reference: &Reference,
        registry_auth: &RegistryAuth,
    ) -> Result<()> {
        let http_client = Registry::client(ClientProtocol::Http);
        Registry::do_push(http_client, policy, reference, registry_auth).await
    }

    async fn fetch_tls(reference: &Reference, registry_auth: &RegistryAuth) -> Result<Vec<u8>> {
        let https_client = Registry::client(ClientProtocol::Https);
        Registry::do_fetch(https_client, reference, registry_auth).await
    }

    async fn fetch_plain(reference: &Reference, registry_auth: &RegistryAuth) -> Result<Vec<u8>> {
        let http_client = Registry::client(ClientProtocol::Http);
        Registry::do_fetch(http_client, reference, registry_auth).await
    }
}

#[async_trait]
impl Fetcher for Registry {
    async fn fetch(
        &self,
        url: &Url,
        destination: &Path,
        sources: Option<&Sources>,
        docker_config: Option<&DockerConfig>,
    ) -> Result<()> {
        Registry::pull(url, destination, docker_config, sources).await
    }
}
