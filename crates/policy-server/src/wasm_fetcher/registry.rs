use anyhow::{anyhow, Result};
use async_std::fs::File;
use async_std::prelude::*;
use async_trait::async_trait;
use oci_distribution::client::{Client, ClientConfig, ClientProtocol};
use oci_distribution::secrets::RegistryAuth;
use oci_distribution::Reference;
use std::{fs, str::FromStr};
use tokio_compat_02::FutureExt;
use url::Url;

use crate::registry::config::{DockerConfig, DockerConfigRaw, RegistryAuth as OwnRegistryAuth};
use crate::wasm_fetcher::fetcher::Fetcher;

// Struct used to reference a WASM module that is hosted on an OCI registry
pub(crate) struct Registry {
    // full path to the WASM module
    destination: String,
    // url of the remote WASM module
    wasm_url: String,
    // whether TLS should be skipped
    skip_tls: bool,
    // configuration resembling `~/.docker/config.json` to some extent
    docker_config: Option<DockerConfig>,
}

impl Registry {
    pub(crate) fn new(
        url: Url,
        skip_tls: bool,
        docker_config_json_path: Option<String>,
    ) -> Result<Registry> {
        match url.path().rsplit('/').next() {
            Some(image_ref) => {
                let wasm_url = url.to_string();
                let docker_config_json_contents =
                    docker_config_json_path.and_then(|docker_config_json_path| {
                        fs::read_to_string(docker_config_json_path).ok()
                    });
                Ok(Registry {
                    destination: image_ref.into(),
                    wasm_url: wasm_url
                        .strip_prefix("registry://")
                        .map_or(Default::default(), |url| url.into()),
                    skip_tls: skip_tls,
                    docker_config: docker_config_json_contents.and_then(|contents| {
                        serde_json::from_str(&contents)
                            .map(|config: DockerConfigRaw| config.into())
                            .ok()
                    }),
                })
            }
            _ => Err(anyhow!(
                "Cannot infer name of the remote file by looking at {}",
                url.path()
            )),
        }
    }

    fn client(&self) -> Client {
        Client::new(self.client_config())
    }

    fn client_config(&self) -> ClientConfig {
        ClientConfig {
            protocol: self.client_protocol(),
        }
    }

    fn client_protocol(&self) -> ClientProtocol {
        if self.skip_tls {
            ClientProtocol::Http
        } else {
            ClientProtocol::Https
        }
    }

    fn auth(&self, registry: &Reference) -> RegistryAuth {
        self.docker_config
            .as_ref()
            .and_then(|docker_config| {
                docker_config
                    .auths
                    .get(registry.registry())
                    .and_then(|auth| {
                        let OwnRegistryAuth::BasicAuth(username, password) = auth;
                        Some(RegistryAuth::Basic(
                            String::from_utf8(username.clone()).unwrap_or_default(),
                            String::from_utf8(password.clone()).unwrap_or_default(),
                        ))
                    })
            })
            .unwrap_or(RegistryAuth::Anonymous)
    }
}

#[async_trait]
impl Fetcher for Registry {
    async fn fetch(&self) -> Result<String> {
        let mut client = self.client();
        let reference = Reference::from_str(self.wasm_url.as_str())?;
        let registry_auth = self.auth(&reference);
        let image_content = client
            .pull(
                &reference,
                &registry_auth,
                vec!["application/vnd.wasm.content.layer.v1+wasm"],
            )
            // We need to call to `compat()` provided by the `tokio-compat-02` crate
            // so that the Future returned by the `oci-distribution` crate can be
            // executed by a newer Tokio runtime.
            .compat()
            .await?
            .layers
            .into_iter()
            .nth(0)
            .and_then(|layer| Some(layer.data))
            .unwrap_or_default();

        let mut file = File::create(self.destination.clone()).await?;
        file.write_all(&image_content[..]).await?;

        Ok(self.destination.clone())
    }
}
