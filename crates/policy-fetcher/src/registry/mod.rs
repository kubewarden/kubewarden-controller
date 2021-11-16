use anyhow::{anyhow, Result};
use async_std::fs::File;
use async_std::prelude::*;
use async_trait::async_trait;
use oci_distribution::{
    client::{
        Certificate as OciCertificate, CertificateEncoding, Client, ClientConfig,
        ClientProtocol as OciClientProtocol, ImageData, ImageLayer,
    },
    manifest,
    secrets::RegistryAuth,
    Reference,
};
use std::{convert::From, path::Path, str::FromStr};
use url::Url;

use crate::fetcher::{ClientProtocol, PolicyFetcher, TlsVerificationMode};
use crate::registry::config::{DockerConfig, RegistryAuth as OwnRegistryAuth};
use crate::sources::{Certificate, Sources};

pub mod config;

// Struct used to reference a WASM module that is hosted on an OCI registry
#[derive(Default)]
pub struct Registry {
    docker_config: Option<DockerConfig>,
}

impl From<&Certificate> for OciCertificate {
    fn from(certificate: &Certificate) -> OciCertificate {
        match certificate {
            Certificate::Der(certificate) => OciCertificate {
                encoding: CertificateEncoding::Der,
                data: certificate.clone(),
            },
            Certificate::Pem(certificate) => OciCertificate {
                encoding: CertificateEncoding::Pem,
                data: certificate.clone(),
            },
        }
    }
}

impl From<ClientProtocol> for OciClientProtocol {
    fn from(client_protocol: ClientProtocol) -> OciClientProtocol {
        match client_protocol {
            ClientProtocol::Http => OciClientProtocol::Http,
            ClientProtocol::Https(_) => OciClientProtocol::Https,
        }
    }
}

impl From<ClientProtocol> for ClientConfig {
    fn from(client_protocol: ClientProtocol) -> ClientConfig {
        match client_protocol {
            ClientProtocol::Http => ClientConfig {
                protocol: client_protocol.into(),
                ..Default::default()
            },
            ClientProtocol::Https(ref tls_fetch_mode) => {
                let mut client_config = ClientConfig {
                    protocol: client_protocol.clone().into(),
                    ..Default::default()
                };

                match tls_fetch_mode {
                    TlsVerificationMode::SystemCa => {}
                    TlsVerificationMode::CustomCaCertificates(certificates) => {
                        client_config.extra_root_certificates =
                            certificates.iter().map(OciCertificate::from).collect();
                    }
                    TlsVerificationMode::NoTlsVerification => {
                        client_config.accept_invalid_certificates = true;
                        client_config.accept_invalid_hostnames = true;
                    }
                };

                client_config
            }
        }
    }
}

impl Registry {
    pub fn new(docker_config: Option<&DockerConfig>) -> Registry {
        Registry {
            docker_config: docker_config.map(|dc| dc.clone()),
        }
    }

    fn client(client_protocol: ClientProtocol) -> Client {
        Client::new(client_protocol.into())
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

    /// Fetch the manifest of the OCI object referenced by the given url.
    /// The url is expected to be in the "registry://" format.
    pub async fn manifest(
        &self,
        url: &str,
        sources: Option<&Sources>,
    ) -> Result<oci_distribution::manifest::OciManifest> {
        let url = Url::parse(url).map_err(|_| anyhow!("invalid URL: {}", url))?;
        let reference =
            Reference::from_str(url.as_ref().strip_prefix("registry://").unwrap_or_default())?;

        let registry_auth = Registry::auth(reference.registry(), self.docker_config.as_ref());
        let sources: Sources = sources.map(|s| s.clone()).unwrap_or_default();
        let cp = crate::client_protocol(&url, &sources)?;

        let (m, _) = Registry::client(cp)
            .pull_manifest(&reference, &registry_auth)
            .await?;

        Ok(m)
    }

    pub async fn push(&self, policy: &[u8], url: &str, sources: Option<&Sources>) -> Result<()> {
        let url = Url::parse(url).map_err(|_| anyhow!("invalid URL: {}", url))?;
        let sources: Sources = sources.map(|s| s.clone()).unwrap_or_default();

        match self
            .do_push(policy, &url, crate::client_protocol(&url, &sources)?)
            .await
        {
            Ok(_) => return Ok(()),
            Err(err) => {
                if !sources.is_insecure_source(&crate::host_and_port(&url)?) {
                    return Err(anyhow!("could not push policy: {}", err,));
                }
            }
        }

        if self
            .do_push(
                policy,
                &url,
                ClientProtocol::Https(TlsVerificationMode::NoTlsVerification),
            )
            .await
            .is_ok()
        {
            return Ok(());
        }

        self.do_push(policy, &url, ClientProtocol::Http)
            .await
            .map_err(|_| anyhow!("could not push policy"))
    }

    async fn do_push(
        &self,
        policy: &[u8],
        url: &Url,
        client_protocol: ClientProtocol,
    ) -> Result<()> {
        let reference =
            Reference::from_str(url.as_ref().strip_prefix("registry://").unwrap_or_default())?;

        let registry_auth = Registry::auth(reference.registry(), self.docker_config.as_ref());

        Registry::client(client_protocol)
            .push(
                &reference,
                &ImageData {
                    layers: vec![ImageLayer::new(
                        policy.to_vec(),
                        manifest::WASM_LAYER_MEDIA_TYPE.to_string(),
                    )],
                    digest: None,
                },
                &b"{}".to_vec(),
                manifest::WASM_CONFIG_MEDIA_TYPE,
                &registry_auth,
                None,
            )
            .await
            .map(|_| ())
            .map_err(|e| anyhow!("could not push policy: {}", e))
    }
}

#[async_trait]
impl PolicyFetcher for Registry {
    async fn fetch(
        &self,
        url: &Url,
        client_protocol: ClientProtocol,
        destination: &Path,
    ) -> Result<()> {
        let reference =
            Reference::from_str(url.as_ref().strip_prefix("registry://").unwrap_or_default())?;

        let image_content = Registry::client(client_protocol)
            .pull(
                &reference,
                &Registry::auth(&crate::host_and_port(url)?, self.docker_config.as_ref()),
                vec![manifest::WASM_LAYER_MEDIA_TYPE],
            )
            .await?
            .layers
            .into_iter()
            .next()
            .map(|layer| layer.data);

        match image_content {
            Some(image_content) => {
                let mut file = File::create(destination).await?;
                file.write_all(&image_content[..]).await?;
                Ok(())
            }
            None => Err(anyhow!("could not pull policy {}", url)),
        }
    }
}
