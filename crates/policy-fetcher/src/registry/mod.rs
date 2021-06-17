use anyhow::{anyhow, Result};
use async_std::fs::File;
use async_std::prelude::*;
use async_trait::async_trait;
use oci_distribution::{
    client::{
        Certificate, CertificateEncoding, Client, ClientConfig,
        ClientProtocol as OciClientProtocol, ImageData, ImageLayer,
    },
    manifest,
    secrets::RegistryAuth,
    Reference,
};
use std::{convert::From, path::Path, str::FromStr};
use url::Url;

use crate::fetcher::Fetcher;
use crate::registry::config::{DockerConfig, RegistryAuth as OwnRegistryAuth};
use crate::sources::Sources;

pub mod config;

// Struct used to reference a WASM module that is hosted on an OCI registry
pub struct Registry;

#[derive(Default)]
struct TLSVerificationSettings {
    insecure: bool,
    extra_root_certificates: Vec<Certificate>,
}

enum ClientProtocol {
    Http,
    Https(TLSVerificationSettings),
}

impl From<&ClientProtocol> for OciClientProtocol {
    fn from(client_protocol: &ClientProtocol) -> OciClientProtocol {
        match client_protocol {
            ClientProtocol::Http => OciClientProtocol::Http,
            ClientProtocol::Https(_) => OciClientProtocol::Https,
        }
    }
}

impl From<&ClientProtocol> for ClientConfig {
    fn from(client_protocol: &ClientProtocol) -> ClientConfig {
        match client_protocol {
            ClientProtocol::Http => ClientConfig {
                protocol: client_protocol.into(),
                ..Default::default()
            },
            ClientProtocol::Https(verification_settings) => ClientConfig {
                protocol: client_protocol.into(),
                accept_invalid_hostnames: verification_settings.insecure,
                accept_invalid_certificates: verification_settings.insecure,
                extra_root_certificates: verification_settings.extra_root_certificates.clone(),
            },
        }
    }
}

impl Registry {
    fn client(client_protocol: &ClientProtocol) -> Client {
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

        // First we try to push to the registry using TLS
        if let Err(err) = Registry::push_tls(policy, &reference, &registry_auth, sources).await {
            if let Some(sources) = sources {
                if !sources.is_insecure_source(reference.registry()) {
                    // Push failed, plus the registry is not marked as "insecure" -> time to bubble up
                    // the error
                    return Err(anyhow!("could not push policy: {}", err));
                }
            } else {
                // Push failed, plus the registry is not marked as "insecure" -> time to bubble up
                // the error
                return Err(anyhow!("could not push policy: {}", err));
            }
        } else {
            return Ok(());
        }

        // We are here because pushing to the registry using TLS didn't work,
        // but the registry is marked as insecure. We will do one last attempt
        // and push over plain HTTP
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

        let image_content = match Registry::fetch_tls(&reference, &registry_auth, sources).await {
            Ok(image_content) => Ok(image_content),
            Err(err) => {
                if sources.map(|sources| sources.is_insecure_source(reference.registry()))
                    != Some(true)
                {
                    return Err(anyhow!("could not pull policy: {}; not retrying in unsafe mode because registry {} is not insecure", err, reference.registry()));
                }
                Registry::fetch_plain(&reference, &registry_auth).await
            }
        };

        match image_content {
            Ok(image_content) => {
                let mut file = File::create(destination).await?;
                file.write_all(&image_content[..]).await?;
                Ok(())
            }
            Err(err) => Err(anyhow!("could not pull policy: {}", err)),
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
            .await
            .map_err(|e| anyhow!("could not push policy due to error: {}", e))?;

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
            .await?
            .layers
            .into_iter()
            .next()
            .map(|layer| layer.data)
            .ok_or_else(|| anyhow!("could not pull policy"))
    }

    fn custom_root_certificates(
        reference: &Reference,
        sources: Option<&Sources>,
    ) -> Vec<Certificate> {
        match sources {
            Some(sources) => {
                if let Some(custom_certificate_authority_chain) =
                    sources.source_authority(reference.registry())
                {
                    custom_certificate_authority_chain
                        .iter()
                        .map(|certificate| Certificate {
                            encoding: CertificateEncoding::Pem,
                            data: certificate.0.clone(),
                        })
                        .collect()
                } else {
                    Vec::new()
                }
            }
            None => Vec::new(),
        }
    }

    async fn push_tls(
        policy: &[u8],
        reference: &Reference,
        registry_auth: &RegistryAuth,
        sources: Option<&Sources>,
    ) -> Result<()> {
        let https_client = Registry::client(&ClientProtocol::Https(TLSVerificationSettings {
            insecure: false,
            extra_root_certificates: Registry::custom_root_certificates(reference, sources),
        }));
        if Registry::do_push(https_client, policy, reference, registry_auth)
            .await
            .is_ok()
        {
            return Ok(());
        }

        if let Some(sources) = sources {
            if sources.is_insecure_source(reference.registry()) {
                let https_client =
                    Registry::client(&ClientProtocol::Https(TLSVerificationSettings {
                        insecure: true,
                        ..Default::default()
                    }));

                if Registry::do_push(https_client, policy, reference, registry_auth)
                    .await
                    .is_ok()
                {
                    return Ok(());
                }
            }
        }

        Err(anyhow!("could not push policy"))
    }

    async fn push_plain(
        policy: &[u8],
        reference: &Reference,
        registry_auth: &RegistryAuth,
    ) -> Result<()> {
        let http_client = Registry::client(&ClientProtocol::Http);
        Registry::do_push(http_client, policy, reference, registry_auth).await
    }

    async fn fetch_tls(
        reference: &Reference,
        registry_auth: &RegistryAuth,
        sources: Option<&Sources>,
    ) -> Result<Vec<u8>> {
        let https_verification_settings = TLSVerificationSettings {
            insecure: false,
            extra_root_certificates: Registry::custom_root_certificates(reference, sources),
        };
        let https_client = Registry::client(&ClientProtocol::Https(https_verification_settings));
        if let Ok(policy) = Registry::do_fetch(https_client, reference, registry_auth).await {
            return Ok(policy);
        };

        if let Some(sources) = sources {
            if sources.is_insecure_source(reference.registry()) {
                let https_client =
                    Registry::client(&ClientProtocol::Https(TLSVerificationSettings {
                        insecure: true,
                        ..Default::default()
                    }));

                if let Ok(policy) = Registry::do_fetch(https_client, reference, registry_auth).await
                {
                    return Ok(policy);
                }
            }
        }

        Err(anyhow!("could not pull policy; make sure the registry is trusted and that the policy is present"))
    }

    async fn fetch_plain(reference: &Reference, registry_auth: &RegistryAuth) -> Result<Vec<u8>> {
        let http_client = Registry::client(&ClientProtocol::Http);
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
