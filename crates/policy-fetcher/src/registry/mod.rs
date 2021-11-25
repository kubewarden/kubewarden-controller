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
use std::convert::TryFrom;
use std::{path::Path, str::FromStr};
use tracing::debug;
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
            docker_config: docker_config.cloned(),
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
    pub async fn manifest(
        &self,
        url: &str,
        sources: Option<&Sources>,
    ) -> Result<oci_distribution::manifest::OciManifest> {
        // Start by building the Reference, this will expand the input url to
        // ensure it contains also the registry. Example: `busybox` ->
        // `docker.io/library/busybox:latest`
        let reference = build_fully_resolved_reference(url)?;
        let url: Url = Url::parse(format!("registry://{}", reference).as_str())?;
        let registry_auth = Registry::auth(reference.registry(), self.docker_config.as_ref());
        let sources: Sources = sources.cloned().unwrap_or_default();
        let cp = crate::client_protocol(&url, &sources)?;

        let (m, _) = Registry::client(cp)
            .pull_manifest(&reference, &registry_auth)
            .await?;

        Ok(m)
    }

    /// Fetch the manifest's digest of the OCI object referenced by the given url.
    pub async fn manifest_digest(&self, url: &str, sources: Option<&Sources>) -> Result<String> {
        // Start by building the Reference, this will expand the input url to
        // ensure it contains also the registry. Example: `busybox` ->
        // `docker.io/library/busybox:latest`
        let reference = build_fully_resolved_reference(url)?;
        let url: Url = Url::parse(format!("registry://{}", reference).as_str())?;
        let registry_auth = Registry::auth(reference.registry(), self.docker_config.as_ref());
        let sources: Sources = sources.cloned().unwrap_or_default();
        let cp = crate::client_protocol(&url, &sources)?;

        Registry::client(cp)
            .fetch_manifest_digest(&reference, &registry_auth)
            .await
    }

    pub async fn push(&self, policy: &[u8], url: &str, sources: Option<&Sources>) -> Result<()> {
        let url = Url::parse(url).map_err(|_| anyhow!("invalid URL: {}", url))?;
        let sources: Sources = sources.cloned().unwrap_or_default();

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

pub(crate) fn build_fully_resolved_reference(url: &str) -> Result<Reference> {
    let image = url.strip_prefix("registry://").unwrap_or(url);
    Reference::try_from(image).map_err(|e| {
        anyhow!(
            "Cannot parse {} into an OCI Reference object: {:?}",
            image,
            e
        )
    })
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
        debug!(image=?reference, ?client_protocol, ?destination, "fetching policy");

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

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    #[rstest(
        input,
        registry,
        repository,
        tag,
        digest,
        case(
            "registry://containers.local.lan/kubewarden/psp-apparmor:v0.1.0",
            "containers.local.lan",
            "kubewarden/psp-apparmor",
            Some("v0.1.0"),
            None
        ),
        // same as before, but without the registry:// protocol
        case(
            "containers.local.lan/kubewarden/psp-apparmor:v0.1.0",
            "containers.local.lan",
            "kubewarden/psp-apparmor",
            Some("v0.1.0"),
            None
        ),
        // ensure latest is added
        case(
            "containers.local.lan/kubewarden/psp-apparmor",
            "containers.local.lan",
            "kubewarden/psp-apparmor",
            Some("latest"),
            None
        ),
        case(
            "localhost:5000/psp-apparmor",
            "localhost:5000",
            "psp-apparmor",
            Some("latest"),
            None
        ),
        // docker hub is a special place...
        case(
            "busybox",
            "docker.io",
            "library/busybox",
            Some("latest"),
            None
        ),
        case(
            "opensuse/leap:15.3",
            "docker.io",
            "opensuse/leap",
            Some("15.3"),
            None
        ),
        case(
            "registry://busybox",
            "docker.io",
            "library/busybox",
            Some("latest"),
            None
        )
    )]
    fn test_reference_from_url(
        input: &str,
        registry: &str,
        repository: &str,
        tag: Option<&str>,
        digest: Option<&str>,
    ) {
        let reference = build_fully_resolved_reference(input).expect("could not parse reference");
        assert_eq!(registry, reference.registry(), "input was: {}", input);
        assert_eq!(repository, reference.repository(), "input was: {}", input);
        assert_eq!(tag, reference.tag(), "input was: {}", input);
        assert_eq!(digest, reference.digest(), "input was: {}", input);
    }
}
