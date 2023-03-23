use anyhow::{anyhow, Result};
use async_trait::async_trait;
use docker_credential::DockerCredential;
use lazy_static::lazy_static;
use oci_distribution::{
    client::{
        Certificate as OciCertificate, CertificateEncoding, Client, ClientConfig,
        ClientProtocol as OciClientProtocol, Config, ImageLayer,
    },
    manifest,
    secrets::RegistryAuth,
    Reference,
};
use regex::Regex;
use std::convert::TryFrom;
use std::str::FromStr;
use tracing::{debug, warn};
use url::Url;

use crate::fetcher::{ClientProtocol, PolicyFetcher, TlsVerificationMode};

use crate::sources::{Certificate, Sources};

lazy_static! {
    static ref SHA256_DIGEST_RE: Regex = Regex::new(r"[A-Fa-f0-9]{64}").unwrap();
    static ref SHA512_DIGEST_RE: Regex = Regex::new(r"[A-Fa-f0-9]{128}").unwrap();
}

// Struct used to reference a WASM module that is hosted on an OCI registry
#[derive(Default)]
pub struct Registry {}

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
                    }
                };

                client_config
            }
        }
    }
}

impl Registry {
    pub fn new() -> Registry {
        Registry {}
    }

    fn client(client_protocol: ClientProtocol) -> Client {
        Client::new(client_protocol.into())
    }

    pub fn auth(registry: &str) -> RegistryAuth {
        match docker_credential::get_credential(registry) {
            Ok(credential) => match credential {
                DockerCredential::IdentityToken(_) => {
                    warn!(%registry, "IdentityToken credential not supported. Using anonymous instead");
                    RegistryAuth::Anonymous
                }
                DockerCredential::UsernamePassword(user_name, password) => {
                    RegistryAuth::Basic(user_name, password)
                }
            },
            Err(error) => {
                debug!(
                    ?error,
                    %registry,
                    "Couldn't fetch credentials. Using anonymous instead"
                );
                RegistryAuth::Anonymous
            }
        }
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
        let registry_auth = Registry::auth(reference.registry());
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
        let registry_auth = Registry::auth(reference.registry());
        let sources: Sources = sources.cloned().unwrap_or_default();
        let cp = crate::client_protocol(&url, &sources)?;

        Registry::client(cp)
            .fetch_manifest_digest(&reference, &registry_auth)
            .await
            .map_err(|e| anyhow!(e))
    }

    /// Push the policy to the OCI registry specified by `url`.
    ///
    /// Returns the immutable reference to the policy (i.e.
    /// `ghcr.io/kubewarden/secure-policy@sha256:72b4569c3daee67abeaa64192fb53895d0edb2d44fa6e1d9d4c5d3f8ece09f6e`)
    pub async fn push(
        &self,
        policy: &[u8],
        destination: &str,
        sources: Option<&Sources>,
    ) -> Result<String> {
        let url = Url::parse(destination).map_err(|_| anyhow!("invalid URL: {}", destination))?;
        let sources: Sources = sources.cloned().unwrap_or_default();
        let destination = destination
            .strip_prefix("registry://")
            .ok_or_else(|| anyhow!("Invalid destination format"))?;

        match self
            .do_push(policy, &url, crate::client_protocol(&url, &sources)?)
            .await
        {
            Ok(manifest_url) => {
                return build_immutable_ref(destination, &manifest_url);
            }
            Err(err) => {
                if !sources.is_insecure_source(&crate::host_and_port(&url)?) {
                    return Err(anyhow!("could not push policy: {}", err,));
                }
            }
        }

        if let Ok(manifest_url) = self
            .do_push(
                policy,
                &url,
                ClientProtocol::Https(TlsVerificationMode::NoTlsVerification),
            )
            .await
        {
            return build_immutable_ref(destination, &manifest_url);
        }

        let manifest_url = self
            .do_push(policy, &url, ClientProtocol::Http)
            .await
            .map_err(|_| anyhow!("could not push policy"))?;

        build_immutable_ref(destination, &manifest_url)
    }

    async fn do_push(
        &self,
        policy: &[u8],
        url: &Url,
        client_protocol: ClientProtocol,
    ) -> Result<String> {
        let reference =
            Reference::from_str(url.as_ref().strip_prefix("registry://").unwrap_or_default())?;

        let registry_auth = Registry::auth(reference.registry());

        let layers = vec![ImageLayer::new(
            policy.to_vec(),
            manifest::WASM_LAYER_MEDIA_TYPE.to_string(),
            None,
        )];

        let config = Config {
            data: b"{}".to_vec(),
            media_type: manifest::WASM_CONFIG_MEDIA_TYPE.to_string(),
            annotations: None,
        };

        let image_manifest = manifest::OciImageManifest::build(&layers, &config, None);
        Registry::client(client_protocol)
            .push(
                &reference,
                &layers,
                config,
                &registry_auth,
                Some(image_manifest),
            )
            .await
            .map(|push_response| push_response.manifest_url)
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
    async fn fetch(&self, url: &Url, client_protocol: ClientProtocol) -> Result<Vec<u8>> {
        let reference =
            Reference::from_str(url.as_ref().strip_prefix("registry://").unwrap_or_default())?;
        debug!(image=?reference, ?client_protocol, "fetching policy");

        let image_content = Registry::client(client_protocol)
            .pull(
                &reference,
                &Registry::auth(&crate::host_and_port(url)?),
                vec![manifest::WASM_LAYER_MEDIA_TYPE],
            )
            .await?
            .layers
            .into_iter()
            .next()
            .map(|layer| layer.data);

        match image_content {
            Some(image_content) => Ok(image_content),
            None => Err(anyhow!("could not pull policy {}: empty layers", url)),
        }
    }
}

/// Builds an immutable OCI reference for the given image
///
/// * `image ref`: the mutable image reference. For example: `ghcr.io/kubewarden/secure-policy:latest`
/// * `manifest_url`: the URL of the manifest, as returned when doing a push operation. For example
///   `https://ghcr.io/v2/kubewarden/secure-policy/manifests/sha256:72b4569c3daee67abeaa64192fb53895d0edb2d44fa6e1d9d4c5d3f8ece09f6e`
fn build_immutable_ref(image_ref: &str, manifest_url: &str) -> Result<String> {
    let manifest_digest = manifest_url
        .rsplit_once('/')
        .map(|(_, digest)| digest.to_string())
        .ok_or_else(|| {
            anyhow!(
                "Cannot extract manifest digest from the OCI registry response: {}",
                manifest_url
            )
        })?;

    let (digest, checksum) = manifest_digest
        .split_once(':')
        .ok_or_else(|| anyhow!("Invalid digest: {}", manifest_digest))?;

    let digest_valid = match digest {
        "sha256" => Ok(SHA256_DIGEST_RE.is_match(checksum)),
        "sha512" => Ok(SHA512_DIGEST_RE.is_match(checksum)),
        unknown => Err(anyhow!(
            "unknown algorithm '{}' for manifest {}",
            unknown,
            manifest_digest
        )),
    }?;

    if !digest_valid {
        return Err(anyhow!(
            "The digest of the returned manifest is not valid: {}",
            manifest_digest
        ));
    }

    let oci_reference = oci_distribution::Reference::try_from(image_ref)?;
    let mut image_immutable_ref = if oci_reference.registry() == "" {
        oci_reference.repository().to_string()
    } else {
        format!(
            "{}/{}",
            oci_reference.registry(),
            oci_reference.repository()
        )
    };
    image_immutable_ref.push('@');
    image_immutable_ref.push_str(&manifest_digest);

    Ok(image_immutable_ref)
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

    #[rstest(
        image_ref,
        manifest_url,
        immutable_ref,
        case(
            "ghcr.io/kubewarden/secure-policy:latest",
            "https://ghcr.io/v2/kubewarden/secure-policy/manifests/sha256:72b4569c3daee67abeaa64192fb53895d0edb2d44fa6e1d9d4c5d3f8ece09f6e",
            Ok(String::from("ghcr.io/kubewarden/secure-policy@sha256:72b4569c3daee67abeaa64192fb53895d0edb2d44fa6e1d9d4c5d3f8ece09f6e")),
        ),
        case(
            "ghcr.io/kubewarden/secure-policy:latest",
            "https://ghcr.io/v2/kubewarden/secure-policy/manifests/sha512:76ffb94a4cfdc6663b8a268d0c50685e1d2c87477b20f4b31fdff3f990af117b0943d16d0b6e2c197e8e3732876d317ef8bdfa1f82afdcd8ad0a1f62ba53653a",
            Ok(String::from("ghcr.io/kubewarden/secure-policy@sha512:76ffb94a4cfdc6663b8a268d0c50685e1d2c87477b20f4b31fdff3f990af117b0943d16d0b6e2c197e8e3732876d317ef8bdfa1f82afdcd8ad0a1f62ba53653a")),
        ),
        // Error because invalid digest
        case(
            "ghcr.io/kubewarden/secure-policy:latest",
            "https://ghcr.io/v2/kubewarden/secure-policy/manifests/sha256:XYZ4569c3daee67abeaa64192fb53895d0edb2d44fa6e1d9d4c5d3f8ece09f6e",
            Err(anyhow!("boom")),
        ),
        // Error because of shorter digest
        case(
            "ghcr.io/kubewarden/secure-policy:latest",
            "https://ghcr.io/v2/kubewarden/secure-policy/manifests/sha256:72b4569c",
            Err(anyhow!("boom")),
        ),
        // Error because unknown algorithm
        case(
            "ghcr.io/kubewarden/secure-policy:latest",
            "https://ghcr.io/v2/kubewarden/secure-policy/manifests/sha384:72b4569c3daee67abeaa64192fb53895d0edb2d44fa6e1d9d4c5d3f8ece09f6e",
            Err(anyhow!("boom")),
        ),
        // Error because invalid url format
        case(
            "ghcr.io/kubewarden/secure-policy:latest",
            "not an url",
            Err(anyhow!("boom")),
        )
    )]
    fn test_extract_manifest_digest(
        image_ref: &str,
        manifest_url: &str,
        immutable_ref: Result<String>,
    ) {
        let actual = build_immutable_ref(image_ref, manifest_url);
        match immutable_ref {
            Err(_) => assert!(actual.is_err()),
            Ok(r) => assert_eq!(r, actual.unwrap()),
        }
    }
}
