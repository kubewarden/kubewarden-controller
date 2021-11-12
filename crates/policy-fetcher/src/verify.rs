use crate::sources::Sources;
use crate::store::Store;
use crate::{policy::Policy, registry::config::DockerConfig};

use anyhow::{anyhow, Result};
use oci_distribution::manifest::WASM_LAYER_MEDIA_TYPE;
use sigstore::cosign::{Client, CosignCapabilities};
use std::collections::HashMap;
use std::convert::TryInto;
use std::str::FromStr;
use tracing::{error, info};
use url::{ParseError, Url};

/// This structure simplifies the process of policy verification
/// using Sigstore
pub struct Verifier {
    cosign_client: Client,
    sources: Option<Sources>,
}

impl Verifier {
    /// Creates a new verifier using the `Sources` provided. These are
    /// later used to interact with remote OCI registries.
    pub fn new(sources: Option<Sources>) -> Self {
        let client_config: sigstore::registry::ClientConfig =
            sources.clone().unwrap_or_default().into();
        let cosign_client = sigstore::cosign::Client::new(client_config);
        Verifier {
            cosign_client,
            sources,
        }
    }

    /// Verifies the given policy using the verification key provided by the
    /// user.
    ///
    /// When annotations are provided, they are enforced with the values
    /// specified inside of the Sigstore signature object.
    ///
    /// Note well: this method doesn't compare the checksum of a possible local
    /// file with the one inside of the signed (and verified) manifest, as that
    /// can only be done with certainty after pulling the policy.
    ///
    /// Note well: right now, verification can be done only against policies
    /// that are stored inside of OCI registries.
    pub async fn verify(
        &mut self,
        url: &str,
        docker_config: Option<DockerConfig>,
        annotations: Option<HashMap<String, String>>,
        verification_key: &str,
    ) -> Result<String> {
        let url = match Url::parse(url) {
            Ok(u) => Ok(u),
            Err(ParseError::RelativeUrlWithoutBase) => {
                Url::parse(format!("registry://{}", url).as_str())
            }
            Err(e) => Err(e),
        }?;
        if url.scheme() != "registry" {
            return Err(anyhow!(
                "Verification works only with 'registry://' protocol"
            ));
        }

        let image_name = url.as_str().strip_prefix("registry://").unwrap();

        let auth: sigstore::registry::Auth = match docker_config.clone() {
            Some(docker_config) => {
                let sigstore_auth: Option<Result<sigstore::registry::Auth>> = docker_config
                    .auth(image_name)
                    .map_err(|e| anyhow!("Cannot build Auth object for image '{}': {:?}", url, e))?
                    .map(|ra| {
                        let a: Result<sigstore::registry::Auth> =
                            TryInto::<sigstore::registry::Auth>::try_into(ra);
                        a
                    });

                match sigstore_auth {
                    None => sigstore::registry::Auth::Anonymous,
                    Some(sa) => sa?,
                }
            }
            None => sigstore::registry::Auth::Anonymous,
        };

        let (cosign_signature_image, source_image_digest) =
            self.cosign_client.triangulate(image_name, &auth).await?;

        let simple_signing_matches = self
            .cosign_client
            .verify(
                &auth,
                &source_image_digest,
                &cosign_signature_image,
                verification_key,
                annotations,
            )
            .await?;

        // cosign_client.verify raises an error if no SimpleSigning
        // object is found -> the vector has at least one entry.
        // Finally, all the entries have the same docker_manifest_digest
        let manifest_digest = simple_signing_matches
            .get(0)
            .unwrap()
            .critical
            .image
            .docker_manifest_digest
            .clone();

        Ok(manifest_digest)
    }

    /// Compares the checksum of the local policy with the one mentioned inside of the
    /// the signed (and verified) manifest.
    async fn verify_local_file_checksum(
        &mut self,
        url: &Url,
        image_name: &str,
        docker_config: Option<DockerConfig>,
        verified_manifest_digest: &str,
    ) -> Result<()> {
        let store = Store::default();
        let local_path =
            store.policy_full_path(url.as_str(), crate::store::PolicyPath::PrefixAndFilename)?;

        if !local_path.exists() {
            info!(policy = %url, "No local policy to verify");
            return Ok(());
        }

        let registry = crate::registry::Registry::new(&docker_config);
        let reference = oci_distribution::Reference::from_str(image_name)?;
        let image_immutable_ref = format!(
            "registry://{}/{}@{}",
            reference.registry(),
            reference.repository(),
            verified_manifest_digest
        );
        let manifest = registry
            .manifest(&image_immutable_ref, &self.sources.clone())
            .await?;

        let digests: Vec<String> = manifest
            .layers
            .iter()
            .filter_map(|layer| match layer.media_type.as_str() {
                WASM_LAYER_MEDIA_TYPE => Some(layer.digest.clone()),
                _ => None,
            })
            .collect();
        if digests.len() != 1 {
            error!(manifest = ?manifest, "The manifest is expected to have one WASM layer");
            return Err(anyhow!("Cannot verify local file integrity, the remote manifest doesn't have only one WASM layer"));
        }
        let expected_digest = digests[0]
            .strip_prefix("sha256:")
            .ok_or_else(|| anyhow!("The checksum inside of the remote manifest is not using the sha256 hashing algorithm as expected."))?;

        let policy = Policy {
            uri: url.to_string(),
            local_path,
        };
        let file_digest = policy.digest()?;
        if file_digest != expected_digest {
            Err(anyhow!("The digest of the local file doesn't match with the one reported inside of the signed manifest. Got {} instead of {}", file_digest, expected_digest))
        } else {
            info!("Local file checksum verification passed");
            Ok(())
        }
    }
}
