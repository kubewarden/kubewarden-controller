use crate::sources::Sources;
use crate::{policy::Policy, registry::config::DockerConfig};

use anyhow::{anyhow, Result};
use oci_distribution::manifest::WASM_LAYER_MEDIA_TYPE;
use sigstore::cosign;
use sigstore::cosign::verification_constraint::VerificationConstraintVec;
use sigstore::cosign::ClientBuilder;
use sigstore::cosign::CosignCapabilities;

use std::{convert::TryInto, str::FromStr};
use tracing::{debug, error, info};
use url::{ParseError, Url};

/// This structure simplifies the process of policy verification
/// using Sigstore
pub struct Verifier {
    cosign_client: sigstore::cosign::Client,
    sources: Option<Sources>,
}

pub mod config;
pub mod verification_constraints;

impl Verifier {
    /// Creates a new verifier using the `Sources` provided. These are
    /// later used to interact with remote OCI registries.
    pub fn new(
        sources: Option<Sources>,
        fulcio_cert: &[u8],
        rekor_public_key: &str,
    ) -> Result<Self> {
        let client_config: sigstore::registry::ClientConfig =
            sources.clone().unwrap_or_default().into();
        let cosign_client = ClientBuilder::default()
            .with_oci_client_config(client_config)
            .with_fulcio_cert(fulcio_cert)
            .with_rekor_pub_key(rekor_public_key)
            .build()
            .map_err(|e| anyhow!("could not build a cosign client: {}", e))?;
        Ok(Verifier {
            cosign_client,
            sources,
        })
    }

    /// Verifies the given policy using the verification key provided by the
    /// user.
    ///
    /// When annotations are provided, they are enforced with the values
    /// specified inside of the Sigstore signature object.
    ///
    /// In case of success, returns the manifest digest of the verified policy.
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
        verification_settings: config::VerificationSettings,
    ) -> Result<String> {
        // obtain image name:
        //
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

        // obtain registry auth:
        //
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

        // obtain all signatures of image:
        //
        // trusted_signature_layers() will error early if cosign_client using
        // Fulcio,Rekor certs and signatures are not verified
        //
        let (cosign_signature_image, source_image_digest) =
            self.cosign_client.triangulate(image_name, &auth).await?;

        let trusted_layers = self
            .cosign_client
            .trusted_signature_layers(&auth, &source_image_digest, &cosign_signature_image)
            .await?;

        // verify signatures against our settings:
        //
        verify_signatures_against_settings(&verification_settings, &trusted_layers)?;

        // everything is fine here:
        debug!(
            policy = url.to_string().as_str(),
            "Policy successfully verified"
        );
        Ok(source_image_digest)
    }

    /// Verifies the checksum of the local file by comparing it with the one
    /// mentioned inside of the signed (and verified) manifest digest.
    /// This ensures nobody tampered with the local policy.
    ///
    /// Note well: right now, verification can be done only against policies
    /// that are stored inside of OCI registries.
    pub async fn verify_local_file_checksum(
        &mut self,
        policy: &Policy,
        docker_config: Option<DockerConfig>,
        verified_manifest_digest: &str,
    ) -> Result<()> {
        let url = match Url::parse(&policy.uri) {
            Ok(u) => Ok(u),
            Err(ParseError::RelativeUrlWithoutBase) => {
                Url::parse(format!("registry://{}", policy.uri).as_str())
            }
            Err(e) => Err(e),
        }?;
        if url.scheme() != "registry" {
            return Err(anyhow!(
                "Verification works only with 'registry://' protocol"
            ));
        }
        let image_name = url.as_str().strip_prefix("registry://").unwrap();

        if !policy.local_path.exists() {
            return Err(anyhow!(
                "Policy cannot be verified, local wasm file doesn't exist: {:?}",
                policy.local_path
            ));
        }

        let registry = crate::registry::Registry::new(docker_config.as_ref());
        let reference = oci_distribution::Reference::from_str(image_name)?;
        let image_immutable_ref = format!(
            "registry://{}/{}@{}",
            reference.registry(),
            reference.repository(),
            verified_manifest_digest
        );
        let manifest = registry
            .manifest(&image_immutable_ref, self.sources.as_ref())
            .await?;

        let digests: Vec<String>;
        if let oci_distribution::manifest::OciManifest::Image(ref image) = manifest {
            digests = image
                .layers
                .iter()
                .filter_map(|layer| match layer.media_type.as_str() {
                    WASM_LAYER_MEDIA_TYPE => Some(layer.digest.clone()),
                    _ => None,
                })
                .collect()
        } else {
            unreachable!("Expected Image, found ImageIndex manifest. This cannot happen, as oci clientConfig.platform_resolver is None and we will error earlier");
        }

        if digests.len() != 1 {
            error!(manifest = ?manifest, "The manifest is expected to have one WASM layer");
            return Err(anyhow!("Cannot verify local file integrity, the remote manifest doesn't have only one WASM layer"));
        }
        let expected_digest = digests[0]
            .strip_prefix("sha256:")
            .ok_or_else(|| anyhow!("The checksum inside of the remote manifest is not using the sha256 hashing algorithm as expected."))?;

        let file_digest = policy.digest()?;
        if file_digest != expected_digest {
            Err(anyhow!("The digest of the local file doesn't match with the one reported inside of the signed manifest. Got {} instead of {}", file_digest, expected_digest))
        } else {
            info!("Local file checksum verification passed");
            Ok(())
        }
    }
}

// Verifies the trusted layers against the verification settings passed to it.
// It does that by creating the verification constraints from the settings, and
// then filtering the trusted_layers with the corresponding constraints.
fn verify_signatures_against_settings(
    verification_settings: &config::VerificationSettings,
    trusted_layers: &[SignatureLayer],
) -> Result<()> {
    // build verification constraints from our settings:
    //
    let mut constraints_all_of: VerificationConstraintVec = Vec::new();
    let mut constraints_any_of: VerificationConstraintVec = Vec::new();

    if let Some(ref signatures_all_of) = verification_settings.all_of {
        for signature in signatures_all_of.iter() {
            constraints_all_of.push(signature.verifier()?);
        }
    }
    if let Some(ref signatures_any_of) = verification_settings.any_of {
        for signature in signatures_any_of.signatures.iter() {
            constraints_any_of.push(signature.verifier()?);
        }
    }

    // filter trusted_layers against our verification constraints:
    //
    let length_constraints_all_of = constraints_all_of.len();
    match cosign::filter_signature_layers(trusted_layers, constraints_all_of) {
        Ok(m) if m.is_empty() => {
            return Err(anyhow!(
                "Image verification failed: no matching signature found on AllOf list"
            ))
        }
        Err(e) => return Err(anyhow!("{}", e)),
        Ok(m) if m.len() <= length_constraints_all_of => {
            return Err(anyhow!(
                "Image verification failed: missing signatures in AllOf list"
            ));
        }
        Ok(_) => (), // all_of verified
    }
    if verification_settings.any_of.is_some() {
        let signatures_any_of = verification_settings.any_of.as_ref().unwrap();
        match cosign::filter_signature_layers(trusted_layers, constraints_any_of) {
            Ok(m) if m.len() < signatures_any_of.minimum_matches.into() => {
                return Err(anyhow!(
                    "Image verification failed: missing signatures in AnyOf list"
                ));
            }
            Err(e) => return Err(anyhow!("{}", e)),
            Ok(_) => (), // any_of verified
        }
    }
    Ok(())
}
