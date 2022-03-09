use crate::sources::Sources;
use crate::{policy::Policy, registry::config::DockerConfig};

use anyhow::{anyhow, Result};
use oci_distribution::manifest::WASM_LAYER_MEDIA_TYPE;
use sigstore::cosign;
use sigstore::cosign::signature_layers::SignatureLayer;
use sigstore::cosign::verification_constraint::VerificationConstraintVec;
use sigstore::cosign::ClientBuilder;
use sigstore::cosign::CosignCapabilities;
use sigstore::errors::SigstoreVerifyConstraintsError;

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
        verification_config: config::VerificationConfig,
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

        // verify signatures against our config:
        //
        verify_signatures_against_config(&verification_config, &trusted_layers)?;

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

        let digests: Vec<String> = if let oci_distribution::manifest::OciManifest::Image(
            ref image,
        ) = manifest
        {
            image
                .layers
                .iter()
                .filter_map(|layer| match layer.media_type.as_str() {
                    WASM_LAYER_MEDIA_TYPE => Some(layer.digest.clone()),
                    _ => None,
                })
                .collect()
        } else {
            unreachable!("Expected Image, found ImageIndex manifest. This cannot happen, as oci clientConfig.platform_resolver is None and we will error earlier");
        };

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

// Verifies the trusted layers against the VerificationConfig passed to it.
// It does that by creating the verification constraints from the config, and
// then filtering the trusted_layers with the corresponding constraints.
fn verify_signatures_against_config(
    verification_config: &config::VerificationConfig,
    trusted_layers: &[SignatureLayer],
) -> Result<()> {
    // build verification constraints from our config:
    //
    let mut constraints_all_of: VerificationConstraintVec = Vec::new();
    let mut constraints_any_of: VerificationConstraintVec = Vec::new();

    if let Some(ref signatures_all_of) = verification_config.all_of {
        for signature in signatures_all_of.iter() {
            constraints_all_of.push(signature.verifier()?);
        }
    }
    if let Some(ref signatures_any_of) = verification_config.any_of {
        for signature in signatures_any_of.signatures.iter() {
            constraints_any_of.push(signature.verifier()?);
        }
    }

    // filter trusted_layers against our verification constraints:
    //
    if verification_config.all_of.is_none() && verification_config.any_of.is_none() {
        // deserialized config is already sanitized, and should not reach here anyways
        return Err(anyhow!(
            "Image verification failed: no signatures to verify"
        ));
    }

    if verification_config.all_of.is_some() {
        if let Err(SigstoreVerifyConstraintsError { .. }) =
            cosign::verify_constraints(trusted_layers, constraints_all_of.iter())
        {
            // TODO build error with list of unsatisfied constraints
            return Err(anyhow!("Image verification failed: missing signatures"));
        }
    }

    if verification_config.any_of.is_some() {
        let signatures_any_of = verification_config.any_of.as_ref().unwrap();
        if let Err(SigstoreVerifyConstraintsError {
            unsatisfied_constraints,
        }) = cosign::verify_constraints(trusted_layers, constraints_any_of.iter())
        {
            let num_satisfied_constraits = constraints_any_of.len() - unsatisfied_constraints.len();
            if num_satisfied_constraits < signatures_any_of.minimum_matches.into() {
                // TODO build error with list of unsatisfied constraints
                return Err(anyhow!(
                    "Image verification failed: minimum number of signatures not reached"
                ));
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use config::{AnyOf, Signature, Subject, VerificationConfig};
    use cosign::signature_layers::CertificateSubject;
    use sigstore::{cosign::signature_layers::CertificateSignature, simple_signing::SimpleSigning};

    fn build_signature_layers_keyless(
        issuer: Option<String>,
        subject: CertificateSubject,
    ) -> SignatureLayer {
        let pub_key = r#"-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAELKhD7F5OKy77Z582Y6h0u1J3GNA+
kvUsh4eKpd1lwkDAzfFDs7yXEExsEkPPuiQJBelDT68n7PDIWB/QEY7mrA==
-----END PUBLIC KEY-----"#;
        let verification_key = sigstore::crypto::CosignVerificationKey::from_pem(
            pub_key.as_bytes(),
            sigstore::crypto::SignatureDigestAlgorithm::default(),
        )
        .expect("Cannot create CosignVerificationKey");

        let raw_data = r#"{"critical":{"identity":{"docker-reference":"registry-testing.svc.lan/kubewarden/disallow-service-nodeport"},"image":{"docker-manifest-digest":"sha256:5f481572d088dc4023afb35fced9530ced3d9b03bf7299c6f492163cb9f0452e"},"type":"cosign container image signature"},"optional":null}"#;
        let raw_data = raw_data.as_bytes().to_vec();
        let signature = "MEUCIGqWScz7s9aP2sGXNFKeqivw3B6kPRs56AITIHnvd5igAiEA1kzbaV2Y5yPE81EN92NUFOl31LLJSvwsjFQ07m2XqaA=".to_string();

        let simple_signing: SimpleSigning =
            serde_json::from_slice(&raw_data).expect("Cannot deserialize SimpleSigning");

        let certificate_signature = Some(CertificateSignature {
            verification_key,
            issuer,
            subject,
        });

        SignatureLayer {
            simple_signing,
            oci_digest: "not relevant".to_string(),
            certificate_signature,
            bundle: None,
            signature,
            raw_data,
        }
    }

    fn generic_issuer(issuer: &str, subject_str: &str) -> config::Signature {
        let subject = Subject::Equal(subject_str.to_string());
        Signature::GenericIssuer {
            issuer: issuer.to_string(),
            subject,
            annotations: None,
        }
    }

    fn signature_layer(issuer: &str, subject_str: &str) -> SignatureLayer {
        let certificate_subject = CertificateSubject::Email(subject_str.to_string());
        build_signature_layers_keyless(Some(issuer.to_string()), certificate_subject)
    }

    #[test]
    fn test_verify_config() {
        // build verification config:
        let signatures_all_of: Vec<Signature> = vec![generic_issuer(
            "https://github.com/login/oauth",
            "user1@provider.com",
        )];
        let signatures_any_of: Vec<Signature> = vec![generic_issuer(
            "https://github.com/login/oauth",
            "user2@provider.com",
        )];
        let verification_config: VerificationConfig = VerificationConfig {
            api_version: "v1".to_string(),
            all_of: Some(signatures_all_of),
            any_of: Some(AnyOf {
                minimum_matches: 1,
                signatures: signatures_any_of,
            }),
        };

        // build trusted layers:
        let trusted_layers: Vec<SignatureLayer> = vec![
            signature_layer("https://github.com/login/oauth", "user1@provider.com"),
            signature_layer("https://github.com/login/oauth", "user2@provider.com"),
        ];

        assert!(verify_signatures_against_config(&verification_config, &trusted_layers).is_ok());
    }

    #[test]
    #[should_panic(expected = "Image verification failed: no signatures to verify")]
    fn test_verify_config_missing_both_any_of_all_of() {
        // build verification config:
        let verification_config: VerificationConfig = VerificationConfig {
            api_version: "v1".to_string(),
            all_of: None,
            any_of: None,
        };

        // build trusted layers:
        let trusted_layers: Vec<SignatureLayer> = vec![signature_layer(
            "https://github.com/login/oauth",
            "user-unrelated@provider.com",
        )];

        verify_signatures_against_config(&verification_config, &trusted_layers).unwrap();
    }

    #[test]
    #[should_panic(expected = "Image verification failed: missing signatures")]
    fn test_verify_config_not_maching_all_of() {
        // build verification config:
        let signatures_all_of: Vec<Signature> = vec![generic_issuer(
            "https://github.com/login/oauth",
            "user1@provider.com",
        )];
        let verification_config: VerificationConfig = VerificationConfig {
            api_version: "v1".to_string(),
            all_of: Some(signatures_all_of),
            any_of: None,
        };

        // build trusted layers:
        let trusted_layers: Vec<SignatureLayer> = vec![signature_layer(
            "https://github.com/login/oauth",
            "user-unrelated@provider.com",
        )];

        verify_signatures_against_config(&verification_config, &trusted_layers).unwrap();
    }

    #[test]
    #[should_panic(expected = "Image verification failed: missing signatures")]
    fn test_verify_config_missing_signatures_all_of() {
        // build verification config:
        let signatures_all_of: Vec<Signature> = vec![
            generic_issuer("https://github.com/login/oauth", "user1@provider.com"),
            generic_issuer("https://github.com/login/oauth", "user2@provider.com"),
            generic_issuer("https://github.com/login/oauth", "user3@provider.com"),
        ];
        let verification_config: VerificationConfig = VerificationConfig {
            api_version: "v1".to_string(),
            all_of: Some(signatures_all_of),
            any_of: None,
        };

        // build trusted layers:
        let trusted_layers: Vec<SignatureLayer> = vec![
            signature_layer("https://github.com/login/oauth", "user1@provider.com"),
            signature_layer("https://github.com/login/oauth", "user2@provider.com"),
        ];

        verify_signatures_against_config(&verification_config, &trusted_layers).unwrap();
    }

    #[test]
    #[should_panic(
        expected = "Image verification failed: minimum number of signatures not reached"
    )]
    fn test_verify_config_missing_signatures_any_of() {
        // build verification config:
        let signatures_any_of: Vec<Signature> = vec![
            generic_issuer("https://github.com/login/oauth", "user1@provider.com"),
            generic_issuer("https://github.com/login/oauth", "user2@provider.com"),
            generic_issuer("https://github.com/login/oauth", "user3@provider.com"),
        ];
        let verification_config: VerificationConfig = VerificationConfig {
            api_version: "v1".to_string(),
            all_of: None,
            any_of: Some(AnyOf {
                minimum_matches: 2,
                signatures: signatures_any_of,
            }),
        };

        // build trusted layers:
        let trusted_layers: Vec<SignatureLayer> = vec![signature_layer(
            "https://github.com/login/oauth",
            "user1@provider.com",
        )];

        verify_signatures_against_config(&verification_config, &trusted_layers).unwrap();
    }

    #[test]
    fn test_verify_config_quorum_signatures_any_of() {
        // build verification config:
        let signatures_any_of: Vec<Signature> = vec![
            generic_issuer("https://github.com/login/oauth", "user1@provider.com"),
            generic_issuer("https://github.com/login/oauth", "user2@provider.com"),
            generic_issuer("https://github.com/login/oauth", "user3@provider.com"),
        ];
        let verification_config: VerificationConfig = VerificationConfig {
            api_version: "v1".to_string(),
            all_of: None,
            any_of: Some(AnyOf {
                minimum_matches: 2,
                signatures: signatures_any_of,
            }),
        };

        // build trusted layers:
        let trusted_layers: Vec<SignatureLayer> = vec![
            signature_layer("https://github.com/login/oauth", "user1@provider.com"),
            signature_layer("https://github.com/login/oauth", "user2@provider.com"),
        ];

        assert!(verify_signatures_against_config(&verification_config, &trusted_layers).is_ok());
    }
}
