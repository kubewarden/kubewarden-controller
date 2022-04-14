use crate::sources::Sources;
use crate::{policy::Policy, registry::config::DockerConfig};

use crate::kubewarden_policy_sdk::host_capabilities::verification::KeylessInfo;
use anyhow::{anyhow, Result};
use oci_distribution::manifest::WASM_LAYER_MEDIA_TYPE;
use sigstore::cosign::{self, signature_layers::SignatureLayer, ClientBuilder, CosignCapabilities};
use std::collections::HashMap;

use crate::verify::config::{LatestVerificationConfig, Signature, Subject};
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

/// Define how Fulcio and Rekor data are going to be provided to sigstore cosign client
pub enum FulcioAndRekorData {
    /// Data is read from the official Sigstore TUF repository
    ///
    /// Note well: we have to rely on the consumer of policy-fetcher library to provide
    /// an instance of sigstore::tuf::SigstoreRepository instead of creating our own
    /// object "on-demand". That's because currently (Mar 2022), fetching the contents
    /// of a TUF repository is a **blocking** operation that cannot be done inside of
    /// `async` contexes without causing a tokio runtime panic. That happens because
    /// the `tough` library, used by sigstore-rs, performs a blocking fetch.
    ///
    /// Note well: for end users of this library, there's no need to depend on sigstore-rs.
    /// This library is re-exposing the crate exactly for this purpose:
    ///
    /// ```
    /// use policy_fetcher::sigstore;
    ///
    /// let repo: sigstore::tuf::SigstoreRepository;
    /// ```
    FromTufRepository {
        repo: sigstore::tuf::SigstoreRepository,
    },
    /// Data is somehow provided by the user, probably by reading it from the
    /// local filesystem
    FromCustomData {
        rekor_public_key: Option<String>,
        fulcio_certs: Vec<crate::sources::Certificate>,
    },
}

impl Verifier {
    /// Creates a new verifier using the `Sources` provided. These are
    /// later used to interact with remote OCI registries.
    pub fn new(
        sources: Option<Sources>,
        fulcio_and_rekor_data: &FulcioAndRekorData,
    ) -> Result<Self> {
        let client_config: sigstore::registry::ClientConfig =
            sources.clone().unwrap_or_default().into();
        let mut cosign_client_builder =
            ClientBuilder::default().with_oci_client_config(client_config);
        match fulcio_and_rekor_data {
            FulcioAndRekorData::FromTufRepository { repo } => {
                cosign_client_builder = cosign_client_builder
                    .with_rekor_pub_key(repo.rekor_pub_key())
                    .with_fulcio_certs(repo.fulcio_certs());
            }
            FulcioAndRekorData::FromCustomData {
                rekor_public_key,
                fulcio_certs,
            } => {
                if let Some(pk) = rekor_public_key {
                    cosign_client_builder = cosign_client_builder.with_rekor_pub_key(pk);
                }
                if !fulcio_certs.is_empty() {
                    let certs: Vec<sigstore::registry::Certificate> = fulcio_certs
                        .iter()
                        .map(|c| {
                            let sc: sigstore::registry::Certificate = c.into();
                            sc
                        })
                        .collect();
                    cosign_client_builder = cosign_client_builder.with_fulcio_certs(&certs);
                }
            }
        }

        let cosign_client = cosign_client_builder
            .build()
            .map_err(|e| anyhow!("could not build a cosign client: {}", e))?;
        Ok(Verifier {
            cosign_client,
            sources,
        })
    }

    pub async fn verify_pub_key(
        &mut self,
        docker_config: Option<&DockerConfig>,
        image_url: String,
        pub_keys: Vec<String>,
        annotations: Option<HashMap<String, String>>,
    ) -> Result<String> {
        // build interim VerificationConfig:
        //
        let mut signatures_all_of: Vec<Signature> = Vec::new();
        for k in pub_keys.iter() {
            let signature = Signature::PubKey {
                owner: None,
                key: k.clone(),
                annotations: annotations.clone(),
            };
            signatures_all_of.push(signature);
        }
        let verification_config = LatestVerificationConfig {
            all_of: Some(signatures_all_of),
            any_of: None,
        };

        self.verify(&image_url, docker_config, &verification_config)
            .await
    }

    pub async fn verify_keyless_exact_match(
        &mut self,
        docker_config: Option<&DockerConfig>,
        image_url: String,
        keyless: Vec<KeylessInfo>,
        annotations: Option<HashMap<String, String>>,
    ) -> Result<String> {
        // Build intering VerificationConfig:
        //
        let mut signatures_all_of: Vec<Signature> = Vec::new();
        for k in keyless.iter() {
            let signature = Signature::GenericIssuer {
                issuer: k.issuer.clone(),
                subject: Subject::Equal(k.subject.clone()),
                annotations: annotations.clone(),
            };
            signatures_all_of.push(signature);
        }
        let verification_config = LatestVerificationConfig {
            all_of: Some(signatures_all_of),
            any_of: None,
        };
        self.verify(&image_url, docker_config, &verification_config)
            .await
    }

    pub async fn verify(
        &mut self,
        image_url: &str,
        docker_config: Option<&DockerConfig>,
        verification_config: &config::LatestVerificationConfig,
    ) -> Result<String> {
        // obtain image name:
        //
        let url = match Url::parse(image_url) {
            Ok(u) => Ok(u),
            Err(ParseError::RelativeUrlWithoutBase) => {
                Url::parse(format!("registry://{}", image_url).as_str())
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
        let auth: sigstore::registry::Auth = match docker_config {
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
        verify_signatures_against_config(verification_config, &trusted_layers)?;

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
        docker_config: Option<&DockerConfig>,
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

        let registry = crate::registry::Registry::new(docker_config);
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
    verification_config: &config::LatestVerificationConfig,
    trusted_layers: &[SignatureLayer],
) -> Result<()> {
    // filter trusted_layers against our verification constraints:
    //
    if verification_config.all_of.is_none() && verification_config.any_of.is_none() {
        // deserialized config is already sanitized, and should not reach here anyways
        return Err(anyhow!(
            "Image verification failed: no signatures to verify"
        ));
    }

    use rayon::prelude::*;

    if let Some(ref signatures_all_of) = verification_config.all_of {
        let unsatisfied_signatures: Vec<&Signature> = signatures_all_of
            .par_iter()
            .filter(|signature| match signature.verifier() {
                Ok(verifier) => {
                    let constraints = [verifier];
                    let is_satisfied =
                        cosign::verify_constraints(trusted_layers, constraints.iter());
                    match is_satisfied {
                        Ok(_) => {
                            debug!(
                                "Constraint satisfied:\n{}",
                                &serde_yaml::to_string(signature).unwrap()
                            );
                            false
                        }
                        Err(_) => true, //filter into unsatisfied_signatures
                    }
                }
                Err(error) => {
                    info!(?error, ?signature, "Cannot create verifier for signature");
                    true
                }
            })
            .collect();
        if !unsatisfied_signatures.is_empty() {
            let mut errormsg = "Image verification failed: missing signatures\n".to_string();
            errormsg.push_str("The following constraints were not satisfied:\n");
            for s in unsatisfied_signatures {
                errormsg.push_str(&serde_yaml::to_string(s)?);
            }
            return Err(anyhow!(errormsg));
        }
    }

    if let Some(ref signatures_any_of) = verification_config.any_of {
        let unsatisfied_signatures: Vec<&Signature> = signatures_any_of
            .signatures
            .par_iter()
            .filter(|signature| match signature.verifier() {
                Ok(verifier) => {
                    let constraints = [verifier];
                    cosign::verify_constraints(trusted_layers, constraints.iter()).is_err()
                }
                Err(error) => {
                    info!(?error, ?signature, "Cannot create verifier for signature");
                    true
                }
            })
            .collect();
        {
            let num_satisfied_constraints =
                signatures_any_of.signatures.len() - unsatisfied_signatures.len();
            if num_satisfied_constraints < signatures_any_of.minimum_matches.into() {
                let mut errormsg =
                    format!("Image verification failed: minimum number of signatures not reached: needed {}, got {}", signatures_any_of.minimum_matches, num_satisfied_constraints);
                errormsg.push_str("\nThe following constraints were not satisfied:\n");
                for s in unsatisfied_signatures.iter() {
                    errormsg.push_str(&serde_yaml::to_string(s)?);
                }
                return Err(anyhow!(errormsg));
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use config::{AnyOf, LatestVerificationConfig, Signature, Subject};
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
        let verification_config = LatestVerificationConfig {
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
        let verification_config = LatestVerificationConfig {
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
    fn test_verify_config_not_maching_all_of() {
        // build verification config:
        let signatures_all_of: Vec<Signature> = vec![generic_issuer(
            "https://github.com/login/oauth",
            "user1@provider.com",
        )];
        let verification_config = LatestVerificationConfig {
            all_of: Some(signatures_all_of),
            any_of: None,
        };

        // build trusted layers:
        let trusted_layers: Vec<SignatureLayer> = vec![signature_layer(
            "https://github.com/login/oauth",
            "user-unrelated@provider.com",
        )];

        let error = verify_signatures_against_config(&verification_config, &trusted_layers);
        assert!(error.is_err());
        let expected_msg = r#"Image verification failed: missing signatures
The following constraints were not satisfied:
---
kind: genericIssuer
issuer: "https://github.com/login/oauth"
subject:
  equal: user1@provider.com
annotations: ~
"#;
        assert_eq!(error.unwrap_err().to_string(), expected_msg);
    }

    #[test]
    fn test_verify_config_missing_signatures_all_of() {
        // build verification config:
        let signatures_all_of: Vec<Signature> = vec![
            generic_issuer("https://github.com/login/oauth", "user1@provider.com"),
            generic_issuer("https://github.com/login/oauth", "user2@provider.com"),
            generic_issuer("https://github.com/login/oauth", "user3@provider.com"),
        ];
        let verification_config = LatestVerificationConfig {
            all_of: Some(signatures_all_of),
            any_of: None,
        };

        // build trusted layers:
        let trusted_layers: Vec<SignatureLayer> = vec![
            signature_layer("https://github.com/login/oauth", "user1@provider.com"),
            signature_layer("https://github.com/login/oauth", "user2@provider.com"),
        ];

        let error = verify_signatures_against_config(&verification_config, &trusted_layers);
        assert!(error.is_err());
        let expected_msg = r#"Image verification failed: missing signatures
The following constraints were not satisfied:
---
kind: genericIssuer
issuer: "https://github.com/login/oauth"
subject:
  equal: user3@provider.com
annotations: ~
"#;
        assert_eq!(error.unwrap_err().to_string(), expected_msg);
    }

    #[test]
    fn test_verify_config_missing_signatures_any_of() {
        // build verification config:
        let signatures_any_of: Vec<Signature> = vec![
            generic_issuer("https://github.com/login/oauth", "user1@provider.com"),
            generic_issuer("https://github.com/login/oauth", "user2@provider.com"),
            generic_issuer("https://github.com/login/oauth", "user3@provider.com"),
        ];
        let verification_config = LatestVerificationConfig {
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

        let error = verify_signatures_against_config(&verification_config, &trusted_layers);
        assert!(error.is_err());
        let expected_msg = r#"Image verification failed: minimum number of signatures not reached: needed 2, got 1
The following constraints were not satisfied:
---
kind: genericIssuer
issuer: "https://github.com/login/oauth"
subject:
  equal: user2@provider.com
annotations: ~
---
kind: genericIssuer
issuer: "https://github.com/login/oauth"
subject:
  equal: user3@provider.com
annotations: ~
"#;
        assert_eq!(error.unwrap_err().to_string(), expected_msg);
    }

    #[test]
    fn test_verify_config_quorum_signatures_any_of() {
        // build verification config:
        let signatures_any_of: Vec<Signature> = vec![
            generic_issuer("https://github.com/login/oauth", "user1@provider.com"),
            generic_issuer("https://github.com/login/oauth", "user2@provider.com"),
            generic_issuer("https://github.com/login/oauth", "user3@provider.com"),
        ];
        let verification_config = LatestVerificationConfig {
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
