use anyhow::{anyhow, Result};
use serde::{Deserialize, Deserializer, Serialize};
use sigstore::{
    cosign::verification_constraint::VerificationConstraint, crypto::SignatureDigestAlgorithm,
};
use std::boxed::Box;
use std::{collections::HashMap, fs::File, path::Path};
use url::Url;

use crate::verify::verification_constraints;

/// Alias to the type that is currently used to store the
/// verification settings.
///
/// When a new version is created:
/// * Update this stype to point to the new version
/// * Implement `TryFrom` that goes from (v - 1) to (v)
pub type LatestVerificationConfig = VerificationConfigV1;

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct VerificationConfigV1 {
    pub all_of: Option<Vec<Signature>>,
    pub any_of: Option<AnyOf>,
}

/// Enum that holds all the known versions of the configuration file
///
/// An unsupported version is a object that has `apiVersion` with an
/// unknown value (e.g: 1000)
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(tag = "apiVersion", rename_all = "camelCase", deny_unknown_fields)]
pub enum VersionedVerificationConfig {
    #[serde(rename = "v1")]
    V1(VerificationConfigV1),
    #[serde(other)]
    Unsupported,
}

/// Enum that distinguish between a well formed (but maybe unknown) version of
/// the verification config, and something which is "just wrong".
#[derive(Debug, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum VerificationConfig {
    Versioned(VersionedVerificationConfig),
    Invalid(serde_json::Value),
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AnyOf {
    #[serde(default = "default_minimum_matches")]
    pub minimum_matches: u8,
    pub signatures: Vec<Signature>,
}

fn default_minimum_matches() -> u8 {
    1
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(rename_all = "camelCase", tag = "kind", deny_unknown_fields)]
pub enum Signature {
    PubKey {
        owner: Option<String>,
        key: String,
        annotations: Option<HashMap<String, String>>,
    },
    GenericIssuer {
        issuer: String,
        subject: Subject,
        annotations: Option<HashMap<String, String>>,
    },
    GithubAction {
        owner: String,
        repo: Option<String>,
        annotations: Option<HashMap<String, String>>,
    },
}

impl Signature {
    pub fn verifier(&self) -> Result<Box<dyn VerificationConstraint>> {
        match self {
            Signature::PubKey {
                owner,
                key,
                annotations,
            } => {
                let vc = verification_constraints::PublicKeyAndAnnotationsVerifier::new(
                    owner.as_ref().map(|r| r.as_str()),
                    key,
                    SignatureDigestAlgorithm::default(),
                    annotations.as_ref(),
                )
                .map_err(|e| anyhow!("Cannot create public key verifier: {}", e))?;
                Ok(Box::new(vc))
            }
            Signature::GenericIssuer {
                issuer,
                subject,
                annotations,
            } => Ok(Box::new(
                verification_constraints::GenericIssuerSubjectVerifier::new(
                    issuer,
                    subject,
                    annotations.as_ref(),
                ),
            )),
            Signature::GithubAction {
                owner,
                repo,
                annotations,
            } => Ok(Box::new(verification_constraints::GitHubVerifier::new(
                owner,
                repo.as_ref().map(|r| r.as_str()),
                annotations.as_ref(),
            ))),
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub enum Subject {
    Equal(String),
    #[serde(deserialize_with = "deserialize_subject_url_prefix")]
    UrlPrefix(Url),
}

fn deserialize_subject_url_prefix<'de, D>(deserializer: D) -> Result<Url, D::Error>
where
    D: Deserializer<'de>,
{
    let mut url = Url::deserialize(deserializer)?;
    if !url.path().ends_with('/') {
        // sanitize url prefix path by postfixing `/`, to prevent
        // `https://github.com/kubewarden` matching
        // `https://github.com/kubewarden-malicious/`
        url.set_path(format!("{}{}", url.path(), '/').as_str());
    }
    Ok(url)
}

pub fn read_verification_file(path: &Path) -> Result<LatestVerificationConfig> {
    let config_file = File::open(path)?;
    let config: VerificationConfig = serde_yaml::from_reader(&config_file)?;

    let config = match config {
        VerificationConfig::Versioned(versioned_config) => match versioned_config {
            VersionedVerificationConfig::V1(c) => c,
            VersionedVerificationConfig::Unsupported => {
                return Err(anyhow!(
                    "Not a supported configuration version: {:?}",
                    versioned_config
                ))
            }
        },
        VerificationConfig::Invalid(value) => {
            return Err(anyhow!("Not a valid configuration file: {:?}", value))
        }
    };

    if config.all_of.is_none() && config.any_of.is_none() {
        return Err(anyhow!(
            "config is missing signatures in both allOf and anyOff list"
        ));
    }
    Ok(config)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_deserialize_on_missing_signature() {
        let config = r#"---
    apiVersion: v1

    allOf:
      - kind: genericIssuer
        issuer: https://token.actions.githubusercontent.com
        # missing subject
        #subject:
        #   urlPrefix: https://github.com/kubewarden/
    "#;
        let vc: VerificationConfig = serde_yaml::from_str(config).unwrap();
        assert!(matches!(vc, VerificationConfig::Invalid(_)));
    }

    #[test]
    fn test_deserialize() {
        let config = r#"---
    apiVersion: v1

    allOf:
      - kind: genericIssuer
        issuer: https://token.actions.githubusercontent.com
        subject:
           equal: https://github.com/kubewarden/policy-secure-pod-images/.github/workflows/release.yml@refs/heads/main
      - kind: genericIssuer
        issuer: https://token.actions.githubusercontent.com
        subject:
           urlPrefix: https://github.com/kubewarden
    "#;

        let vc: VerificationConfig = serde_yaml::from_str(config).unwrap();
        let signatures: Vec<Signature> = vec![
            Signature::GenericIssuer {
                    issuer: "https://token.actions.githubusercontent.com".to_string(),
                    subject: Subject::Equal("https://github.com/kubewarden/policy-secure-pod-images/.github/workflows/release.yml@refs/heads/main".to_string()),
                    annotations: None
                },
            Signature::GenericIssuer {
                issuer: "https://token.actions.githubusercontent.com".to_string(),
                subject: Subject::UrlPrefix(Url::parse("https://github.com/kubewarden/").unwrap()),
                annotations: None,
            }
        ];

        match vc {
            VerificationConfig::Versioned(versioned) => match versioned {
                VersionedVerificationConfig::V1(v1) => {
                    let expected = VerificationConfigV1 {
                        all_of: Some(signatures),
                        any_of: None,
                    };
                    assert_eq!(v1, expected);
                }
                _ => panic!("not the expected versioned config"),
            },
            _ => panic!("got an invalid config"),
        }
    }

    #[test]
    fn test_sanitize_url_prefix() {
        let config = r#"---
    apiVersion: v1

    allOf:
      - kind: genericIssuer
        issuer: https://token.actions.githubusercontent.com
        subject:
           urlPrefix: https://github.com/kubewarden # should deserialize path to kubewarden/
      - kind: genericIssuer
        issuer: https://yourdomain.com/oauth2
        subject:
           urlPrefix: https://github.com/kubewarden/ # should deserialize path to kubewarden/
    "#;
        let vc: VerificationConfig = serde_yaml::from_str(config).unwrap();
        let signatures: Vec<Signature> = vec![
            Signature::GenericIssuer {
                issuer: "https://token.actions.githubusercontent.com".to_string(),
                subject: Subject::UrlPrefix(Url::parse("https://github.com/kubewarden/").unwrap()),
                annotations: None,
            },
            Signature::GenericIssuer {
                issuer: "https://yourdomain.com/oauth2".to_string(),
                subject: Subject::UrlPrefix(Url::parse("https://github.com/kubewarden/").unwrap()),
                annotations: None,
            },
        ];

        match vc {
            VerificationConfig::Versioned(versioned) => match versioned {
                VersionedVerificationConfig::V1(v1) => {
                    let expected = VerificationConfigV1 {
                        all_of: Some(signatures),
                        any_of: None,
                    };
                    assert_eq!(v1, expected);
                }
                _ => panic!("not the expected versioned config"),
            },
            _ => panic!("got an invalid config"),
        }
    }
}
