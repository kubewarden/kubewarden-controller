use anyhow::{anyhow, Result};
use serde::{Deserialize, Deserializer, Serialize};
use sigstore::{
    cosign::verification_constraint::VerificationConstraint, crypto::SignatureDigestAlgorithm,
};
use std::boxed::Box;
use std::{collections::HashMap, fs::File, path::Path};
use url::Url;

use crate::verify::verification_constraints;

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct VerificationSettings {
    pub api_version: String,
    pub all_of: Option<Vec<Signature>>,
    pub any_of: Option<AnyOf>,
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

pub fn read_verification_file(path: &Path) -> Result<VerificationSettings> {
    let settings_file = File::open(path)?;
    let vs: VerificationSettings = serde_yaml::from_reader(&settings_file)?;
    if vs.all_of.is_none() && vs.any_of.is_none() {
        return Err(anyhow!(
            "config is missing signatures in both allOf and anyOff list"
        ));
    }
    Ok(vs)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[should_panic(expected = "missing field `subject`")]
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
        let _vs: VerificationSettings = serde_yaml::from_str(config).unwrap();
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

        let vs: VerificationSettings = serde_yaml::from_str(config).unwrap();
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
        let expected: VerificationSettings = VerificationSettings {
            api_version: "v1".to_string(),
            all_of: Some(signatures),
            any_of: None,
        };
        assert_eq!(vs, expected);
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
        let vs: VerificationSettings = serde_yaml::from_str(config).unwrap();
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
        let expected: VerificationSettings = VerificationSettings {
            api_version: "v1".to_string(),
            all_of: Some(signatures),
            any_of: None,
        };
        assert_eq!(vs, expected);
    }
}
