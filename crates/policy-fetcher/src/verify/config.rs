use anyhow::Result;
use serde::{Deserialize, Deserializer};
use std::{collections::HashMap, fs::File, path::Path};
use url::Url;

#[derive(Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct VerificationSettings {
    pub api_version: String,
    pub all_of: Vec<Signature>,
    pub any_of: Option<AnyOf>,
}

#[derive(Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AnyOf {
    #[serde(default = "default_minimum_matches")]
    pub minimum_matches: String,
    pub signatures: Vec<Signature>,
}

fn default_minimum_matches() -> String {
    "1".to_string()
}

#[derive(Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(rename_all = "camelCase", tag = "kind", deny_unknown_fields)]
pub enum Signature {
    PubKey(PubKey),
    GenericIssuer(GenericIssuer),
    UrlIssuer(UrlIssuer),
    GithubAction(GithubAction),
}

#[derive(Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PubKey {
    pub owner: Option<String>,
    pub key: String,
    pub annotations: Option<HashMap<String, String>>,
}

#[derive(Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GenericIssuer {
    pub issuer: String,
    #[serde(flatten)] // FIXME not supported with deny_unknown_fields, see tests
    pub subject: Subject,
    pub annotations: Option<HashMap<String, String>>,
}

#[derive(Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct UrlIssuer {
    pub url: Url,
    #[serde(flatten)] // FIXME not supported with deny_unknown_fields, see tests
    pub subject: Subject,
    pub annotations: Option<HashMap<String, String>>,
}

#[derive(Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub enum Subject {
    SubjectEqual(String),
    #[serde(deserialize_with = "deserialize_subject_url_prefix")]
    SubjectUrlPrefix(Url),
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

#[derive(Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GithubAction {
    pub owner: String,
    pub repo: Option<String>,
    pub annotations: Option<HashMap<String, String>>,
}

pub fn read_verification_file(path: &Path) -> Result<VerificationSettings> {
    let settings_file = File::open(path)?;
    let vs: VerificationSettings = serde_yaml::from_reader(&settings_file)?;
    Ok(vs)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[should_panic(expected = "invalid type: unit value, expected a sequence")]
    fn test_deserialize_fail_on_empty_signatures() {
        let config = r#"---
apiVersion: v1
allOf:
"#;
        let _vs: VerificationSettings = serde_yaml::from_str(config).unwrap();
    }

    #[test]
    #[should_panic(expected = "no variant of enum Subject found in flattened data")]
    fn test_deserialize_on_missing_flattened_field() {
        let config = r#"---
apiVersion: v1

allOf:
  - kind: urlIssuer
    url: https://token.actions.githubusercontent.com
    # subjectEqual: thisismissing
  - kind: genericIssuer
    issuer: https://token.actions.githubusercontent.com
    subjectUrlPrefix: https://github.com/kubewarden/
"#;
        let _vs: VerificationSettings = serde_yaml::from_str(config).unwrap();
    }

    #[test]
    // Test that using serde's `flatten` and `deny_unknown_fields` works
    // correctly, as they are not supported together.
    fn test_deserialize_flattened_fields() {
        let config = r#"---
apiVersion: v1

allOf:
  - kind: urlIssuer
    url: https://token.actions.githubusercontent.com
    subjectEqual: https://github.com/kubewarden/policy-secure-pod-images/.github/workflows/release.yml@refs/heads/main
  - kind: genericIssuer
    issuer: https://token.actions.githubusercontent.com
    subjectUrlPrefix: https://github.com/kubewarden
"#;

        let vs: VerificationSettings = serde_yaml::from_str(config).unwrap();
        let mut signatures: Vec<Signature> = Vec::new();
        signatures.push(
            Signature::UrlIssuer(
                UrlIssuer {
                    url: Url::parse("https://token.actions.githubusercontent.com").unwrap(),
                    subject: Subject::SubjectEqual("https://github.com/kubewarden/policy-secure-pod-images/.github/workflows/release.yml@refs/heads/main".to_string()),
                    annotations: None
                }
        ));
        signatures.push(Signature::GenericIssuer(GenericIssuer {
            issuer: "https://token.actions.githubusercontent.com".to_string(),
            subject: Subject::SubjectUrlPrefix(
                Url::parse("https://github.com/kubewarden/").unwrap(),
            ),
            annotations: None,
        }));
        let expected: VerificationSettings = VerificationSettings {
            api_version: "v1".to_string(),
            all_of: signatures.clone(),
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
    subjectUrlPrefix: https://github.com/kubewarden # should deserialize path to kubewarden/
  - kind: genericIssuer
    issuer: https://yourdomain.com/oauth2
    subjectUrlPrefix: https://github.com/kubewarden/ # should deserialize path to kubewarden/
"#;
        let vs: VerificationSettings = serde_yaml::from_str(config).unwrap();
        let mut signatures: Vec<Signature> = Vec::new();
        signatures.push(Signature::GenericIssuer(GenericIssuer {
            issuer: "https://token.actions.githubusercontent.com".to_string(),
            subject: Subject::SubjectUrlPrefix(
                Url::parse("https://github.com/kubewarden/").unwrap(),
            ),
            annotations: None,
        }));
        signatures.push(Signature::GenericIssuer(GenericIssuer {
            issuer: "https://yourdomain.com/oauth2".to_string(),
            subject: Subject::SubjectUrlPrefix(
                Url::parse("https://github.com/kubewarden/").unwrap(),
            ),
            annotations: None,
        }));
        let expected: VerificationSettings = VerificationSettings {
            api_version: "v1".to_string(),
            all_of: signatures.clone(),
            any_of: None,
        };
        assert_eq!(vs, expected);
    }
}
