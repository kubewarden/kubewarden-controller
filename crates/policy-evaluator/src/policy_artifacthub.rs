use email_address::*;
use mail_parser::*;
use semver::Version;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::str::FromStr;
use time::OffsetDateTime;
use url::Url;

use crate::constants::{
    ARTIFACTHUB_ANNOTATION_KUBEWARDEN_CONTEXTAWARE, ARTIFACTHUB_ANNOTATION_KUBEWARDEN_MUTATION,
    ARTIFACTHUB_ANNOTATION_KUBEWARDEN_QUESTIONSUI, ARTIFACTHUB_ANNOTATION_KUBEWARDEN_RESOURCES,
    ARTIFACTHUB_ANNOTATION_KUBEWARDEN_RULES, ARTIFACTHUB_ANNOTATION_RANCHER_HIDDENUI,
    KUBEWARDEN_ANNOTATION_ARTIFACTHUB_DISPLAYNAME, KUBEWARDEN_ANNOTATION_ARTIFACTHUB_KEYWORDS,
    KUBEWARDEN_ANNOTATION_ARTIFACTHUB_RESOURCES, KUBEWARDEN_ANNOTATION_POLICY_AUTHOR,
    KUBEWARDEN_ANNOTATION_POLICY_DESCRIPTION, KUBEWARDEN_ANNOTATION_POLICY_LICENSE,
    KUBEWARDEN_ANNOTATION_POLICY_OCIURL, KUBEWARDEN_ANNOTATION_POLICY_SOURCE,
    KUBEWARDEN_ANNOTATION_POLICY_TITLE, KUBEWARDEN_ANNOTATION_POLICY_URL,
    KUBEWARDEN_ANNOTATION_POLICY_USAGE, KUBEWARDEN_ANNOTATION_RANCHER_HIDDENUI,
};
use crate::errors::ArtifactHubError;
use crate::policy_metadata::Metadata;

pub type Result<T> = std::result::Result<T, ArtifactHubError>;

/// Partial implementation of the format of artifacthub-pkg.yml file as defined
/// in
/// https://github.com/artifacthub/hub/blob/master/docs/metadata/artifacthub-pkg.yml
/// and
/// https://artifacthub.io/docs/topics/repositories/kubewarden-policies
#[derive(Deserialize, Serialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct ArtifactHubPkg {
    /// Semver version of the policy, e.g: "0.2.0"
    version: Version,
    /// ArtifactHub package name, e.g: verify-image-signatures
    name: String,
    /// Display name, e.g: Verify Image Signatures
    display_name: String,
    /// Time at creation in RFC3339 format, e.g: 2023-01-19T14:46:21+02:00
    #[serde(with = "time::serde::rfc3339")]
    created_at: OffsetDateTime,
    /// One-line description of policy
    description: String,
    /// License in SPDX format, e.g: Apache-2.0
    #[serde(skip_serializing_if = "Option::is_none")]
    license: Option<String>,
    /// Home URL of policy (source repository)
    /// E.g:  https://github.com/kubewarden/verify-image-signatures
    #[serde(rename = "homeURL", skip_serializing_if = "Option::is_none")]
    home_url: Option<Url>,
    /// List of images of the ArtifactHub package
    /// E.g: ("policy", <url to wasm module>)
    #[serde(skip_serializing_if = "Option::is_none")]
    containers_images: Option<Vec<ContainerImage>>,
    /// List of keywords. E.g: ["pod", "signature", "sigstore"]
    #[serde(skip_serializing_if = "Option::is_none")]
    keywords: Option<Vec<String>>,
    /// List of links in tuple (name, url) format
    /// E.g: {"policy", <url>}, {"source", <url>}
    #[serde(skip_serializing_if = "Option::is_none")]
    links: Option<Vec<Link>>,
    /// List of maintainers in tuple (name, email) format
    #[serde(skip_serializing_if = "Option::is_none")]
    maintainers: Option<Vec<Maintainer>>,
    /// Provider of policy, for us, hardcoded to {name: "kubewarden"}
    provider: Provider,
    /// Recommendations of policy, for us, hardcoded to:
    /// [{url: <url of kubewarden controller repo>}]
    recommendations: Vec<Recommendation>,
    /// List of annotations. Contains kubewarden-specific annotations
    annotations: HashMap<String, String>,
    /// Multiline package documentation in Markdown format. For us, policy
    /// readme file
    #[serde(skip_serializing_if = "Option::is_none")]
    readme: Option<String>,
}

#[derive(Deserialize, Serialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
struct ContainerImage {
    /// name is always "policy"
    name: ConstContainerImageName,
    /// URL of the policy wasm module
    /// E.g: ghcr.io/kubewarden/policies/verify-image-signatures:v0.2.1
    image: String,
}

#[derive(Deserialize, Serialize, Debug, Clone)]
enum ConstContainerImageName {
    #[serde(rename = "policy")]
    Policy,
}

/// Link, of either the policy wasm module or the policy source repository
/// Example:
///  - name: policy
///    url: https://github.com/kubewarden/verify-image-signatures/releases/download/v0.2.1/policy.wasm
///  - name: source
///    url: https://github.com/kubewarden/verify-image-signatures
#[derive(Deserialize, Serialize, Debug, Clone, PartialEq)]
struct Link {
    /// Either "policy" or "source"
    name: ConstLinkName,
    /// Either URL of policy repository or URL of policy wasm module
    url: Url,
}

#[derive(Deserialize, Serialize, Debug, Clone, PartialEq)]
enum ConstLinkName {
    #[serde(rename = "policy")]
    Policy,
    #[serde(rename = "source")]
    Source,
}

/// Hardcoded recommendation with url of kubewarden controller
#[derive(Deserialize, Serialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
struct Recommendation {
    url: String,
}
impl Default for Recommendation {
    fn default() -> Self {
        Recommendation {
            url: String::from(
                "https://artifacthub.io/packages/helm/kubewarden/kubewarden-controller",
            ),
        }
    }
}

#[derive(Deserialize, Serialize, Debug, Clone, PartialEq)]
#[serde(rename_all = "camelCase")]
struct Maintainer {
    name: String,
    email: String,
}

/// Hardcoded provider with "kubewarden"
#[derive(Deserialize, Serialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
struct Provider {
    name: String,
}
impl Default for Provider {
    fn default() -> Self {
        Provider {
            name: String::from("kubewarden"),
        }
    }
}

impl ArtifactHubPkg {
    pub fn from_metadata(
        metadata: &Metadata,
        version: &str,
        created_at: OffsetDateTime,
        questions: Option<&str>,
    ) -> Result<Self> {
        // validate inputs
        if metadata.annotations.is_none() {
            return Err(ArtifactHubError::NoAnnotations);
        }
        let metadata_annots = metadata.annotations.as_ref().unwrap();
        if metadata_annots.is_empty() {
            return Err(ArtifactHubError::NoAnnotations);
        }
        let semver_version = Version::parse(version)
            .map_err(|e| ArtifactHubError::NoSemverVersion(e.to_string()))?;
        if questions
            .and_then(|q| if q.is_empty() { Some(q) } else { None })
            .is_some()
        {
            return Err(ArtifactHubError::EmptyQuestionsUI);
        }

        // build struct
        let name = parse_name(metadata_annots)?;
        let display_name = parse_display_name(metadata_annots)?;
        let description = parse_description(metadata_annots)?;
        let home_url = parse_home_url(metadata_annots)?;
        let containers_images = parse_containers_images(metadata_annots, &semver_version)?;
        let keywords = parse_keywords(metadata_annots)?;
        let links = parse_links(metadata_annots, &semver_version)?;
        let maintainers = parse_maintainers(metadata_annots)?;
        let annotations = parse_annotations(metadata_annots, metadata, questions)?;
        let readme = parse_readme(metadata_annots)?;

        let artifacthubpkg = ArtifactHubPkg {
            version: semver_version,
            name,
            display_name,
            created_at,
            description,
            license: metadata_annots
                .get(KUBEWARDEN_ANNOTATION_POLICY_LICENSE)
                .cloned(),
            home_url,
            containers_images,
            keywords,
            links,
            maintainers,
            provider: Default::default(),
            recommendations: vec![Recommendation::default()],
            annotations,
            readme,
        };

        Ok(artifacthubpkg)
    }
}

fn parse_name(metadata_annots: &HashMap<String, String>) -> Result<String> {
    metadata_annots
        .get(KUBEWARDEN_ANNOTATION_POLICY_TITLE)
        .ok_or_else(|| {
            ArtifactHubError::MissingAnnotation(String::from(KUBEWARDEN_ANNOTATION_POLICY_TITLE))
        })
        .cloned()
}

fn parse_display_name(metadata_annots: &HashMap<String, String>) -> Result<String> {
    metadata_annots
        .get(KUBEWARDEN_ANNOTATION_ARTIFACTHUB_DISPLAYNAME)
        .ok_or_else(|| {
            ArtifactHubError::MissingAnnotation(String::from(
                KUBEWARDEN_ANNOTATION_ARTIFACTHUB_DISPLAYNAME,
            ))
        })
        .cloned()
}

fn parse_description(metadata_annots: &HashMap<String, String>) -> Result<String> {
    metadata_annots
        .get(KUBEWARDEN_ANNOTATION_POLICY_DESCRIPTION)
        .ok_or_else(|| {
            ArtifactHubError::MissingAnnotation(String::from(
                KUBEWARDEN_ANNOTATION_POLICY_DESCRIPTION,
            ))
        })
        .cloned()
}

fn parse_home_url(metadata_annots: &HashMap<String, String>) -> Result<Option<Url>> {
    match metadata_annots.get(KUBEWARDEN_ANNOTATION_POLICY_URL) {
        Some(s) => {
            let url = Url::parse(s).map_err(|e| ArtifactHubError::MalformedURL {
                annot: String::from(KUBEWARDEN_ANNOTATION_POLICY_URL),
                error: e.to_string(),
            })?;
            Ok(Some(url))
        }
        None => Ok(None),
    }
}

fn parse_containers_images(
    metadata_annots: &HashMap<String, String>,
    version: &Version,
) -> Result<Option<Vec<ContainerImage>>> {
    match metadata_annots.get(KUBEWARDEN_ANNOTATION_POLICY_OCIURL) {
        Some(s) => {
            let oci_url = Url::parse(format!("{}:v{}", s, version.to_string().as_str()).as_str())
                .map_err(|e| ArtifactHubError::MalformedURL {
                annot: String::from(KUBEWARDEN_ANNOTATION_POLICY_OCIURL),
                error: e.to_string(),
            })?;
            let container_images = vec![ContainerImage {
                name: ConstContainerImageName::Policy,
                image: oci_url.to_string(),
            }];
            Ok(Some(container_images))
        }
        None => Err(ArtifactHubError::MissingAnnotation(String::from(
            KUBEWARDEN_ANNOTATION_POLICY_OCIURL,
        ))),
    }
}

/// parses the value of annotation KUBEWARDEN_ANNOTATION_ARTIFACTHUB_KEYWORDS of
/// csv of keywords into a vector of keywords, making sure is well formed
fn parse_keywords(metadata_annots: &HashMap<String, String>) -> Result<Option<Vec<String>>> {
    match metadata_annots.get(KUBEWARDEN_ANNOTATION_ARTIFACTHUB_KEYWORDS) {
        Some(s) => {
            let csv = s
                .split(',')
                .map(|s| s.trim_start_matches(' '))
                .map(|s| s.trim_end_matches(' '))
                .map(str::to_string)
                .collect::<Vec<String>>();
            if csv.clone().into_iter().any(|word| word.is_empty()) {
                Err(ArtifactHubError::MalformedCSV(String::from(
                    KUBEWARDEN_ANNOTATION_ARTIFACTHUB_KEYWORDS,
                )))
            } else {
                Ok(Some(csv))
            }
        }
        None => Ok(None),
    }
}

/// parses the value of annotation KUBEWARDEN_ANNOTATION_POLICY_SOURCE
/// into a vector of Link, making sure is well formed
fn parse_links(
    metadata_annots: &HashMap<String, String>,
    version: &Version,
) -> Result<Option<Vec<Link>>> {
    match metadata_annots.get(KUBEWARDEN_ANNOTATION_POLICY_SOURCE) {
        Some(s) => {
            let policy_source = Url::parse(s).map_err(|e| ArtifactHubError::MalformedURL {
                annot: String::from(KUBEWARDEN_ANNOTATION_POLICY_SOURCE),
                error: e.to_string(),
            })?;
            match policy_source.host_str() == Some("github.com") {
                true => {
                    let url = Url::parse(
                        format!(
                            "{}/releases/download/v{}/policy.wasm",
                            policy_source.as_str(),
                            version.to_string().as_str(),
                        )
                        .as_str(),
                    )
                    .map_err(|e| ArtifactHubError::MalformedURL {
                        annot: String::from(KUBEWARDEN_ANNOTATION_POLICY_SOURCE),
                        error: e.to_string(),
                    })?;
                    Ok(Some(vec![
                        Link {
                            name: ConstLinkName::Policy,
                            url,
                        },
                        Link {
                            name: ConstLinkName::Source,
                            url: policy_source,
                        },
                    ]))
                }
                false => Ok(Some(vec![Link {
                    name: ConstLinkName::Source,
                    url: policy_source,
                }])),
            }
        }
        None => Ok(None),
    }
}

// parses the value of annotation KUBEWARDEN_ANNOTATION_POLICY_AUTHOR into a
// vector of maintainers, making sure the csv input and emails are well formed
fn parse_maintainers(metadata_annots: &HashMap<String, String>) -> Result<Option<Vec<Maintainer>>> {
    match metadata_annots.get(KUBEWARDEN_ANNOTATION_POLICY_AUTHOR) {
        Some(s) => {
            // name-addr https://www.rfc-editor.org/rfc/rfc5322#section-3.4
            let mut maintainers: Vec<Maintainer> = vec![];
            let to = format!("To: {}", s);
            let msg = mail_parser::Message::parse(to.as_bytes()).ok_or(
                ArtifactHubError::MalformedCSVEmail(String::from(
                    KUBEWARDEN_ANNOTATION_POLICY_AUTHOR,
                )),
            )?;

            let addr = msg.to();

            match addr {
                HeaderValue::Address(addr) => {
                    let email = EmailAddress::from_str(&addr.address.clone().unwrap_or_default())
                        .map_err(|e| ArtifactHubError::MalformedEmail {
                        annot: String::from(KUBEWARDEN_ANNOTATION_POLICY_AUTHOR),
                        error: e.to_string(),
                    })?;

                    maintainers.push(Maintainer {
                        name: addr.name.clone().unwrap_or_default().to_string(),
                        email: email.to_string(),
                    });
                }
                HeaderValue::AddressList(vec_addr) => {
                    for a in vec_addr {
                        let email = EmailAddress::from_str(&a.address.clone().unwrap_or_default())
                            .map_err(|e| ArtifactHubError::MalformedEmail {
                                annot: String::from(KUBEWARDEN_ANNOTATION_POLICY_AUTHOR),
                                error: e.to_string(),
                            })?;
                        maintainers.push(Maintainer {
                            name: a.name.clone().unwrap_or_default().to_string(),
                            email: email.to_string(),
                        });
                    }
                }
                _ => {
                    return Err(ArtifactHubError::MalformedCSVEmail(String::from(
                        KUBEWARDEN_ANNOTATION_POLICY_AUTHOR,
                    )))
                }
            }
            Ok(Some(maintainers))
        }
        None => Ok(None),
    }
}

fn parse_annotations(
    metadata_annots: &HashMap<String, String>,
    metadata: &Metadata,
    questions: Option<&str>,
) -> Result<HashMap<String, String>> {
    // add required annotations
    let mut annotations: HashMap<String, String> = HashMap::new();
    annotations.insert(
        ARTIFACTHUB_ANNOTATION_KUBEWARDEN_MUTATION.to_string(),
        metadata.mutating.to_string(),
    );
    annotations.insert(
        ARTIFACTHUB_ANNOTATION_KUBEWARDEN_CONTEXTAWARE.to_string(),
        metadata.context_aware.to_string(),
    );
    annotations.insert(
        ARTIFACTHUB_ANNOTATION_KUBEWARDEN_RULES.to_string(),
        serde_json::to_string(&metadata.rules).unwrap(),
    );

    // add optional annotations
    if let Some(s) = questions {
        annotations.insert(
            ARTIFACTHUB_ANNOTATION_KUBEWARDEN_QUESTIONSUI.to_string(),
            s.to_string(),
        );
    };
    if let Some(string_bool) = metadata_annots.get(KUBEWARDEN_ANNOTATION_RANCHER_HIDDENUI) {
        annotations.insert(
            ARTIFACTHUB_ANNOTATION_RANCHER_HIDDENUI.to_string(),
            FromStr::from_str(string_bool).map_err(|_| {
                ArtifactHubError::MalformedBoolString(String::from(
                    KUBEWARDEN_ANNOTATION_RANCHER_HIDDENUI,
                ))
            })?,
        );
    };
    if let Some(s) = metadata_annots.get(KUBEWARDEN_ANNOTATION_ARTIFACTHUB_RESOURCES) {
        annotations.insert(
            ARTIFACTHUB_ANNOTATION_KUBEWARDEN_RESOURCES.to_string(),
            s.to_string(),
        );
    };

    Ok(annotations)
}

fn parse_readme(metadata_annots: &HashMap<String, String>) -> Result<Option<String>> {
    match metadata_annots.get(KUBEWARDEN_ANNOTATION_POLICY_USAGE) {
        Some(s) => Ok(Some(s.to_string())),
        None => Err(ArtifactHubError::MissingAnnotation(String::from(
            KUBEWARDEN_ANNOTATION_POLICY_USAGE,
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use assert_json_diff::assert_json_eq;
    use serde_json::json;
    use std::collections::HashMap;

    fn mock_metadata_with_minimum_required() -> Metadata {
        Metadata {
            protocol_version: None,
            rules: vec![],
            annotations: Some(HashMap::from([
                (
                    String::from(KUBEWARDEN_ANNOTATION_POLICY_TITLE),
                    String::from("verify-image-signatures"),
                ),
                (
                    String::from(KUBEWARDEN_ANNOTATION_ARTIFACTHUB_DISPLAYNAME),
                    String::from("Verify Image Signatures"),
                ),
                (
                    String::from(KUBEWARDEN_ANNOTATION_POLICY_DESCRIPTION),
                    String::from("A description"),
                ),
                (
                    String::from(KUBEWARDEN_ANNOTATION_POLICY_OCIURL),
                    String::from("https://github.com/ocirepo"),
                ),
                (
                    String::from(KUBEWARDEN_ANNOTATION_ARTIFACTHUB_RESOURCES),
                    String::from("Pod, Deployment"),
                ),
                (
                    String::from(KUBEWARDEN_ANNOTATION_POLICY_USAGE),
                    String::from("readme contents"),
                ),
            ])),
            mutating: false,
            background_audit: true,
            context_aware: false,
            execution_mode: Default::default(),
        }
    }

    fn mock_metadata_with_all() -> Metadata {
        Metadata {
            protocol_version: None,
            rules: vec![],
            annotations: Some(HashMap::from([
                (
                    String::from(KUBEWARDEN_ANNOTATION_POLICY_TITLE),
                    String::from("verify-image-signatures"),
                ),
                (
                    String::from(KUBEWARDEN_ANNOTATION_POLICY_DESCRIPTION),
                    String::from("A description"),
                ),
                (
                    String::from(KUBEWARDEN_ANNOTATION_POLICY_AUTHOR),
                    String::from("Tux Tuxedo <tux@example.com>, Pidgin <pidgin@example.com>"),
                ),
                (
                    String::from(KUBEWARDEN_ANNOTATION_POLICY_URL),
                    String::from("https://github.com/home"),
                ),
                (
                    String::from(KUBEWARDEN_ANNOTATION_POLICY_OCIURL),
                    String::from("https://github.com/ocirepo"),
                ),
                (
                    String::from(KUBEWARDEN_ANNOTATION_POLICY_SOURCE),
                    String::from("https://github.com/repo"),
                ),
                (
                    String::from(KUBEWARDEN_ANNOTATION_POLICY_LICENSE),
                    String::from("Apache-2.0"),
                ),
                (
                    String::from(KUBEWARDEN_ANNOTATION_POLICY_USAGE),
                    String::from("readme contents"),
                ),
                (
                    String::from(KUBEWARDEN_ANNOTATION_ARTIFACTHUB_RESOURCES),
                    String::from("Pod, Deployment"),
                ),
                (
                    String::from(KUBEWARDEN_ANNOTATION_ARTIFACTHUB_DISPLAYNAME),
                    String::from("Verify Image Signatures"),
                ),
                (
                    String::from(KUBEWARDEN_ANNOTATION_ARTIFACTHUB_KEYWORDS),
                    String::from("pod, signature"),
                ),
                (
                    String::from(KUBEWARDEN_ANNOTATION_RANCHER_HIDDENUI),
                    String::from("true"),
                ),
            ])),
            mutating: false,
            background_audit: true,
            context_aware: false,
            execution_mode: Default::default(),
        }
    }

    #[test]
    fn artifacthubpkg_validate_inputs() -> Result<()> {
        // check annotations None
        let arthub = ArtifactHubPkg::from_metadata(
            &Metadata::default(),
            "0.2.1",
            OffsetDateTime::UNIX_EPOCH,
            None,
        );
        assert_eq!(
            arthub.unwrap_err().to_string(),
            "no annotations in policy metadata. policy metadata must specify annotations"
        );

        // check annotations empty
        let metadata = Metadata {
            annotations: Some(HashMap::from([])),
            ..Default::default()
        };
        let arthub =
            ArtifactHubPkg::from_metadata(&metadata, "0.2.1", OffsetDateTime::UNIX_EPOCH, None);
        assert_eq!(
            arthub.unwrap_err().to_string(),
            "no annotations in policy metadata. policy metadata must specify annotations"
        );

        // check version is semver
        let arthub = ArtifactHubPkg::from_metadata(
            &mock_metadata_with_minimum_required(),
            "not-semver",
            OffsetDateTime::UNIX_EPOCH,
            None,
        );
        assert_eq!(
            arthub.unwrap_err().to_string(),
            "policy version must be in semver: unexpected character 'n' while parsing major version number"
        );

        // check questions is some and not empty
        let metadata = Metadata {
            annotations: Some(HashMap::from([(String::from("foo"), String::from("bar"))])),
            ..Default::default()
        };
        let arthub =
            ArtifactHubPkg::from_metadata(&metadata, "0.2.1", OffsetDateTime::UNIX_EPOCH, Some(""));
        assert_eq!(
            arthub.unwrap_err().to_string(),
            "questions-ui content cannot be empty"
        );

        Ok(())
    }

    #[test]
    fn check_parse_keywords() -> Result<()> {
        let keywords_annot = HashMap::from([(
            String::from(KUBEWARDEN_ANNOTATION_ARTIFACTHUB_KEYWORDS),
            String::from(" foo,bar, faz fiz, baz"),
        )]);
        let keywords_annot_empty = HashMap::from([(
            String::from(KUBEWARDEN_ANNOTATION_ARTIFACTHUB_KEYWORDS),
            String::from(""),
        )]);
        let keywords_annot_commas = HashMap::from([(
            String::from(KUBEWARDEN_ANNOTATION_ARTIFACTHUB_KEYWORDS),
            String::from("foo,,bar"),
        )]);

        assert_eq!(
            parse_keywords(&keywords_annot).unwrap(),
            Some(
                vec!["foo", "bar", "faz fiz", "baz"]
                    .into_iter()
                    .map(str::to_string)
                    .collect()
            )
        );
        assert_eq!(
            parse_keywords(&keywords_annot_empty)
                .unwrap_err()
                .to_string(),
            format!(
                "annotation \"{}\" in policy metadata is malformed, must be csv values",
                KUBEWARDEN_ANNOTATION_ARTIFACTHUB_KEYWORDS
            )
        );
        assert_eq!(
            parse_keywords(&keywords_annot_commas)
                .unwrap_err()
                .to_string(),
            format!(
                "annotation \"{}\" in policy metadata is malformed, must be csv values",
                KUBEWARDEN_ANNOTATION_ARTIFACTHUB_KEYWORDS
            )
        );
        Ok(())
    }

    #[test]
    fn check_parse_links() -> Result<()> {
        let semver_version = Version::parse("0.2.1").unwrap();
        let source_annot = HashMap::from([(
            String::from(KUBEWARDEN_ANNOTATION_POLICY_SOURCE),
            String::from("https://github.com/repo"),
        )]);
        let source_annot_not_github = HashMap::from([(
            String::from(KUBEWARDEN_ANNOTATION_POLICY_SOURCE),
            String::from("https://notgithub.com/repo"),
        )]);
        let source_annot_badurl = HashMap::from([(
            String::from(KUBEWARDEN_ANNOTATION_POLICY_SOURCE),
            String::from("@&*foo"),
        )]);

        assert_eq!(
            parse_links(&source_annot, &semver_version).unwrap(),
            Some(vec![
                Link {
                    name: ConstLinkName::Policy,
                    url: Url::parse("https://github.com/repo/releases/download/v0.2.1/policy.wasm")
                        .unwrap(),
                },
                Link {
                    name: ConstLinkName::Source,
                    url: Url::parse("https://github.com/repo").unwrap(),
                }
            ])
        );
        assert_eq!(
            parse_links(&source_annot_not_github, &semver_version).unwrap(),
            Some(vec![Link {
                name: ConstLinkName::Source,
                url: Url::parse("https://notgithub.com/repo").unwrap(),
            }])
        );
        assert!(parse_links(&source_annot_badurl, &semver_version).is_err());

        Ok(())
    }

    #[test]
    fn check_parse_maintainers() -> Result<()> {
        let author_annot = HashMap::from([(
            String::from(KUBEWARDEN_ANNOTATION_POLICY_AUTHOR),
            String::from("Tux Tuxedo <tux@example.com>, Pidgin <pidgin@example.com>"),
        )]);
        let author_annot_empty = HashMap::from([(
            String::from(KUBEWARDEN_ANNOTATION_POLICY_AUTHOR),
            String::from(""),
        )]);
        let author_annot_commas = HashMap::from([(
            String::from(KUBEWARDEN_ANNOTATION_POLICY_AUTHOR),
            String::from("Foo <foo@example.com>,,Bar <bar@example.com>"),
        )]);
        let author_annot_nameemail = HashMap::from([(
            String::from(KUBEWARDEN_ANNOTATION_POLICY_AUTHOR),
            String::from("Foo foo@example.com, Bar <bar@example.com>"),
        )]);
        let author_annot_bademail = HashMap::from([(
            String::from(KUBEWARDEN_ANNOTATION_POLICY_AUTHOR),
            String::from("Bar <#$%#$%>"),
        )]);

        assert_eq!(
            parse_maintainers(&author_annot).unwrap(),
            Some(vec![
                Maintainer {
                    name: String::from("Tux Tuxedo"),
                    email: String::from("tux@example.com"),
                },
                Maintainer {
                    name: String::from("Pidgin"),
                    email: String::from("pidgin@example.com"),
                }
            ])
        );
        assert_eq!(
            parse_maintainers(&author_annot_empty)
                .unwrap_err()
                .to_string(),
            format!(
                "annotation \"{}\" in policy metadata is malformed, must be csv values of \"name <email>\"",
                KUBEWARDEN_ANNOTATION_POLICY_AUTHOR
            )
        );

        assert_eq!(
            parse_maintainers(&author_annot_commas).unwrap(),
            Some(vec![
                Maintainer {
                    name: String::from("Foo"),
                    email: String::from("foo@example.com"),
                },
                Maintainer {
                    name: String::from("Bar"),
                    email: String::from("bar@example.com"),
                }
            ])
        );
        assert!(parse_maintainers(&author_annot_nameemail).is_err());
        assert!(parse_maintainers(&author_annot_bademail).is_err());
        Ok(())
    }

    #[test]
    fn artifacthubpkg_missing_required() -> Result<()> {
        let semver_version = Version::parse("0.2.1").unwrap();
        let invalid_annotations = HashMap::from([(String::from("foo"), String::from("bar"))]);

        assert!(parse_name(&invalid_annotations).is_err());
        assert!(parse_display_name(&invalid_annotations).is_err());
        assert_eq!(
            parse_containers_images(&invalid_annotations, &semver_version)
                .unwrap_err()
                .to_string(),
            format!(
                "policy metadata must specify \"{}\" in annotations",
                KUBEWARDEN_ANNOTATION_POLICY_OCIURL
            )
        );

        Ok(())
    }

    #[test]
    fn artifacthubpkg_with_minimum_required() -> Result<()> {
        let artif = ArtifactHubPkg::from_metadata(
            &mock_metadata_with_minimum_required(),
            "0.2.1",
            OffsetDateTime::UNIX_EPOCH,
            None,
        )
        .unwrap();
        let expected = json!({
            "version": "0.2.1",
            "name": "verify-image-signatures",
            "displayName": "Verify Image Signatures",
            "createdAt": "1970-01-01T00:00:00Z",
            "description": "A description",
            "annotations": {
                "kubewarden/mutation": "false",
                "kubewarden/contextAware": "false",
                "kubewarden/rules": "[]",
                "kubewarden/resources": "Pod, Deployment",
            },
            "containersImages": [
            {
                "name": "policy",
                "image": "https://github.com/ocirepo:v0.2.1"
            },
            ],
            "readme": "readme contents",
            "provider": {
               "name":  "kubewarden"
            },
            "recommendations": [
                {
                    "url": "https://artifacthub.io/packages/helm/kubewarden/kubewarden-controller"
                }
            ],
        });

        let actual = serde_json::to_value(&artif).unwrap();
        assert_json_eq!(expected, actual);
        Ok(())
    }

    #[test]
    fn artifacthubpkg_with_all() -> Result<()> {
        let artif = ArtifactHubPkg::from_metadata(
            &mock_metadata_with_all(),
            "0.2.1",
            OffsetDateTime::UNIX_EPOCH,
            Some("questions contents"),
        )
        .unwrap();
        let expected = json!({
            "version": "0.2.1",
            "name": "verify-image-signatures",
            "displayName": "Verify Image Signatures",
            "createdAt": "1970-01-01T00:00:00Z",
            "description": "A description",
            "license": "Apache-2.0",
            "homeURL": "https://github.com/home",
            "containersImages": [
            {
                "name": "policy",
                "image": "https://github.com/ocirepo:v0.2.1"
            },
            ],
            "keywords": [
                "pod",
                "signature"
            ],
            "links": [
            {
                "name": "policy",
                "url": "https://github.com/repo/releases/download/v0.2.1/policy.wasm"
            },
            {
                "name": "source",
                "url": "https://github.com/repo"
            }
            ],
            "readme": "readme contents",
            "maintainers": [
            {
                "name": "Tux Tuxedo",
                "email": "tux@example.com"
            },
            {
                "name": "Pidgin",
                "email": "pidgin@example.com"
            }
            ],
            "provider": {
                "name": "kubewarden"
            },
            "recommendations": [
                {
                    "url": "https://artifacthub.io/packages/helm/kubewarden/kubewarden-controller"
                }
            ],
            "annotations": {
                "kubewarden/resources": "Pod, Deployment",
                "kubewarden/mutation": "false",
                "kubewarden/contextAware": "false",
                "kubewarden/hidden-ui": "true",
                "kubewarden/rules": "[]",
                "kubewarden/questions-ui": "questions contents"
            }
        });

        let actual = serde_json::to_value(&artif).unwrap();
        assert_json_eq!(expected, actual);
        Ok(())
    }
}
