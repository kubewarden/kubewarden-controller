use anyhow::anyhow;
use sigstore::cosign::signature_layers::CertificateSignature;
use sigstore::cosign::verification_constraint::{
    AnnotationVerifier, PublicKeyVerifier, VerificationConstraint,
};
use sigstore::cosign::{signature_layers::CertificateSubject, SignatureLayer};
use sigstore::crypto::SignatureDigestAlgorithm;
use sigstore::errors::{Result, SigstoreError};
use std::collections::HashMap;
use std::convert::TryFrom;

use super::config::Subject;

/// Verification Constraint for public keys and annotations
///
/// This constraint ensures that the SignatureLayer contains both a signature
/// matching the provided Public key, and  all the annotations specified.
#[derive(Debug)]
pub struct PublicKeyAndAnnotationsVerifier {
    pub_key_verifier: PublicKeyVerifier,
    annotation_verifier: Option<AnnotationVerifier>,
}

impl PublicKeyAndAnnotationsVerifier {
    pub fn new(
        key: &str,
        signature_digest_algorithm: SignatureDigestAlgorithm,
        annotations: Option<&HashMap<String, String>>,
    ) -> Result<Self> {
        let pub_key_verifier = PublicKeyVerifier::new(key.as_bytes(), signature_digest_algorithm)?;
        let annotation_verifier = annotations.map(|a| AnnotationVerifier {
            annotations: a.to_owned(),
        });

        Ok(Self {
            pub_key_verifier,
            annotation_verifier,
        })
    }
}

impl VerificationConstraint for PublicKeyAndAnnotationsVerifier {
    fn verify(&self, sl: &SignatureLayer) -> Result<bool> {
        let outcome = if let Some(av) = &self.annotation_verifier {
            self.pub_key_verifier.verify(sl)? && av.verify(sl)?
        } else {
            self.pub_key_verifier.verify(sl)?
        };
        Ok(outcome)
    }
}

/// Verification Constraint for Generic Issuer
///
/// This constraint looks at the signature done in keyless mode and
/// inspects its Subject.
#[derive(Debug)]
pub struct GenericIssuerSubjectVerifier {
    issuer: String,
    subject: Subject,
    annotation_verifier: Option<AnnotationVerifier>,
}

impl GenericIssuerSubjectVerifier {
    pub fn new(
        issuer: &str,
        subject: &Subject,
        annotations: Option<&HashMap<String, String>>,
    ) -> Self {
        let annotation_verifier = annotations.map(|a| AnnotationVerifier {
            annotations: a.to_owned(),
        });

        let s = match &subject {
            Subject::Equal(_) => subject.clone(),
            Subject::UrlPrefix(url) => {
                let prefix = url.to_string();
                if prefix.ends_with('/') {
                    subject.clone()
                } else {
                    let u = url::Url::parse(format!("{}/", prefix).as_str())
                        .expect("This should never fail");
                    Subject::UrlPrefix(u)
                }
            }
        };

        Self {
            issuer: issuer.to_string(),
            subject: s,
            annotation_verifier,
        }
    }

    fn verify_subject_equal(
        &self,
        expected: &str,
        certificate_signature: &CertificateSignature,
    ) -> bool {
        let certificate_subject = match &certificate_signature.subject {
            CertificateSubject::Email(e) => e,
            CertificateSubject::Uri(u) => u,
        };

        Some(&self.issuer) == certificate_signature.issuer.as_ref()
            && expected == certificate_subject
    }

    fn verify_subject_url_prefix(
        &self,
        prefix: &url::Url,
        certificate_signature: &CertificateSignature,
    ) -> bool {
        let certificate_subject = match &certificate_signature.subject {
            CertificateSubject::Email(e) => e,
            CertificateSubject::Uri(u) => u,
        };

        Some(&self.issuer) == certificate_signature.issuer.as_ref()
            && certificate_subject.starts_with(&prefix.to_string())
    }
}

impl VerificationConstraint for GenericIssuerSubjectVerifier {
    fn verify(&self, sl: &SignatureLayer) -> Result<bool> {
        if sl.certificate_signature.is_none() {
            return Ok(false);
        }
        let certificate_signature = sl.certificate_signature.as_ref().unwrap();

        let basic_check = match &self.subject {
            Subject::Equal(value) => self.verify_subject_equal(value, certificate_signature),
            Subject::UrlPrefix(prefix) => {
                self.verify_subject_url_prefix(prefix, certificate_signature)
            }
        };
        let outcome = if let Some(av) = &self.annotation_verifier {
            basic_check && av.verify(sl)?
        } else {
            basic_check
        };
        Ok(outcome)
    }
}

/// Verification Constraint for Signatures produced by GitHub Actions
///
/// This constraint looks at the signature done in keyless mode by a
/// Github Action and inspects its Subject.
#[derive(Debug)]
pub struct GitHubVerifier {
    owner: String,
    repo: Option<String>,
    annotation_verifier: Option<AnnotationVerifier>,
}

const GITHUB_ACTION_ISSUER: &str = "https://token.actions.githubusercontent.com";

impl GitHubVerifier {
    pub fn new(
        owner: &str,
        repo: Option<&str>,
        annotations: Option<&HashMap<String, String>>,
    ) -> Self {
        let annotation_verifier = annotations.map(|a| AnnotationVerifier {
            annotations: a.to_owned(),
        });

        Self {
            owner: owner.to_string(),
            repo: repo.map(|r| r.to_owned()),
            annotation_verifier,
        }
    }
}

impl VerificationConstraint for GitHubVerifier {
    fn verify(&self, sl: &SignatureLayer) -> Result<bool> {
        if sl.certificate_signature.is_none() {
            return Ok(false);
        }
        let certificate_signature = sl.certificate_signature.as_ref().unwrap();

        // the certificate issuer must be provided and must match the one of GH Actions
        match &certificate_signature.issuer {
            None => return Ok(false),
            Some(issuer) => {
                if issuer != GITHUB_ACTION_ISSUER {
                    return Ok(false);
                }
            }
        };

        let signature_url = match &certificate_signature.subject {
            CertificateSubject::Email(_) => return Ok(false),
            CertificateSubject::Uri(u) => u,
        };

        let signature_repo = GitHubRepo::try_from(signature_url.as_str()).map_err(|_|
            SigstoreError::VerificationConstraintError(format!("The certificate signature url doesn't seem a GitHub valid one, despite the issuer being the GitHub Action one: {}", signature_url)))?;

        if signature_repo.owner != self.owner {
            return Ok(false);
        }

        if let Some(repo) = &self.repo {
            if &signature_repo.repo != repo {
                return Ok(false);
            }
        }

        let outcome = if let Some(av) = &self.annotation_verifier {
            av.verify(sl)?
        } else {
            true
        };
        Ok(outcome)
    }
}

struct GitHubRepo {
    pub owner: String,
    pub repo: String,
}

impl TryFrom<&str> for GitHubRepo {
    type Error = anyhow::Error;

    fn try_from(u: &str) -> std::result::Result<Self, Self::Error> {
        let u = url::Url::parse(u).map_err(|e| anyhow!("Cannot parse github url: {}", e))?;
        if u.host_str() != Some("github.com") {
            return Err(anyhow!("Not a GitHub url: host doesn't match"));
        }
        let mut segments = u
            .path_segments()
            .ok_or_else(|| anyhow!("Cannot parse GitHub url: no path segments"))?;
        let owner = segments
            .next()
            .ok_or_else(|| anyhow!("cannot parse github url: owner not found"))?;
        let repo = segments
            .next()
            .ok_or_else(|| anyhow!("cannot parse github url: repo not found"))?;

        Ok(GitHubRepo {
            owner: owner.to_string(),
            repo: repo.to_string(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;
    use sigstore::{cosign::signature_layers::CertificateSignature, simple_signing::SimpleSigning};

    fn build_signature_layers_pub_key<'a>() -> (&'a str, SignatureLayer) {
        let pub_key: &'a str = r#"-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAELKhD7F5OKy77Z582Y6h0u1J3GNA+
kvUsh4eKpd1lwkDAzfFDs7yXEExsEkPPuiQJBelDT68n7PDIWB/QEY7mrA==
-----END PUBLIC KEY-----"#;
        let raw_data = r#"{"critical":{"identity":{"docker-reference":"registry-testing.svc.lan/busybox"},"image":{"docker-manifest-digest":"sha256:f3cfc9d0dbf931d3db4685ec659b7ac68e2a578219da4aae65427886e649b06b"},"type":"cosign container image signature"},"optional":null}"#;
        let raw_data = raw_data.as_bytes().to_vec();
        let signature = "MEYCIQDWWxPQa3XFUsPbyTY+n+bZu/6Pwhg5WwyYDQtEfQho9wIhAPkKW7eub8b7BX+YbbRac8TwwIrK5KxvdtQ6NuoD+ivW".to_string();

        let simple_signing: SimpleSigning =
            serde_json::from_slice(&raw_data).expect("Cannot deserialize SimpleSigning");

        (
            pub_key,
            SignatureLayer {
                simple_signing,
                oci_digest: "not relevant".to_string(),
                certificate_signature: None,
                bundle: None,
                signature,
                raw_data,
            },
        )
    }

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

    #[test]
    fn test_public_key_and_annotation_verifier() {
        let (pub_key, sl) = build_signature_layers_pub_key();

        let vc = PublicKeyAndAnnotationsVerifier::new(
            pub_key,
            SignatureDigestAlgorithm::default(),
            None,
        )
        .expect("Cannot create verification constraint");
        let is_verified = vc.verify(&sl).expect("Should have been successful");
        assert!(is_verified);

        let mut annotations: HashMap<String, String> = HashMap::new();
        annotations.insert("key1".into(), "value2".into());

        let vc = PublicKeyAndAnnotationsVerifier::new(
            pub_key,
            SignatureDigestAlgorithm::default(),
            Some(&annotations),
        )
        .expect("Cannot create verification constraint");
        let is_verified = vc.verify(&sl).expect("Should have been successful");
        assert!(!is_verified);
    }

    #[test]
    fn test_generic_issuer_subject_equal_reject_because_no_signature() {
        let (_, sl) = build_signature_layers_pub_key();

        let issuer = "https://github.com/login/oauth";
        let subject_str = "user@provider.com";
        let subject = Subject::Equal(subject_str.to_string());

        let vc = GenericIssuerSubjectVerifier::new(issuer, &subject, None);
        let is_verified = vc.verify(&sl).expect("Should have been successful");
        assert!(!is_verified);
    }

    #[test]
    fn test_generic_issuer_subject_equal_valid() {
        // works with interactive signatures -> email subject
        let issuer = "https://github.com/login/oauth";
        let subject_str = "user@provider.com";
        let subject = Subject::Equal(subject_str.to_string());

        let certificate_subject = CertificateSubject::Email(subject_str.to_string());

        let sl = build_signature_layers_keyless(Some(issuer.to_string()), certificate_subject);

        let vc = GenericIssuerSubjectVerifier::new(issuer, &subject, None);
        let is_verified = vc.verify(&sl).expect("Should have been successful");
        assert!(is_verified);

        // works with non-interactive signatures -> url subject
        let issuer = "https://token.actions.githubusercontent.com";
        let subject_str = "https://github.com/kubewarden/policy-secure-pod-images/.github/workflows/release.yml@refs/heads/main";
        let subject = Subject::Equal(subject_str.to_string());

        let certificate_subject = CertificateSubject::Uri(subject_str.to_string());

        let sl = build_signature_layers_keyless(Some(issuer.to_string()), certificate_subject);

        let vc = GenericIssuerSubjectVerifier::new(issuer, &subject, None);
        let is_verified = vc.verify(&sl).expect("Should have been successful");
        assert!(is_verified);

        // works with interactive signatures -> email subject
        let issuer = "https://github.com/login/oauth";
        let subject_str = "user@provider.com";
        let subject = Subject::Equal(subject_str.to_string());

        let certificate_subject = CertificateSubject::Email(subject_str.to_string());

        let sl = build_signature_layers_keyless(Some(issuer.to_string()), certificate_subject);

        let vc = GenericIssuerSubjectVerifier::new(issuer, &subject, None);
        let is_verified = vc.verify(&sl).expect("Should have been successful");
        assert!(is_verified);
    }

    #[test]
    fn test_generic_issuer_subject_equal_fail_because_of_annotations() {
        let issuer = "https://github.com/login/oauth";
        let subject_str = "user@provider.com";
        let subject = Subject::Equal(subject_str.to_string());

        let certificate_subject = CertificateSubject::Email(subject_str.to_string());

        let sl = build_signature_layers_keyless(Some(issuer.to_string()), certificate_subject);

        let mut annotations: HashMap<String, String> = HashMap::new();
        annotations.insert("key1".into(), "value1".into());

        let vc = GenericIssuerSubjectVerifier::new(issuer, &subject, Some(&annotations));
        let is_verified = vc.verify(&sl).expect("Should have been successful");
        assert!(!is_verified);
    }

    #[test]
    fn test_generic_issuer_subject_equal_fail_because_of_issuer() {
        let issuer = "https://github.com/login/oauth";
        let subject_str = "user@provider.com";
        let subject = Subject::Equal(subject_str.to_string());

        let certificate_subject = CertificateSubject::Email(subject_str.to_string());

        let vc = GenericIssuerSubjectVerifier::new(issuer, &subject, None);

        // a signature without issuer - could happen with early signatures of cosign
        let sl = build_signature_layers_keyless(None, certificate_subject.clone());
        let is_verified = vc.verify(&sl).expect("Should have been successful");
        assert!(!is_verified);

        // a signature with a different issuer
        let sl =
            build_signature_layers_keyless(Some("another issuer".to_string()), certificate_subject);
        let is_verified = vc.verify(&sl).expect("Should have been successful");
        assert!(!is_verified);
    }

    #[test]
    fn test_generic_issuer_subject_equal_fail_because_of_subject() {
        let issuer = "https://github.com/login/oauth";
        let subject_str = "user@provider.com";
        let subject = Subject::Equal(subject_str.to_string());

        let vc = GenericIssuerSubjectVerifier::new(issuer, &subject, None);

        let another_subject = CertificateSubject::Email("alice@provider.com".to_string());
        let sl = build_signature_layers_keyless(Some(issuer.to_string()), another_subject);
        let is_verified = vc.verify(&sl).expect("Should have been successful");
        assert!(!is_verified);
    }

    #[test]
    fn test_generic_issuer_subject_url_prefix_valid() {
        let issuer = "https://token.actions.githubusercontent.com";
        let subject_str = "https://github.com/kubewarden/policy-secure-pod-images/.github/workflows/release.yml@refs/heads/main";
        let prefix = url::Url::parse("https://github.com/kubewarden/policy-secure-pod-images/")
            .expect("Cannot build url prefix");
        let subject = Subject::UrlPrefix(prefix);

        let certificate_subject = CertificateSubject::Uri(subject_str.to_string());

        let sl = build_signature_layers_keyless(Some(issuer.to_string()), certificate_subject);

        let vc = GenericIssuerSubjectVerifier::new(issuer, &subject, None);
        let is_verified = vc.verify(&sl).expect("Should have been successful");
        assert!(is_verified);
    }

    #[test]
    fn test_generic_issuer_subject_url_prefix_prevent_abuses() {
        // signature done inside of `kubewarde-hacker` organization, but we trust only `kubewarden`
        // org

        let issuer = "https://token.actions.githubusercontent.com";
        let subject_str = "https://github.com/kubewarden-hacker/policy-secure-pod-images/.github/workflows/release.yml@refs/heads/main";
        let certificate_subject = CertificateSubject::Uri(subject_str.to_string());
        let sl = build_signature_layers_keyless(Some(issuer.to_string()), certificate_subject);

        // It has a trailing `/`
        let prefix =
            url::Url::parse("https://github.com/kubewarden/").expect("Cannot build url prefix");
        let subject = Subject::UrlPrefix(prefix);
        let vc = GenericIssuerSubjectVerifier::new(issuer, &subject, None);
        let is_verified = vc.verify(&sl).expect("Should have been successful");
        assert!(!is_verified);

        // It doesn't have a trailing `/` -> this is automatically added
        let prefix =
            url::Url::parse("https://github.com/kubewarden").expect("Cannot build url prefix");
        let subject = Subject::UrlPrefix(prefix);
        let vc = GenericIssuerSubjectVerifier::new(issuer, &subject, None);
        let is_verified = vc.verify(&sl).expect("Should have been successful");
        assert!(!is_verified);
    }

    #[rstest(
        url,
        owner,
        repo,
        case(
            "https://github.com/flavio/policy-secure-pod-images/.github/workflows/release.yml@refs/heads/main",
            Some("flavio"),
            Some("policy-secure-pod-images"),
        ),
        case(
            "https://example.com",
            None,
            None,
        ),
        case(
            "https://github.com",
            None,
            None,
        ),
        case(
            "https://github.com/kubewarden",
            None,
            None,
        ),
        case(
            "https://github.com/kubewarden/policy",
            Some("kubewarden"),
            Some("policy"),
        )
    )]
    fn github_repo_parser(url: &str, owner: Option<&str>, repo: Option<&str>) {
        let gh = GitHubRepo::try_from(url);

        if owner.is_none() != repo.is_none() {
            panic!("wrong input for the test case");
        }

        match gh {
            Err(_) => {
                if owner.is_some() {
                    panic!("Didn't expect an error");
                }
            }
            Ok(gh) => {
                if owner.is_none() {
                    panic!("An error was expected");
                } else {
                    assert_eq!(gh.owner, owner.unwrap(), "Didn't get the expected owner");
                    assert_eq!(gh.repo, repo.unwrap(), "Didn't get the expected repo");
                }
            }
        }
    }

    #[test]
    fn test_github_verifier_reject_because_no_signature() {
        let (_, sl) = build_signature_layers_pub_key();

        let vc = GitHubVerifier::new("kubewarden", Some("policy"), None);
        let is_verified = vc.verify(&sl).expect("Should have been successful");
        assert!(!is_verified);
    }

    #[test]
    fn test_github_verifier_success() {
        let issuer = "https://token.actions.githubusercontent.com";
        let subject_str = "https://github.com/kubewarden/policy-secure-pod-images/.github/workflows/release.yml@refs/heads/main";

        let certificate_subject = CertificateSubject::Uri(subject_str.to_string());

        let sl = build_signature_layers_keyless(Some(issuer.to_string()), certificate_subject);

        // check specifically this owner/repo
        let vc = GitHubVerifier::new("kubewarden", Some("policy-secure-pod-images"), None);
        let is_verified = vc.verify(&sl).expect("Should have been successful");
        assert!(is_verified);

        // anything from this owner is fine
        let vc = GitHubVerifier::new("kubewarden", None, None);
        let is_verified = vc.verify(&sl).expect("Should have been successful");
        assert!(is_verified);
    }

    #[test]
    fn test_github_verifier_reject() {
        let issuer = "https://token.actions.githubusercontent.com";
        let subject_str = "https://github.com/kubewarden/policy-secure-pod-images/.github/workflows/release.yml@refs/heads/main";

        let certificate_subject = CertificateSubject::Uri(subject_str.to_string());

        let sl = build_signature_layers_keyless(Some(issuer.to_string()), certificate_subject);

        // check specifically this owner/repo
        let vc = GitHubVerifier::new("kubewarden", Some("psp-one"), None);
        let is_verified = vc.verify(&sl).expect("Should have been successful");
        assert!(!is_verified);

        // anything from this owner is fine
        let vc = GitHubVerifier::new("kubewarden-tests", None, None);
        let is_verified = vc.verify(&sl).expect("Should have been successful");
        assert!(!is_verified);
    }

    #[test]
    fn test_github_verifier_reject_because_issuer_url_is_wrong() {
        let issuer = "https://google.com";
        let subject_str = "https://github.com/kubewarden/policy-secure-pod-images/.github/workflows/release.yml@refs/heads/main";

        let certificate_subject = CertificateSubject::Uri(subject_str.to_string());

        let sl = build_signature_layers_keyless(Some(issuer.to_string()), certificate_subject);

        let vc = GitHubVerifier::new("kubewarden", None, None);
        let is_verified = vc.verify(&sl).expect("Should have been successful");
        assert!(!is_verified);
    }

    #[test]
    fn test_github_verifier_reject_because_certificate_subject_does_not_have_url() {
        let issuer = "https://token.actions.githubusercontent.com";
        let subject_str = "https://github.com/kubewarden/policy-secure-pod-images/.github/workflows/release.yml@refs/heads/main";

        let certificate_subject = CertificateSubject::Email(subject_str.to_string());

        let sl = build_signature_layers_keyless(Some(issuer.to_string()), certificate_subject);

        let vc = GitHubVerifier::new("kubewarden", None, None);
        let is_verified = vc.verify(&sl).expect("Should have been successful");
        assert!(!is_verified);
    }
}
