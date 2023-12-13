use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::errors::FailedToParseYamlDataError;
use std::collections::{HashMap, HashSet};
use std::convert::{TryFrom, TryInto};
use std::path::{Path, PathBuf};
use std::{fs, fs::File};

pub type SourceResult<T> = std::result::Result<T, SourceError>;

#[derive(Error, Debug)]
pub enum SourceError {
    #[error(transparent)]
    InvalidURLError(#[from] crate::errors::InvalidURLError),
    #[error("Fail to interact with OCI registry: {0}")]
    OCIRegistryError(#[from] oci_distribution::errors::OciDistributionError),
    #[error("Invalid OCI image reference: {0}")]
    InvalidOCIImageReferenceError(#[from] oci_distribution::ParseError),
    #[error("could not pull policy {0}: empty layers")]
    EmptyLayersError(String),
    #[error("Invalid certificate: {0}")]
    InvalidCertificateError(String),
    #[error("Cannot read certificate from file: {0}")]
    CannotReadCertificateError(#[from] std::io::Error),
    #[error(transparent)]
    FailedToParseYamlDataError(#[from] FailedToParseYamlDataError),
    #[error("failed to create the http client: {0}")]
    FailedToCreateHttpClientError(#[from] reqwest::Error),
}

#[derive(Clone, Default, Deserialize, Debug)]
struct RawSourceAuthorities(HashMap<String, Vec<RawSourceAuthority>>);

// This is how a RawSourceAuthority looks like:
// ```json
// {
//    "type": "Path"
//    "path": "/foo.pem"
// },
// {
//    "type": "Data"
//    "data": "PEM Data"
// }
// ```
#[derive(Clone, Deserialize, Debug)]
#[serde(tag = "type")]
enum RawSourceAuthority {
    Data { data: RawCertificate },
    Path { path: PathBuf },
}

impl TryFrom<RawSourceAuthority> for RawCertificate {
    type Error = SourceError;

    fn try_from(raw_source_authority: RawSourceAuthority) -> SourceResult<Self> {
        match raw_source_authority {
            RawSourceAuthority::Data { data } => Ok(data),
            RawSourceAuthority::Path { path } => {
                let file_data =
                    fs::read(path.clone()).map_err(SourceError::CannotReadCertificateError)?;
                Ok(RawCertificate(String::from_utf8(file_data).unwrap()))
            }
        }
    }
}

#[derive(Clone, Default, Deserialize, Debug)]
#[serde(default)]
struct RawSources {
    insecure_sources: HashSet<String>,
    source_authorities: RawSourceAuthorities,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq)]
struct RawCertificate(String);

#[derive(Clone, Debug, Default)]
struct SourceAuthorities(HashMap<String, Vec<Certificate>>);

impl TryFrom<RawSourceAuthorities> for SourceAuthorities {
    type Error = SourceError;

    fn try_from(raw_source_authorities: RawSourceAuthorities) -> SourceResult<SourceAuthorities> {
        let mut sa = SourceAuthorities::default();

        for (host, authorities) in raw_source_authorities.0 {
            let mut certs: Vec<Certificate> = Vec::new();
            for authority in authorities {
                let raw_cert: RawCertificate = authority.try_into()?;
                let cert: Certificate = raw_cert.try_into()?;
                certs.push(cert);
            }
            sa.0.insert(host.clone(), certs);
        }

        Ok(sa)
    }
}

#[derive(Clone, Debug, Default)]
pub struct Sources {
    insecure_sources: HashSet<String>,
    source_authorities: SourceAuthorities,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Certificate {
    Der(Vec<u8>),
    Pem(Vec<u8>),
}

impl TryFrom<RawSources> for Sources {
    type Error = SourceError;

    fn try_from(sources: RawSources) -> SourceResult<Sources> {
        Ok(Sources {
            insecure_sources: sources.insecure_sources.clone(),
            source_authorities: sources.source_authorities.try_into()?,
        })
    }
}

impl TryFrom<RawCertificate> for Certificate {
    type Error = SourceError;

    fn try_from(raw_certificate: RawCertificate) -> SourceResult<Certificate> {
        if reqwest::Certificate::from_pem(raw_certificate.0.as_bytes()).is_ok() {
            Ok(Certificate::Pem(raw_certificate.0.as_bytes().to_vec()))
        } else if reqwest::Certificate::from_der(raw_certificate.0.as_bytes()).is_ok() {
            Ok(Certificate::Der(raw_certificate.0.as_bytes().to_vec()))
        } else {
            Err(SourceError::InvalidCertificateError(
                "raw certificate is not in PEM nor in DER encoding".to_owned(),
            ))
        }
    }
}

impl From<&Certificate> for sigstore::registry::Certificate {
    fn from(cert: &Certificate) -> Self {
        match cert {
            Certificate::Der(data) => sigstore::registry::Certificate {
                encoding: sigstore::registry::CertificateEncoding::Der,
                data: data.clone(),
            },
            Certificate::Pem(data) => sigstore::registry::Certificate {
                encoding: sigstore::registry::CertificateEncoding::Pem,
                data: data.clone(),
            },
        }
    }
}

impl From<Sources> for oci_distribution::client::ClientConfig {
    fn from(sources: Sources) -> Self {
        let protocol = if sources.insecure_sources.is_empty() {
            oci_distribution::client::ClientProtocol::Https
        } else {
            let insecure: Vec<String> = sources.insecure_sources.iter().cloned().collect();
            oci_distribution::client::ClientProtocol::HttpsExcept(insecure)
        };

        let extra_root_certificates: Vec<oci_distribution::client::Certificate> = sources
            .source_authorities
            .0
            .iter()
            .flat_map(|(_, certs)| {
                certs
                    .iter()
                    .map(|c| c.into())
                    .collect::<Vec<oci_distribution::client::Certificate>>()
            })
            .collect();

        oci_distribution::client::ClientConfig {
            protocol,
            accept_invalid_certificates: false,
            extra_root_certificates,
            platform_resolver: None,
            ..Default::default()
        }
    }
}

impl From<Sources> for sigstore::registry::ClientConfig {
    fn from(sources: Sources) -> Self {
        let protocol = if sources.insecure_sources.is_empty() {
            sigstore::registry::ClientProtocol::Https
        } else {
            let insecure: Vec<String> = sources.insecure_sources.iter().cloned().collect();
            sigstore::registry::ClientProtocol::HttpsExcept(insecure)
        };

        let extra_root_certificates: Vec<sigstore::registry::Certificate> = sources
            .source_authorities
            .0
            .iter()
            .flat_map(|(_, certs)| {
                certs
                    .iter()
                    .map(|c| c.into())
                    .collect::<Vec<sigstore::registry::Certificate>>()
            })
            .collect();

        sigstore::registry::ClientConfig {
            accept_invalid_certificates: false,
            protocol,
            extra_root_certificates,
        }
    }
}

impl Sources {
    pub fn is_insecure_source(&self, host: &str) -> bool {
        self.insecure_sources.contains(host)
    }

    pub fn source_authority(&self, host: &str) -> Option<Vec<Certificate>> {
        self.source_authorities.0.get(host).map(Clone::clone)
    }
}

pub fn read_sources_file(path: &Path) -> SourceResult<Sources> {
    serde_yaml::from_reader::<_, RawSources>(File::open(path)?)
        .map_err(FailedToParseYamlDataError)?
        .try_into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::io::Write;
    use tempfile::NamedTempFile;

    const CERT_DATA: &str = r#"-----BEGIN CERTIFICATE-----
MIICUTCCAfugAwIBAgIBADANBgkqhkiG9w0BAQQFADBXMQswCQYDVQQGEwJDTjEL
MAkGA1UECBMCUE4xCzAJBgNVBAcTAkNOMQswCQYDVQQKEwJPTjELMAkGA1UECxMC
VU4xFDASBgNVBAMTC0hlcm9uZyBZYW5nMB4XDTA1MDcxNTIxMTk0N1oXDTA1MDgx
NDIxMTk0N1owVzELMAkGA1UEBhMCQ04xCzAJBgNVBAgTAlBOMQswCQYDVQQHEwJD
TjELMAkGA1UEChMCT04xCzAJBgNVBAsTAlVOMRQwEgYDVQQDEwtIZXJvbmcgWWFu
ZzBcMA0GCSqGSIb3DQEBAQUAA0sAMEgCQQCp5hnG7ogBhtlynpOS21cBewKE/B7j
V14qeyslnr26xZUsSVko36ZnhiaO/zbMOoRcKK9vEcgMtcLFuQTWDl3RAgMBAAGj
gbEwga4wHQYDVR0OBBYEFFXI70krXeQDxZgbaCQoR4jUDncEMH8GA1UdIwR4MHaA
FFXI70krXeQDxZgbaCQoR4jUDncEoVukWTBXMQswCQYDVQQGEwJDTjELMAkGA1UE
CBMCUE4xCzAJBgNVBAcTAkNOMQswCQYDVQQKEwJPTjELMAkGA1UECxMCVU4xFDAS
BgNVBAMTC0hlcm9uZyBZYW5nggEAMAwGA1UdEwQFMAMBAf8wDQYJKoZIhvcNAQEE
BQADQQA/ugzBrjjK9jcWnDVfGHlk3icNRq0oV7Ri32z/+HQX67aRfgZu7KWdI+Ju
Wm7DCfrPNGVwFWUQOmsPue9rZBgO
-----END CERTIFICATE-----
"#;

    #[test]
    fn test_deserialization_of_path_based_raw_source_authority() {
        let expected_path = "/foo.pem";
        let raw = json!({"type": "Path", "path": expected_path });

        let actual: Result<RawSourceAuthority, serde_json::Error> = serde_json::from_value(raw);
        match actual {
            Ok(RawSourceAuthority::Path { path }) => {
                let expected: PathBuf = expected_path.into();
                assert_eq!(path, expected);
            }
            unexpected => {
                panic!("Didn't get the expected value: {:?}", unexpected);
            }
        }
    }

    #[test]
    fn test_deserialization_of_data_based_raw_source_authority() {
        let expected_data = RawCertificate("hello world".into());
        let raw = json!({ "type": "Data", "data": expected_data });

        let actual: Result<RawSourceAuthority, serde_json::Error> = serde_json::from_value(raw);
        match actual {
            Ok(RawSourceAuthority::Data { data }) => {
                assert_eq!(data, expected_data);
            }
            unexpected => {
                panic!("Didn't get the expected value: {:?}", unexpected);
            }
        }
    }

    #[test]
    fn test_deserialization_of_unknown_raw_source_authority() {
        let broken_cases = vec![json!({ "something": "unknown" }), json!({ "path": 1 })];
        for bc in broken_cases {
            let actual: Result<RawSourceAuthority, serde_json::Error> =
                serde_json::from_value(bc.clone());
            assert!(
                actual.is_err(),
                "Expected {:?} to fail, got instead {:?}",
                bc,
                actual
            );
        }
    }

    #[test]
    fn test_raw_source_authority_cannot_be_converted_into_raw_certificate_when_file_is_missing() {
        let mut path = PathBuf::new();
        path.push("/boom");
        let auth = RawSourceAuthority::Path { path };

        let expected: SourceResult<RawCertificate> = auth.try_into();
        assert!(matches!(
            expected,
            Err(SourceError::CannotReadCertificateError(_))
        ));
    }

    #[test]
    fn test_raw_path_based_source_authority_convertion_into_raw_certificate() {
        let mut file = NamedTempFile::new().unwrap();

        let expected_contents = "hello world";
        write!(file, "{}", expected_contents).unwrap();

        let path = file.path();
        let auth = RawSourceAuthority::Path {
            path: path.to_path_buf(),
        };

        let expected: SourceResult<RawCertificate> = auth.try_into();
        assert!(matches!(expected, Ok(RawCertificate(data)) if data == expected_contents));
    }

    #[test]
    fn test_raw_source_authorities_to_source_authority() {
        let expected_cert = Certificate::Pem(CERT_DATA.into());

        let raw = json!({
            "foo.com": [
                {"type": "Data", "data": RawCertificate(CERT_DATA.into())},
                {"type": "Data", "data": RawCertificate(CERT_DATA.into())}
            ]}
        );
        let raw_source_authorities: RawSourceAuthorities = serde_json::from_value(raw).unwrap();

        let actual: SourceResult<SourceAuthorities> = raw_source_authorities.try_into();

        assert!(actual.is_ok(), "Got an unexpected error: {:?}", actual);

        let actual_map = actual.unwrap().0;
        let actual_certs = actual_map.get("foo.com").unwrap();
        assert_eq!(actual_certs.len(), 2);
        for actual_cert in actual_certs {
            assert_eq!(actual_cert, &expected_cert);
        }
    }
}
