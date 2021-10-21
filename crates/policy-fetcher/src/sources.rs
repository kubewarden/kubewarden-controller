use anyhow::{anyhow, Result};

use serde::{Deserialize, Serialize};

use std::collections::{HashMap, HashSet};
use std::convert::{TryFrom, TryInto};
use std::path::{Path, PathBuf};
use std::{fs, fs::File};

#[derive(Clone, Default, Deserialize, Debug)]
struct RawSourceAuthorities(HashMap<String, Vec<RawSourceAuthority>>);

// This is how a RawSourceAuthority looks like:
// ```json
// {
//    "path": "/foo.pem"
// },
// {
//    "data": "PEM Data"
// }
// ```
#[derive(Clone, Deserialize, Debug)]
#[serde(untagged)]
enum RawSourceAuthority {
    DataBased { data: RawCertificate },
    PathBased { path: PathBuf },
}

impl TryFrom<RawSourceAuthority> for RawCertificate {
    type Error = anyhow::Error;

    fn try_from(raw_source_authority: RawSourceAuthority) -> Result<Self> {
        match raw_source_authority {
            RawSourceAuthority::DataBased { data } => Ok(data),
            RawSourceAuthority::PathBased { path } => {
                let file_data = fs::read(path.clone()).map_err(|e| {
                    anyhow!("Cannot read certificate from file '{:?}': {:?}", path, e)
                })?;
                Ok(RawCertificate(file_data))
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
struct RawCertificate(Vec<u8>);

#[derive(Clone, Debug, Default)]
struct SourceAuthorities(HashMap<String, Vec<Certificate>>);

impl TryFrom<RawSourceAuthorities> for SourceAuthorities {
    type Error = anyhow::Error;

    fn try_from(raw_source_authorities: RawSourceAuthorities) -> Result<SourceAuthorities> {
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

#[derive(Clone, Debug, PartialEq)]
pub enum Certificate {
    Der(Vec<u8>),
    Pem(Vec<u8>),
}

impl TryFrom<RawSources> for Sources {
    type Error = anyhow::Error;

    fn try_from(sources: RawSources) -> Result<Sources> {
        Ok(Sources {
            insecure_sources: sources.insecure_sources.clone(),
            source_authorities: sources.source_authorities.try_into()?,
        })
    }
}

impl TryFrom<RawCertificate> for Certificate {
    type Error = anyhow::Error;

    fn try_from(raw_certificate: RawCertificate) -> Result<Certificate> {
        if reqwest::Certificate::from_pem(&raw_certificate.0).is_ok() {
            Ok(Certificate::Pem(raw_certificate.0))
        } else if reqwest::Certificate::from_der(&raw_certificate.0).is_ok() {
            Ok(Certificate::Der(raw_certificate.0))
        } else {
            Err(anyhow!(
                "certificate {:?} is not in PEM nor in DER encoding",
                raw_certificate
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
            .map(|(_, certs)| {
                certs
                    .iter()
                    .map(|c| c.into())
                    .collect::<Vec<oci_distribution::client::Certificate>>()
            })
            .flatten()
            .collect();

        oci_distribution::client::ClientConfig {
            accept_invalid_hostnames: false,
            accept_invalid_certificates: false,
            protocol,
            extra_root_certificates,
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
            .map(|(_, certs)| {
                certs
                    .iter()
                    .map(|c| c.into())
                    .collect::<Vec<sigstore::registry::Certificate>>()
            })
            .flatten()
            .collect();

        sigstore::registry::ClientConfig {
            accept_invalid_hostnames: false,
            accept_invalid_certificates: false,
            protocol,
            extra_root_certificates,
        }
    }
}

impl Sources {
    pub(crate) fn is_insecure_source(&self, host: &str) -> bool {
        self.insecure_sources.contains(host)
    }

    pub(crate) fn source_authority(&self, host: &str) -> Option<Vec<Certificate>> {
        self.source_authorities.0.get(host).map(Clone::clone)
    }
}

pub fn read_sources_file(path: &Path) -> Result<Sources> {
    serde_yaml::from_reader::<_, RawSources>(File::open(path)?)?.try_into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::io::Write;
    use tempfile::NamedTempFile;

    #[test]
    fn test_deserialization_of_path_based_raw_source_authority() {
        let expected_path = "/foo.pem";
        let raw = json!({ "path": expected_path });

        let actual: Result<RawSourceAuthority, serde_json::Error> = serde_json::from_value(raw);
        match actual {
            Ok(RawSourceAuthority::PathBased { path }) => {
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
        let raw = json!({ "data": expected_data });

        let actual: Result<RawSourceAuthority, serde_json::Error> = serde_json::from_value(raw);
        match actual {
            Ok(RawSourceAuthority::DataBased { data }) => {
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
        let auth = RawSourceAuthority::PathBased { path };

        let expected: Result<RawCertificate> = auth.try_into();
        assert!(expected.is_err());
    }

    #[test]
    fn test_raw_path_based_source_authority_convertion_into_raw_certificate() -> Result<()> {
        let mut file = NamedTempFile::new()?;

        let expected_contents = "hello world";
        write!(file, "{}", expected_contents)?;

        let path = file.path();
        let auth = RawSourceAuthority::PathBased {
            path: path.to_path_buf(),
        };

        let expected: Result<RawCertificate> = auth.try_into();
        match expected {
            Ok(RawCertificate(data)) => {
                assert_eq!(&data, expected_contents.as_bytes());
            }
            unexpected => {
                panic!("Didn't get what I was expecting: {:?}", unexpected);
            }
        }

        Ok(())
    }

    #[test]
    fn test_raw_source_authorities_to_source_authority() {
        let cert_data = r#"-----BEGIN CERTIFICATE-----
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
        let expected_cert = Certificate::Pem(cert_data.into());

        let raw = json!({
            "foo.com": [
                { "data": RawCertificate(cert_data.into())},
                { "data": RawCertificate(cert_data.into())}
            ]}
        );
        let raw_source_authorities: RawSourceAuthorities = serde_json::from_value(raw).unwrap();

        let actual: Result<SourceAuthorities> = raw_source_authorities.try_into();
        assert!(actual.is_ok(), "Got an expected error: {:?}", actual);

        let actual_map = actual.unwrap().0;
        let actual_certs = actual_map.get("foo.com").unwrap();
        assert_eq!(actual_certs.len(), 2);
        for actual_cert in actual_certs {
            assert_eq!(actual_cert, &expected_cert);
        }
    }
}
