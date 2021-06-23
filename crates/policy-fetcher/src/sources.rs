use anyhow::{anyhow, Result};

use serde::Deserialize;

use std::collections::{HashMap, HashSet};
use std::convert::{TryFrom, TryInto};
use std::fs::File;
use std::path::Path;

#[derive(Clone, Default, Deserialize, Debug)]
struct RawSourceAuthorities(HashMap<String, Vec<RawCertificate>>);

#[derive(Clone, Default, Deserialize, Debug)]
#[serde(default)]
struct RawSources {
    insecure_sources: HashSet<String>,
    source_authorities: RawSourceAuthorities,
}

#[derive(Clone, Debug, Default, Deserialize, PartialEq)]
struct RawCertificate(pub Vec<u8>);

#[derive(Clone, Debug, Default)]
struct SourceAuthorities(HashMap<String, Vec<Certificate>>);

impl From<RawSourceAuthorities> for SourceAuthorities {
    fn from(source_authorities: RawSourceAuthorities) -> SourceAuthorities {
        SourceAuthorities(
            source_authorities
                .0
                .iter()
                .map(|(host, certificates)| {
                    (
                        host.clone(),
                        certificates
                            .iter()
                            .filter_map(|certificate| Certificate::try_from(certificate).ok())
                            .collect(),
                    )
                })
                .collect(),
        )
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

impl TryFrom<&RawCertificate> for Certificate {
    type Error = anyhow::Error;

    fn try_from(raw_certificate: &RawCertificate) -> Result<Certificate> {
        if reqwest::Certificate::from_pem(&raw_certificate.0).is_ok() {
            Ok(Certificate::Pem(raw_certificate.0.clone()))
        } else if reqwest::Certificate::from_der(&raw_certificate.0).is_ok() {
            Ok(Certificate::Der(raw_certificate.0.clone()))
        } else {
            Err(anyhow!(
                "certificate {:?} is not in PEM nor in DER encoding",
                raw_certificate
            ))
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
