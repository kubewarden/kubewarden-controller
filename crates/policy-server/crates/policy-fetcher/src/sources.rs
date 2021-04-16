use anyhow::Result;

use native_tls::Certificate;

use serde::Deserialize;

use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::{fs, fs::File};

#[derive(Default, Deserialize, Debug)]
#[serde(default)]
pub struct Sources {
    insecure_sources: HashSet<String>,
    source_authorities: HashMap<String, CertificateAuthority>,
}

#[derive(Deserialize, Debug)]
pub(crate) struct CertificateAuthority {
    ca_path: PathBuf,
}

impl Sources {
    pub(crate) fn is_insecure_source<S: Into<String>>(&self, host: S) -> bool {
        self.insecure_sources.contains(&host.into())
    }

    pub(crate) fn source_authority<S: Into<String>>(&self, host: S) -> Option<Certificate> {
        self.source_authorities
            .get(&host.into())
            .and_then(|ca_path| fs::read_to_string(ca_path.ca_path.clone()).ok())
            .and_then(|pem_certificate| {
                // TODO (ereslibre): avoid parsing every time --
                // initialize parsed certs, or warm-up cache
                Certificate::from_pem(pem_certificate.as_bytes()).ok()
            })
    }
}

pub fn read_sources_file(path: &str) -> Result<Sources> {
    Ok(serde_yaml::from_reader::<_, Sources>(File::open(path)?)?)
}
