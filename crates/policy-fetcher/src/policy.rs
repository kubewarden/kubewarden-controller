use sha2::{Digest, Sha256};
use std::fmt;
use std::fmt::Display;
use std::path::PathBuf;

#[derive(Debug, PartialEq, Eq)]
pub struct Policy {
    pub uri: String,
    pub local_path: PathBuf,
}

impl Policy {
    pub fn digest(&self) -> Result<String, std::io::Error> {
        let d = Sha256::digest(std::fs::read(&self.local_path)?);
        Ok(format!("{:x}", d))
    }
}

impl Display for Policy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.uri)
    }
}
