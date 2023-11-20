use sha2::{Digest, Sha256};
use std::fmt;
use std::fmt::Display;
use std::path::PathBuf;

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct Policy {
    pub uri: String,
    pub local_path: PathBuf,
}

#[derive(thiserror::Error, Debug)]
#[error("cannot retrieve path from uri: {err}")]
pub struct DigestError {
    #[from]
    err: std::io::Error,
}

type PolicyResult<T> = std::result::Result<T, DigestError>;

impl Policy {
    pub fn digest(&self) -> PolicyResult<String> {
        let d = Sha256::digest(std::fs::read(&self.local_path)?);
        Ok(format!("{:x}", d))
    }
}

impl Display for Policy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.uri)
    }
}
