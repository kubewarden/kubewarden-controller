use std::fmt;
use std::fmt::Display;
use std::path::PathBuf;

#[derive(Debug)]
pub struct Policy {
    pub uri: String,
    pub local_path: PathBuf,
}

impl Display for Policy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.uri)
    }
}
