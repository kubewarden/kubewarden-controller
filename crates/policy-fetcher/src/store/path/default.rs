use std::path::{Path, PathBuf};

use crate::store::errors::StoreResult;

/// Encode a path to a format that doesn't contain any invalid characters
/// for the target platform.
/// This is the default implementation for non-Windows platforms,
/// which just returns the path as-is.
pub fn encode_path<P: AsRef<Path>>(path: P) -> PathBuf {
    path.as_ref().to_path_buf()
}

/// Encode a filename.
pub fn encode_filename(filename: &str) -> String {
    filename.to_string()
}

/// Retrieve a path that was transformed with `transform_path`.
pub fn decode_path<P: AsRef<Path>>(path: P) -> StoreResult<PathBuf> {
    Ok(path.as_ref().to_path_buf())
}
