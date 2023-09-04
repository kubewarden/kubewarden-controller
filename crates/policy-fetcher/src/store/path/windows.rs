use anyhow::Result;
use base64::{alphabet, engine::general_purpose, Engine as _};
use std::path::{Path, PathBuf};

use crate::store::scheme;

/// A base64 engine that uses URL_SAFE alphabet and escapes using no padding
/// For performance reasons, it's recommended to cache its creation
pub const BASE64_ENGINE: general_purpose::GeneralPurpose =
    general_purpose::GeneralPurpose::new(&alphabet::URL_SAFE, general_purpose::NO_PAD);

/// Encode a path to a format that doesn't contain any invalid characters.
/// This is the implementation for Windows platforms, which encodes the path using base64.
/// This is necessary because Windows does not allow certain characters
/// in filenames, such as `:`.
pub fn encode_path<P: AsRef<Path>>(path: P) -> PathBuf {
    let mut encoded_path = PathBuf::new();

    for component in path.as_ref().components() {
        if let std::path::Component::RootDir = component {
            encoded_path.push(component.as_os_str());
            continue;
        }

        // Do not encode remote schemes
        let str_component = component.as_os_str().to_string_lossy();
        if scheme::is_known_remote_scheme(str_component.as_ref()) {
            encoded_path.push(str_component.to_string());
            continue;
        }

        let encoded_component = BASE64_ENGINE.encode(str_component.to_string());
        encoded_path.push(encoded_component);
    }

    encoded_path
}

/// Encode a filename.
pub fn encode_filename(filename: &str) -> String {
    BASE64_ENGINE.encode(filename)
}

/// Decode a path that was transformed with `encode_path`.
pub fn decode_path<P: AsRef<Path>>(path: P) -> Result<PathBuf> {
    let mut decoded_path = PathBuf::new();

    for component in path.as_ref().components() {
        if let std::path::Component::RootDir = component {
            decoded_path.push(component.as_os_str());
            continue;
        }

        // Do not decode remote schemes, as they are not encoded
        let str_component = component.as_os_str().to_string_lossy();
        if scheme::is_known_remote_scheme(str_component.as_ref()) {
            decoded_path.push(str_component.to_string());
            continue;
        }

        let decoded_component = BASE64_ENGINE.decode(str_component.to_string())?;
        decoded_path.push(String::from_utf8_lossy(&decoded_component).to_string());
    }

    Ok(decoded_path)
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::ffi::OsStr;
    #[test]
    fn test_encode_path() {
        let expected_path = PathBuf::from("/")
            .join("registry")
            .join(encode_filename("ghcr.io"))
            .join(encode_filename("some"))
            .join(encode_filename("path"))
            .join(encode_filename("to"))
            .join(encode_filename("wasm-module.wasm:1.0.0"));

        let path = "/registry/ghcr.io/some/path/to/wasm-module.wasm:1.0.0";

        assert_eq!(expected_path, encode_path(path),);
        assert_eq!(expected_path, encode_path(OsStr::new(path)));
        assert_eq!(expected_path, encode_path(Path::new(path)));
        assert_eq!(expected_path, encode_path(Path::new(path)));
    }

    #[test]
    fn test_decode_path() {
        assert_eq!(
            PathBuf::from("/registry/example.com:1234/some/path/to/wasm-module.wasm:1.0.0"),
            decode_path(
                PathBuf::from("/")
                    .join("registry")
                    .join(encode_filename("example.com:1234"))
                    .join(encode_filename("some"))
                    .join(encode_filename("path"))
                    .join(encode_filename("to"))
                    .join(encode_filename("wasm-module.wasm:1.0.0"))
            )
            .expect("failed to decode path"),
        );
    }
}
