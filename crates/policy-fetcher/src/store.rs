use anyhow::{anyhow, Result};
#[cfg(target_os = "windows")]
use base64;
use directories::ProjectDirs;
use lazy_static::lazy_static;
use path_slash::PathBufExt;
use std::ffi::{OsStr, OsString};
use std::path::{Path, PathBuf};
use url::Url;
use walkdir::WalkDir;

use crate::policy::Policy;

static KNOWN_REMOTE_SCHEMES: &[&str] = &["http", "https", "registry"];

lazy_static! {
    pub static ref DEFAULT_ROOT: ProjectDirs =
        ProjectDirs::from("io.kubewarden", "", "kubewarden").unwrap();
    pub static ref DEFAULT_STORE_ROOT: PathBuf = DEFAULT_ROOT.cache_dir().join("store");
}

pub enum PolicyPath {
    PrefixOnly,
    PrefixAndFilename,
}

// Store represents a structure that is able to save and retrieve
// WebAssembly modules from a central and local location.
//
// In the local filesystem, the structure of the directory is the
// following:
//
// <root>/<scheme>/<host>/<image>:<tag>.wasm
//
// for each image. No index or embedded database is implemented
// yet. Assuming we have pulled the following images:
//
// - registry://ghcr.io/some-org/some/path/to/wasm-module.wasm:1.0.0
// - https://internal.host.company/some/path/to/1.0.0/wasm-module.wasm
// - registry://internal.host.company:5000/some/path/to/wasm-module.wasm:1.0.0
//
// The structure of the folder would look like the following:
//
// <root>
//   - https
//     - internal.host.company
//       - some
//         - path
//           - to
//             - wasm-module.wasm
//   - registry
//     - ghcr.io
//       - some
//         - path
//           - to
//             - 1.0.0
//               - wasm-module.wasm:1.0.0
//     - internal.host.company:5000
//       - some
//         - path
//           - to
//             - wasm-module.wasm:1.0.0
#[derive(Debug, PartialEq, Eq)]
pub struct Store {
    pub root: PathBuf,
}

impl Store {
    pub fn new(root: &Path) -> Self {
        Store {
            root: root.to_path_buf(),
        }
    }

    // Creates all directories provided in `path` starting from the
    // root of this store.
    pub fn ensure(&self, path: &Path) -> std::io::Result<()> {
        std::fs::create_dir_all(&self.root.join(path))
    }

    // Returns the full path of a policy coming from the URL `url` in
    // this store. If `policy_path` is set to `PrefixOnly`, the
    // filename of the policy will be omitted, otherwise it will be
    // included.
    pub fn policy_full_path(&self, url: &str, policy_path: PolicyPath) -> Result<PathBuf> {
        let path = self.policy_path(url, policy_path)?;

        Ok(self.root.join(path))
    }

    // Returns the path of a policy coming from the URL `url`
    // without the store. If `policy_path` is set to `PrefixOnly`, the
    // filename of the policy will be omitted, otherwise it will be
    // included.
    pub fn policy_path(&self, url: &str, policy_path: PolicyPath) -> Result<PathBuf> {
        let url = Url::parse(url)?;
        let filename = Store::policy_file_name(&url);
        let policy_prefix = self.policy_prefix(&url);

        Ok(match policy_path {
            PolicyPath::PrefixOnly => policy_prefix,
            PolicyPath::PrefixAndFilename => policy_prefix.join(filename),
        })
    }

    fn policy_file_name(url: &Url) -> &str {
        let filename = url.path().split('/').last().unwrap();

        // In Windows we encode the filename with base64, so it can
        // contain special characters like `:` that are not allowed in
        // the filesystem
        #[cfg(target_os = "windows")]
        let filename: String =
            base64::encode_config(filename.to_string().as_bytes(), base64::URL_SAFE_NO_PAD);

        filename
    }

    // Returns the host and port (if any) as a string.
    //
    // On Windows, given that filesystem directories and files cannot
    // include a colon (`:`), base64 the result.
    fn host_and_port(url: &Url) -> String {
        let host_and_port = url
            .host_str()
            .map(|host| {
                if let Some(port) = url.port() {
                    format!("{}:{}", host, port)
                } else {
                    host.into()
                }
            })
            .unwrap_or_default();

        // In Windows we encode the filename with base64, so it can
        // contain special characters like `:` that are not allowed in
        // the filesystem
        #[cfg(target_os = "windows")]
        let host_and_port = base64::encode_config(
            host_and_port.to_string().as_bytes(),
            base64::URL_SAFE_NO_PAD,
        );

        host_and_port
    }

    // Returns the prefix of the policy as a `PathBuf`. This prefix
    // does not include the root of the store.
    pub(crate) fn policy_prefix(&self, url: &Url) -> PathBuf {
        let element_count = url.path().split('/').count();
        let elements = url.path().split('/');
        let path = elements.skip(1).take(
            element_count - 2, /* skip empty root after split and leaf filename */
        );

        // In Windows we encode the directory names with base64, so
        // they can contain special characters like `:` that are not
        // allowed in the filesystem
        #[cfg(target_os = "windows")]
        let path = path.map(|path| base64::encode_config(path.as_bytes(), base64::URL_SAFE_NO_PAD));

        #[cfg(not(target_os = "windows"))]
        let path = path.map(String::from);

        let path = path.collect::<Vec<String>>().join("/");

        Path::new(url.scheme())
            .join(Store::host_and_port(url))
            .join(&path)
    }

    fn decode_base64(encoded_str: &[u8]) -> Result<String> {
        let encoded_str =
            ::std::str::from_utf8(encoded_str).map_err(|_| anyhow!("invalid string encoding"))?;
        let decoded_str = base64::decode_config(encoded_str, base64::URL_SAFE_NO_PAD)
            .map_err(|_| anyhow!("invalid base64 encoding"))?;
        ::std::str::from_utf8(&decoded_str)
            .map_err(|_| anyhow!("invalid string encoding"))
            .map(String::from)
    }

    // Lists all policies in this store
    //
    // On Windows, given that filesystem directories and files cannot
    // include a colon (`:`), decode the base64 from the name of the
    // directory or file.
    pub fn list(&self) -> Result<Vec<Policy>> {
        let mut policies = Vec::new();
        if let Ok(store_root_path) = std::fs::read_dir(self.root.as_path()) {
            for scheme in store_root_path {
                let scheme = scheme?;
                match scheme.file_name().to_str() {
                    Some(scheme) => {
                        if !is_known_remote_scheme(scheme) {
                            continue;
                        }
                    }
                    None => continue,
                }
                for host in std::fs::read_dir(scheme.path())? {
                    let host = host?;
                    for policy in WalkDir::new(host.path()) {
                        let policy = policy?;
                        if let Ok(metadata) = std::fs::metadata(policy.path()) {
                            if metadata.is_file() {
                                let policy_store_path =
                                    policy.path().iter().skip(host.path().components().count());
                                let policy_store_path =
                                    retrieve_policy_store_path(policy_store_path)?;
                                policies.push(Policy {
                                    uri: format!(
                                        "{}://{}{}",
                                        scheme.file_name().to_str().unwrap(),
                                        retrieve_policy_name_and_tag(host.file_name())?,
                                        policy_store_path,
                                    ),
                                    local_path: policy.path().to_path_buf(),
                                })
                            }
                        }
                    }
                }
            }
        }
        Ok(policies)
    }
}

fn retrieve_policy_name_and_tag(filename: OsString) -> Result<String> {
    if cfg!(windows) {
        Store::decode_base64(filename.to_str().unwrap().as_bytes())
    } else {
        Ok(filename.to_str().unwrap().to_string())
    }
}

// Use conditional compilation to decide implementation based on the
// target OS. In Windows, we want to transform the path in the store
// to use base64.
#[cfg(target_os = "windows")]
fn retrieve_policy_store_path<'a>(
    policy_store_path: impl std::iter::Iterator<Item = &'a OsStr>,
) -> Result<String> {
    transform_policy_store_path(policy_store_path)
}

// Use conditional compilation to decide implementation based on the
// target OS. In Unix, we want to retrieve the policy path in the
// store as found in its hierarchy
#[cfg(not(target_os = "windows"))]
fn retrieve_policy_store_path<'a>(
    policy_store_path: impl std::iter::Iterator<Item = &'a OsStr>,
) -> Result<String> {
    PathBuf::from("/")
        .join(policy_store_path.collect::<PathBuf>())
        .into_os_string()
        .into_string()
        .map_err(|_| anyhow!("invalid path"))
}

// Retrieve the policy path in the store after computing the base64 of
// every directory in the store hierarchy and convert the result to a
// string comprised of forward slashes. Resulting String should
// contain forward-slashes in all platforms.
#[allow(dead_code)]
fn transform_policy_store_path<'a>(
    mut policy_store_path: impl std::iter::Iterator<Item = &'a OsStr>,
) -> Result<String> {
    Ok(policy_store_path
        .try_fold(PathBuf::from("/"), |acc, x| {
            if let Ok(decoded_filename) = Store::decode_base64(x.to_string_lossy().as_bytes()) {
                Ok(acc.join(decoded_filename))
            } else {
                Err(anyhow!("invalid filename"))
            }
        })
        .map_err(|_| anyhow!("cannot compute policy path"))?
        .to_slash_lossy()
        .to_string())
}

impl Default for Store {
    fn default() -> Self {
        Self {
            root: DEFAULT_STORE_ROOT.clone(),
        }
    }
}

fn is_known_remote_scheme(scheme: &str) -> bool {
    KNOWN_REMOTE_SCHEMES.contains(&scheme)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Store;
    use rstest::rstest;

    #[test]
    fn keep_policy_full_path_unix() {
        assert_eq!(
            retrieve_policy_store_path(
                PathBuf::from("/registry/example.com:1234/some/path").iter()
            )
            .unwrap(),
            "/registry/example.com:1234/some/path".to_string()
        );
        assert_eq!(
            retrieve_policy_store_path(
                PathBuf::from("/registry/example.com:1234/some/path/to/policy:tag").iter()
            )
            .unwrap(),
            "/registry/example.com:1234/some/path/to/policy:tag".to_string()
        );
        assert_eq!(
            retrieve_policy_store_path(PathBuf::from("/https/example.com:1234/some/path").iter())
                .unwrap(),
            "/https/example.com:1234/some/path".to_string()
        );
    }

    #[test]
    fn transform_policy_full_path_windows() -> Result<()> {
        assert_eq!(
            transform_policy_store_path(
                PathBuf::new()
                    .join(base64::encode_config(
                        "registry".as_bytes(),
                        base64::URL_SAFE_NO_PAD
                    ))
                    .join(base64::encode_config(
                        "example.com:1234".as_bytes(),
                        base64::URL_SAFE_NO_PAD
                    ))
                    .join(base64::encode_config(
                        "some".as_bytes(),
                        base64::URL_SAFE_NO_PAD
                    ))
                    .join(base64::encode_config(
                        "path".as_bytes(),
                        base64::URL_SAFE_NO_PAD
                    ))
                    .iter()
            )?,
            "/registry/example.com:1234/some/path".to_string()
        );
        assert_eq!(
            transform_policy_store_path(
                PathBuf::new()
                    .join(base64::encode_config(
                        "registry".as_bytes(),
                        base64::URL_SAFE_NO_PAD
                    ))
                    .join(base64::encode_config(
                        "example.com:1234".as_bytes(),
                        base64::URL_SAFE_NO_PAD
                    ))
                    .join(base64::encode_config(
                        "some".as_bytes(),
                        base64::URL_SAFE_NO_PAD
                    ))
                    .join(base64::encode_config(
                        "path".as_bytes(),
                        base64::URL_SAFE_NO_PAD
                    ))
                    .join(base64::encode_config(
                        "to".as_bytes(),
                        base64::URL_SAFE_NO_PAD
                    ))
                    .join(base64::encode_config(
                        "policy:tag".as_bytes(),
                        base64::URL_SAFE_NO_PAD
                    ))
                    .iter()
            )?,
            "/registry/example.com:1234/some/path/to/policy:tag".to_string()
        );
        assert_eq!(
            transform_policy_store_path(
                PathBuf::new()
                    .join(base64::encode_config(
                        "https".as_bytes(),
                        base64::URL_SAFE_NO_PAD
                    ))
                    .join(base64::encode_config(
                        "example.com:1234".as_bytes(),
                        base64::URL_SAFE_NO_PAD
                    ))
                    .join(base64::encode_config(
                        "some".as_bytes(),
                        base64::URL_SAFE_NO_PAD
                    ))
                    .join(base64::encode_config(
                        "path".as_bytes(),
                        base64::URL_SAFE_NO_PAD
                    ))
                    .iter()
            )?,
            "/https/example.com:1234/some/path".to_string()
        );
        Ok(())
    }

    #[rstest(
        input_url,
        input_policy_path,
        expected_relative_path,
        case(
            "registry://ghcr.io/kubewarden/policies/pod-privileged:v0.2.2",
            PolicyPath::PrefixAndFilename,
            "registry/ghcr.io/kubewarden/policies/pod-privileged:v0.2.2"
        ),
        case(
            "https://github.com/kubewarden/pod-privileged-policy/releases/download/v0.1.6/policy.wasm ",
            PolicyPath::PrefixAndFilename,
            "https/github.com/kubewarden/pod-privileged-policy/releases/download/v0.1.6/policy.wasm"
        ),
        case(
            "registry://ghcr.io/kubewarden/policies/pod-privileged:v0.2.2",
            PolicyPath::PrefixOnly,
            "registry/ghcr.io/kubewarden/policies"
        ),
        case(
            "https://github.com/kubewarden/pod-privileged-policy/releases/download/v0.1.6/policy.wasm ",
            PolicyPath::PrefixOnly,
            "https/github.com/kubewarden/pod-privileged-policy/releases/download/v0.1.6"
        )
    )]
    fn policy_full_path(
        input_url: &str,
        input_policy_path: PolicyPath,
        expected_relative_path: &str,
    ) -> Result<()> {
        let default = Store::default();
        let path = default.policy_full_path(input_url, input_policy_path)?;
        assert_eq!(default.root.join(expected_relative_path), path);

        Ok(())
    }

    #[rstest(
        input_url,
        input_policy_path,
        expected_path,
        case(
            "registry://ghcr.io/kubewarden/policies/pod-privileged:v0.2.2",
            PolicyPath::PrefixAndFilename,
            "registry/ghcr.io/kubewarden/policies/pod-privileged:v0.2.2"
        ),
        case(
            "https://github.com/kubewarden/pod-privileged-policy/releases/download/v0.1.6/policy.wasm ",
            PolicyPath::PrefixAndFilename,
            "https/github.com/kubewarden/pod-privileged-policy/releases/download/v0.1.6/policy.wasm"
        ),
        case(
            "registry://ghcr.io/kubewarden/policies/pod-privileged:v0.2.2",
            PolicyPath::PrefixOnly,
            "registry/ghcr.io/kubewarden/policies"
        ),
        case(
            "https://github.com/kubewarden/pod-privileged-policy/releases/download/v0.1.6/policy.wasm ",
            PolicyPath::PrefixOnly,
            "https/github.com/kubewarden/pod-privileged-policy/releases/download/v0.1.6"
        )
    )]
    fn policy_path(
        input_url: &str,
        input_policy_path: PolicyPath,
        expected_path: &str,
    ) -> Result<()> {
        let default = Store::default();
        let path = default.policy_path(input_url, input_policy_path)?;
        assert_eq!(PathBuf::from(expected_path), path);

        Ok(())
    }
}
