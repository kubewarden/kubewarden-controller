use anyhow::Result;

use std::path::{Path, PathBuf};
use std::str::FromStr;
use walkdir::WalkDir;

use crate::policy::Policy;

static KNOWN_REMOTE_SCHEMES: &[&str] = &["http", "https", "registry"];
const DEFAULT_STORE_ROOT: &str = ".kubewarden/store";

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
pub struct Store {
    pub root: PathBuf,
}

impl Store {
    pub fn new(root: &Path) -> Self {
        Store {
            root: root.to_path_buf(),
        }
    }

    #[cfg(not(test))]
    pub fn ensure(&self, path: &Path) -> Result<()> {
        std::fs::create_dir_all(&self.root.join(path)).map_err(|e| e.into())
    }

    #[cfg(test)]
    pub fn ensure(&self, _path: &Path) -> Result<()> {
        Ok(())
    }

    pub fn list(&self) -> std::io::Result<Vec<Policy>> {
        let mut policies = Vec::new();
        for scheme in std::fs::read_dir(self.root.as_path())? {
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
                            policies.push(Policy {
                                uri: format!(
                                    "{}://{}{}",
                                    scheme.file_name().to_str().unwrap(),
                                    host.file_name().to_str().unwrap(),
                                    policy.path().to_str().unwrap().trim_start_matches(
                                        self.root
                                            .join(scheme.file_name())
                                            .join(host.file_name())
                                            .to_str()
                                            .unwrap(),
                                    )
                                ),
                                local_path: policy.path().to_path_buf(),
                            })
                        }
                    }
                }
            }
        }
        Ok(policies)
    }
}

impl Default for Store {
    fn default() -> Self {
        Self {
            root: home::home_dir()
                .unwrap_or_else(|| PathBuf::from_str(".").unwrap())
                .join(DEFAULT_STORE_ROOT),
        }
    }
}

fn is_known_remote_scheme(scheme: &str) -> bool {
    KNOWN_REMOTE_SCHEMES.contains(&scheme)
}
