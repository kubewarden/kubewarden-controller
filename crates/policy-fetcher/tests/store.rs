use std::path::Path;

use anyhow::Result;
use policy_fetcher::policy::Policy;
use policy_fetcher::store::{path, Store};
use tempfile::tempdir;

#[test]
fn test_list() -> Result<()> {
    let store_root = tempdir()?;

    let mut expected_policies = vec![
        Policy {
            uri: "https://internal.host.company/some/path/to/1.0.0/wasm-module.wasm".to_owned(),
            local_path: store_root.path().join(path::encode_path(
                "https/internal.host.company/some/path/to/1.0.0/wasm-module.wasm",
            )),
        },
        Policy {
            uri: "registry://ghcr.io/some/path/to/wasm-module.wasm:1.0.0".to_owned(),
            local_path: store_root.path().join(path::encode_path(
                "registry/ghcr.io/some/path/to/wasm-module.wasm:1.0.0",
            )),
        },
        Policy {
            uri: "registry://internal.host.company:5000/some/path/to/wasm-module.wasm:1.0.0"
                .to_owned(),
            local_path: store_root.path().join(path::encode_path(
                "registry/internal.host.company:5000/some/path/to/wasm-module.wasm:1.0.0",
            )),
        },
    ];

    setup_store(&expected_policies)?;

    let store = Store::new(store_root.path());
    let mut list = store.list()?;

    expected_policies.sort_by_key(|p| p.uri.clone());
    list.sort_by_key(|p| p.uri.clone());

    assert_eq!(expected_policies, list);

    Ok(())
}

fn setup_store(policies: &[Policy]) -> Result<()> {
    for policy in policies {
        std::fs::create_dir_all(policy.local_path.parent().unwrap())?;

        std::fs::copy(
            Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/test_data/simple.wasm"),
            &policy.local_path,
        )?;
    }

    Ok(())
}
