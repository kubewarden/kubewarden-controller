use anyhow::Result;
use clap::crate_version;
use itertools::Itertools;
use policy_evaluator::{
    burrego,
    policy_fetcher::store::{Store, DEFAULT_ROOT},
};

pub(crate) fn info() -> Result<()> {
    let builtins: String = burrego::get_builtins()
        .keys()
        .sorted()
        .map(|builtin| format!("  - {builtin}"))
        .join("\n");

    let store = Store::default();

    println!(
        r#"kwctl version: {}

Open Policy Agent/Gatekeeper implemented builtins:
{}

Policy store: {}
Config directory: {}
    "#,
        crate_version!(),
        builtins,
        store.root.to_string_lossy(),
        DEFAULT_ROOT.config_dir().to_string_lossy(),
    );

    Ok(())
}
