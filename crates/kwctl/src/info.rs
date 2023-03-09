use anyhow::Result;
use clap::crate_version;
use itertools::Itertools;
use policy_evaluator::{burrego, policy_fetcher::store::Store};

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

Policy store: {}"
    "#,
        crate_version!(),
        builtins,
        store.root.to_string_lossy()
    );

    Ok(())
}
