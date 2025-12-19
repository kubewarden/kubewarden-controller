use anyhow::Result;
use clap::ArgMatches;

use crate::config::pull_and_run::{parse_policy_definitions, parse_pull_and_run_settings};

pub(crate) async fn exec(matches: &ArgMatches) -> Result<()> {
    let policy_definitions = parse_policy_definitions(matches)?;
    let pull_and_run_settings = parse_pull_and_run_settings(matches, &policy_definitions).await?;

    crate::command::run::exec(&policy_definitions, &pull_and_run_settings).await
}
