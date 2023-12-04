mod cli;

use anyhow::Result;

fn main() -> Result<()> {
    let matches = cli::build_cli().get_matches();
    let config = policy_server::config::Config::from_args(&matches)?;

    policy_server::run(config)
}
