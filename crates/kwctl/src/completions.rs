use anyhow::{anyhow, Result};
use clap_complete::{
    generate,
    shells::{Bash, Elvish, Fish, PowerShell, Zsh},
};
use std::io;

pub(crate) fn completions(shell: &str) -> Result<()> {
    let mut app = crate::cli::build_cli();

    match shell {
        "bash" => {
            generate(Bash, &mut app, "kwctl", &mut io::stdout());
            Ok(())
        }
        "fish" => {
            generate(Fish, &mut app, "kwctl", &mut io::stdout());
            Ok(())
        }
        "zsh" => {
            generate(Zsh, &mut app, "kwctl", &mut io::stdout());
            Ok(())
        }
        "elvish" => {
            generate(Elvish, &mut app, "kwctl", &mut io::stdout());
            Ok(())
        }
        "powershell" => {
            generate(PowerShell, &mut app, "kwctl", &mut io::stdout());
            Ok(())
        }
        unknown => Err(anyhow!("Unknown shell '{}'", unknown)),
    }
}
