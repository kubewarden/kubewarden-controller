use anyhow::Result;

pub(crate) fn completions(shell: &clap::Shell) -> Result<()> {
    let mut app = crate::cli::build_cli();
    let mut buf: Vec<u8> = Vec::new();
    app.gen_completions_to("kwctl", *shell, &mut buf);

    let output = String::from_utf8(buf)?;

    match shell {
        clap::Shell::Zsh => print!("{}", fix_zsh_completion(&output)),
        _ => print!("{}", output),
    };

    Ok(())
}

// zsh output has to be fixed, the last line should not be used
// See: https://github.com/clap-rs/clap/issues/2488#issuecomment-864576617
fn fix_zsh_completion(output: &str) -> String {
    let line_count = output.lines().count();
    let res: Vec<String> = output
        .lines()
        .take(line_count - 1)
        .map(String::from)
        .collect();
    res.join("\n")
}
