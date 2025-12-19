use std::path::Path;

use assert_cmd::Command;

#[allow(dead_code)]
pub fn setup_command(path: &Path) -> Command {
    let mut cmd = Command::cargo_bin("kwctl").unwrap();

    cmd.current_dir(path)
        .env("XDG_CONFIG_HOME", path.join(".config"))
        .env("XDG_CACHE_HOME", path.join(".cache"))
        .env("XDG_DATA_HOME", path.join(".local/share"));

    cmd
}

#[allow(dead_code)]
pub fn test_data(path: &str) -> String {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("data")
        .join(path)
        .to_string_lossy()
        .to_string()
}
