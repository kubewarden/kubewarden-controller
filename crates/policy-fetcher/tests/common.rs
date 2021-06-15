use std::{fs::read_to_string, path::Path};

#[allow(dead_code)]
pub(crate) fn test_data(filename: &Path) -> String {
    let test_data_file = std::env::current_dir()
        .expect(&format!(
            "[test setup error] could not read the current directory"
        ))
        .join("tests")
        .join("test_data")
        .join(filename);

    read_to_string(&test_data_file).expect(&format!(
        "[test setup error] could not read file {:?}",
        &test_data_file
    ))
}
