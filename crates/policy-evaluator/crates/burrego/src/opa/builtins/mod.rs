use anyhow::Result;
use std::collections::HashMap;

pub mod strings;

pub fn get_builtins(
) -> HashMap<&'static str, fn(&Vec<serde_json::Value>) -> Result<serde_json::Value>> {
    let mut functions: HashMap<
        &'static str,
        fn(&Vec<serde_json::Value>) -> Result<serde_json::Value>,
    > = HashMap::new();
    functions.insert("sprintf", strings::sprintf);

    functions
}
