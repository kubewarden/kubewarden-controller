use anyhow::Result;
use std::collections::HashMap;

pub mod strings;

pub type BuiltinFunctionsMap =
    HashMap<&'static str, fn(&[serde_json::Value]) -> Result<serde_json::Value>>;

pub fn get_builtins() -> BuiltinFunctionsMap {
    //let mut functions: HashMap<
    //    &'static str,
    //    fn(&Vec<serde_json::Value>) -> Result<serde_json::Value>,
    //> = HashMap::new();
    let mut functions: BuiltinFunctionsMap = HashMap::new();
    functions.insert("sprintf", strings::sprintf);

    functions
}
