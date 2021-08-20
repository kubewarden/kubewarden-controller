use anyhow::Result;
use std::collections::HashMap;

pub mod encoding;
pub mod strings;

pub type BuiltinFunctionsMap =
    HashMap<&'static str, fn(&[serde_json::Value]) -> Result<serde_json::Value>>;

pub fn get_builtins() -> BuiltinFunctionsMap {
    let mut functions: BuiltinFunctionsMap = HashMap::new();
    functions.insert("sprintf", strings::sprintf);

    // encoding
    functions.insert(
        "base64url.encode_no_pad",
        encoding::base64url::encode_no_pad,
    );

    functions
}
