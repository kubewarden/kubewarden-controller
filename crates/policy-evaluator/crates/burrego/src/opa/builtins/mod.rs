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
    functions.insert("urlquery.encode", encoding::urlquery::encode);
    functions.insert("urlquery.decode", encoding::urlquery::decode);
    functions.insert("urlquery.encode_object", encoding::urlquery::encode_object);
    functions.insert("urlquery.decode_object", encoding::urlquery::decode_object);
    functions.insert("json.is_valid", encoding::json::is_valid);
    functions.insert("yaml.marshal", encoding::yaml::marshal);
    functions.insert("yaml.unmarshal", encoding::yaml::unmarshal);
    functions.insert("hex.encode", encoding::hex::encode);

    functions
}
