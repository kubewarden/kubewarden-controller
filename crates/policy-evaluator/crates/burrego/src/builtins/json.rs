use anyhow::{anyhow, Result};

pub fn patch(args: &[serde_json::Value]) -> Result<serde_json::Value> {
    if args.len() != 2 {
        return Err(anyhow!("Wrong number of arguments given to json.patch"));
    }

    if !args[0].is_object() {
        return Err(anyhow!("json.patch: 1st parameter is not an object"));
    }
    let mut obj = args[0].clone();

    if !args[1].is_array() {
        return Err(anyhow!("json.patch: 2nd parameter is not an array"));
    }
    let patches_str = serde_json::to_string(&args[1])
        .map_err(|_| anyhow!("json.patch: cannot convert 2nd parameter to string"))?;
    let patches: json_patch::Patch = serde_json::from_str(&patches_str).unwrap();

    json_patch::patch(&mut obj, &patches)
        .map_err(|e| anyhow!("json.patch: cannot apply patch: {:?}", e))?;

    serde_json::to_value(obj).map_err(|e| anyhow!("Cannot convert value into JSON: {:?}", e))
}

#[cfg(test)]
mod test {
    use super::*;
    use assert_json_diff::assert_json_eq;
    use serde_json::json;

    #[test]
    fn test_patch() {
        let args: Vec<serde_json::Value> = vec![
            json!({"a": {"foo": 1}}),
            json!([{"op": "add", "path": "/a/bar", "value": 2}]),
        ];

        let actual = patch(&args);
        assert!(actual.is_ok());
        assert_json_eq!(json!({"a": {"foo": 1, "bar": 2}}), actual.unwrap());
    }
}
