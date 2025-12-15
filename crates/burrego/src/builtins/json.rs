use crate::errors::{BurregoError, Result};

pub fn patch(args: &[serde_json::Value]) -> Result<serde_json::Value> {
    if args.len() != 2 {
        return Err(BurregoError::BuiltinError {
            name: "json.patch".to_string(),
            message: "wrong number of arguments".to_string(),
        });
    }

    if !args[0].is_object() {
        return Err(BurregoError::BuiltinError {
            name: "json.patch".to_string(),
            message: "1st parameter is not an object".to_string(),
        });
    }
    let mut obj = args[0].clone();

    if !args[1].is_array() {
        return Err(BurregoError::BuiltinError {
            name: "json.patch".to_string(),
            message: "2nd parameter is not an array".to_string(),
        });
    }
    let patches_str = serde_json::to_string(&args[1]).map_err(|_| BurregoError::BuiltinError {
        name: "json.patch".to_string(),
        message: "cannot convert 2nd parameter to string".to_string(),
    })?;
    let patches: json_patch::Patch = serde_json::from_str(&patches_str).unwrap();

    json_patch::patch(&mut obj, &patches).map_err(|e| BurregoError::BuiltinError {
        name: "json.patch".to_string(),
        message: format!("cannot apply patch: {e:?}"),
    })?;

    serde_json::to_value(obj).map_err(|e| BurregoError::BuiltinError {
        name: "json.patch".to_string(),
        message: format!("cannot convert value into JSON: {e:?}"),
    })
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
