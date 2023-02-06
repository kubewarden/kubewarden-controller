use crate::errors::{BurregoError, Result};
use std::{collections::HashMap, convert::From};

struct GoTmplValue(gtmpl::Value);

impl From<serde_json::Value> for GoTmplValue {
    fn from(value: serde_json::Value) -> Self {
        match value {
            serde_json::Value::String(s) => GoTmplValue(gtmpl::Value::String(s)),
            serde_json::Value::Number(n) => {
                let n: i64 = n.as_i64().unwrap();
                let number: gtmpl_value::Number = n.into();
                GoTmplValue(gtmpl::Value::Number(number))
            }
            serde_json::Value::Bool(b) => GoTmplValue(gtmpl::Value::Bool(b)),
            serde_json::Value::Array(arr) => {
                let res: Vec<gtmpl::Value> = arr
                    .iter()
                    .map(|i| {
                        let v: GoTmplValue = i.clone().into();
                        v.0
                    })
                    .collect();
                GoTmplValue(gtmpl::Value::Array(res))
            }
            serde_json::Value::Object(obj) => {
                let res: HashMap<String, gtmpl::Value> = obj
                    .iter()
                    .map(|(k, v)| {
                        let val: GoTmplValue = v.clone().into();
                        (k.clone(), val.0)
                    })
                    .collect();
                GoTmplValue(gtmpl::Value::Map(res))
            }
            _ => GoTmplValue(gtmpl::Value::Nil),
        }
    }
}

pub fn sprintf(args: &[serde_json::Value]) -> Result<serde_json::Value> {
    if args.len() != 2 {
        return Err(BurregoError::BuiltinError {
            name: "sprintf".to_string(),
            message: "Wrong number of arguments given".to_string(),
        });
    }

    let fmt_str = args[0].as_str().ok_or_else(|| BurregoError::BuiltinError {
        name: "sprintf".to_string(),
        message: "1st parameter is not a string".to_string(),
    })?;
    let fmt_args: Vec<gtmpl::Value> = args[1]
        .as_array()
        .ok_or_else(|| BurregoError::BuiltinError {
            name: "sprintf".to_string(),
            message: "2nd parameter is not an array".to_string(),
        })?
        .iter()
        .map(|i| {
            let g: GoTmplValue = i.clone().into();
            g.0
        })
        .collect();

    let mut index_cmds: Vec<String> = Vec::new();
    for i in 0..fmt_args.len() {
        index_cmds.push(format!("(index . {i})"));
    }

    let template_str = format!(r#"{{{{ printf "{}" {}}}}}"#, fmt_str, index_cmds.join(" "));
    let res = gtmpl::template(&template_str, fmt_args.as_slice()).map_err(|e| {
        BurregoError::BuiltinError {
            name: "sprintf".to_string(),
            message: format!(
                "Cannot render go template '{template_str}' with args {fmt_args:?}: {e:?}"
            ),
        }
    })?;

    serde_json::to_value(res).map_err(|e| BurregoError::BuiltinError {
        name: "sprintf".to_string(),
        message: format!("Cannot convert value into JSON: {e:?}"),
    })
}

#[cfg(test)]
mod test {
    use super::*;
    use serde_json::json;

    #[test]
    fn sprintf_mixed_input() {
        let args: Vec<serde_json::Value> = vec![
            json!("hello %v %v %v"),
            json!(["world", 42, ["this", "is", "a", "list"]]),
        ];

        let actual = sprintf(&args);
        assert!(actual.is_ok());
        assert_eq!(json!("hello world 42 [this is a list]"), actual.unwrap());
    }
}
