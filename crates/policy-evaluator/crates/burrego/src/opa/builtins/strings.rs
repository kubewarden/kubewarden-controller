use anyhow::{anyhow, Result};

pub fn sprintf(args: &Vec<serde_json::Value>) -> Result<serde_json::Value> {
    println!("sprintf invoked with: {:?}", args);
    if args.len() != 2 {
        return Err(anyhow!("Wrong number of arguments given to sprintf"));
    }

    let fmt_str = args[0]
        .as_str()
        .ok_or(anyhow!("sprintf: 1st parameter is not a string"))?;
    let fmt_args: Vec<String> = args[1]
        .as_array()
        .ok_or(anyhow!("sprintf: 2nd parameter is not an array"))?
        .iter()
        .map(|i| match i {
            serde_json::Value::String(v) => format!(r#""{}""#, v),
            serde_json::Value::Number(v) => v.to_string(),
            serde_json::Value::Bool(v) => v.to_string(),
            _ => String::from(""),
        })
        .collect();

    let template_str = format!(r#"{{{{ printf "{}" {}}}}}"#, fmt_str, fmt_args.join(" "));
    let templ_args: Vec<gtmpl::Value> = Vec::new();
    let res = gtmpl::template(&template_str, templ_args.as_slice())
        .map_err(|e| anyhow!("Cannot render go template: {:?}", e))?;

    serde_json::to_value(res).map_err(|e| anyhow!("Cannot convert value into JSON: {:?}", e))
}
