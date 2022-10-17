use anyhow::{anyhow, Result};

#[tracing::instrument(skip(args))]
pub fn trace(args: &[serde_json::Value]) -> Result<serde_json::Value> {
    if args.len() != 1 {
        return Err(anyhow!("Wrong number of arguments given to trace"));
    }

    let message_str = args[0]
        .as_str()
        .ok_or_else(|| anyhow!("trace: 1st parameter is not a string"))?;

    tracing::debug!("{}", message_str);

    Ok(serde_json::Value::Null)
}
