use crate::errors::{BurregoError, Result};

#[tracing::instrument(skip(args))]
pub fn trace(args: &[serde_json::Value]) -> Result<serde_json::Value> {
    if args.len() != 1 {
        return Err(BurregoError::BuiltinError {
            name: "trace".to_string(),
            message: "Wrong number of arguments".to_string(),
        });
    }

    let message_str = args[0].as_str().ok_or_else(|| BurregoError::BuiltinError {
        name: "trace".to_string(),
        message: "1st parameter is not a string".to_string(),
    })?;

    tracing::debug!("{}", message_str);

    Ok(serde_json::Value::Null)
}
