use crate::errors::{BurregoError, Result};

pub fn quote_meta(args: &[serde_json::Value]) -> Result<serde_json::Value> {
    if args.len() != 1 {
        return Err(BurregoError::BuiltinError {
            name: "glob.quote_meta".to_string(),
            message: "wrong number of arguments".to_string(),
        });
    }

    let input = args[0].as_str().ok_or_else(|| BurregoError::BuiltinError {
        name: "glob.quote_meta".to_string(),
        message: "1st parameter is not a string".to_string(),
    })?;

    serde_json::to_value(escape(input)).map_err(|e| BurregoError::BuiltinError {
        name: "glob.quote_meta".to_string(),
        message: format!("cannot convert value into JSON: {:?}", e),
    })
}

fn escape(s: &str) -> String {
    let mut escaped = String::new();
    for c in s.chars() {
        match c {
            '*' | '?' | '\\' | '[' | ']' | '{' | '}' => {
                escaped.push('\\');
                escaped.push(c);
            }
            c => {
                escaped.push(c);
            }
        }
    }
    escaped
}

#[cfg(test)]
mod test {
    #[test]
    fn escape() {
        assert_eq!(super::escape("*.domain.com"), r"\*.domain.com");

        assert_eq!(super::escape("*.domain-*.com"), r"\*.domain-\*.com");

        assert_eq!(super::escape("domain.com"), r"domain.com");

        assert_eq!(super::escape("domain-[ab].com"), r"domain-\[ab\].com");

        assert_eq!(super::escape("nie?ce"), r"nie\?ce");

        assert_eq!(
            super::escape("some *?\\[]{} text"),
            "some \\*\\?\\\\\\[\\]\\{\\} text"
        );
    }
}
