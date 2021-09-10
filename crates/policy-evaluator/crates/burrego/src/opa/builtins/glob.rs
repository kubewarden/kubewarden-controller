use anyhow::{anyhow, Result};

pub fn quote_meta(args: &[serde_json::Value]) -> Result<serde_json::Value> {
    if args.len() != 1 {
        return Err(anyhow!("glob.quote_meta: wrong number of arguments"));
    }

    let input = args[0]
        .as_str()
        .ok_or_else(|| anyhow!("glob.quote_meta: 1st parameter is not a string"))?;

    serde_json::to_value(escape(input))
        .map_err(|e| anyhow!("glob.quote_meta: cannot convert value into JSON: {:?}", e))
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

        assert_eq!(super::escape("some *?\\[]{} text"), "some \\*\\?\\\\\\[\\]\\{\\} text");
    }
}
