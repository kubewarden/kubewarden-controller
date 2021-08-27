pub mod base64url {
    use anyhow::{anyhow, Result};

    pub fn encode_no_pad(args: &[serde_json::Value]) -> Result<serde_json::Value> {
        if args.len() != 1 {
            return Err(anyhow!(
                "base64url.encode_no_pad: wrong number of arguments"
            ));
        }

        let input = args[0]
            .as_str()
            .ok_or_else(|| anyhow!("base64url.encode_no_pad: 1st parameter is not a string"))?;

        let res = base64::encode_config(input, base64::URL_SAFE_NO_PAD);

        serde_json::to_value(res).map_err(|e| {
            anyhow!(
                "base64url.encode_no_pad: cannot convert value into JSON: {:?}",
                e
            )
        })
    }

    #[cfg(test)]
    mod test {
        use super::*;
        use serde_json::json;

        #[test]
        fn test_encode_no_pad() {
            let input = "Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat. Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur. Excepteur sint occaecat cupidatat non proident, sunt in culpa qui officia deserunt mollit anim id est laborum.";

            let args: Vec<serde_json::Value> = vec![json!(input)];
            let actual = encode_no_pad(&args);
            assert!(actual.is_ok());

            let actual = actual.unwrap();
            assert_eq!(
                json!(base64::encode_config(input, base64::URL_SAFE_NO_PAD)),
                actual
            );
            assert_ne!(
                json!(base64::encode_config(input, base64::URL_SAFE)),
                actual
            );
        }
    }
}

pub mod urlquery {
    use anyhow::{anyhow, Result};
    use std::collections::HashMap;
    use url::Url;

    pub fn encode(args: &[serde_json::Value]) -> Result<serde_json::Value> {
        if args.len() != 1 {
            return Err(anyhow!("urlquery.encode: wrong number of arguments"));
        }

        let input = args[0]
            .as_str()
            .ok_or_else(|| anyhow!("urlquery.encode: 1st parameter is not a string"))?;

        let mut url = Url::parse("https://example.com/")
            .map_err(|e| anyhow!("urlquery.encode: internal error 1 - {:?}", e))?;
        url.set_query(Some(format!("input={}", input).as_str()));

        let res = url
            .query()
            .ok_or_else(|| anyhow!("urlquery.encode: internal error 2"))?;
        let res = res
            .strip_prefix("input=")
            .ok_or_else(|| anyhow!("urlquery.encode: internal error 3"))?;

        serde_json::to_value(res)
            .map_err(|e| anyhow!("urlquery.encode: Cannot convert value into JSON: {:?}", e))
    }

    pub fn decode(args: &[serde_json::Value]) -> Result<serde_json::Value> {
        if args.len() != 1 {
            return Err(anyhow!("urlquery.decode: wrong number of arguments"));
        }

        let input = args[0]
            .as_str()
            .ok_or_else(|| anyhow!("urlquery.decode: 1st parameter is not a string"))?;

        let mut url = Url::parse("https://example.com/")
            .map_err(|e| anyhow!("urlquery.decode: internal error 1 - {:?}", e))?;
        url.set_query(Some(format!("input={}", input).as_str()));

        let mut pairs = url.query_pairs();
        if pairs.count() != 1 {
            return Err(anyhow!("urlquery.decode: internal error 2"));
        }
        let (_, value) = pairs.next().unwrap();
        serde_json::to_value(&value)
            .map_err(|e| anyhow!("urlquery.decode: Cannot convert value into JSON: {:?}", e))
    }

    pub fn encode_object(args: &[serde_json::Value]) -> Result<serde_json::Value> {
        if args.len() != 1 {
            return Err(anyhow!("urlquery.encode_object: wrong number of arguments"));
        }

        let obj = args[0]
            .as_object()
            .ok_or_else(|| anyhow!("urlquery.encode_object: 1st parameter is not an object"))?;

        let mut url = Url::parse("https://example.com/")
            .map_err(|e| anyhow!("urlquery.encode_object: internal error 1 - {:?}", e))?;

        let mut queries: Vec<String> = Vec::new();
        for (key, value) in obj.iter() {
            let value_str = value.as_str();
            if value_str.is_none() {
                return Err(anyhow!(
                    "urlquery.encode_object: the value of key {} is not a string",
                    key
                ));
            }
            queries.push(format!("{}={}", key, value_str.unwrap()));
        }
        url.set_query(Some(queries.join("&").as_str()));

        let res = url
            .query()
            .ok_or_else(|| anyhow!("urlquery.encode_object: internal error 2"))?;

        serde_json::to_value(res).map_err(|e| {
            anyhow!(
                "urlquery.encode_object: Cannot convert value into JSON: {:?}",
                e
            )
        })
    }

    pub fn decode_object(args: &[serde_json::Value]) -> Result<serde_json::Value> {
        if args.len() != 1 {
            return Err(anyhow!("urlquery.decode_object: wrong number of arguments"));
        }

        let input = args[0]
            .as_str()
            .ok_or_else(|| anyhow!("urlquery.decode: 1st parameter is not a string"))?;

        let mut url = Url::parse("https://example.com/")
            .map_err(|e| anyhow!("urlquery.decode_object: internal error 1 - {:?}", e))?;
        url.set_query(Some(input));

        let mut res: HashMap<String, String> = HashMap::new();
        let pairs = url.query_pairs();
        for (key, value) in pairs {
            res.insert(String::from(key), String::from(value));
        }

        serde_json::to_value(&res).map_err(|e| {
            anyhow!(
                "urlquery.decode_object: Cannot convert value into JSON: {:?}",
                e
            )
        })
    }

    #[cfg(test)]
    mod test {
        use super::*;
        use assert_json_diff::assert_json_eq;
        use serde_json::json;

        #[test]
        fn test_encode() {
            let input = "español";

            let args: Vec<serde_json::Value> = vec![json!(input)];
            let actual = encode(&args);
            assert!(actual.is_ok());

            let actual = actual.unwrap();
            assert_eq!(json!("espa%C3%B1ol"), actual);
        }

        #[test]
        fn test_decode() {
            let input = "espa%C3%B1ol";

            let args: Vec<serde_json::Value> = vec![json!(input)];
            let actual = decode(&args);
            assert!(actual.is_ok());

            let actual = actual.unwrap();
            assert_eq!(json!("español"), actual);
        }

        #[test]
        fn test_encode_object() {
            let input = json!(
            {
                "language": "español",
                "name": "Rafael Fernández López"
            });

            let args: Vec<serde_json::Value> = vec![json!(input)];
            let actual = encode_object(&args);
            assert!(actual.is_ok());

            assert_json_eq!(
                json!("language=espa%C3%B1ol&name=Rafael%20Fern%C3%A1ndez%20L%C3%B3pez"),
                actual.unwrap()
            );
        }

        #[test]
        fn test_encode_object_does_not_have_string_values() {
            let input = json!(
            {
                "language": "español",
                "name": "Rafael Fernández López",
                "awesomeness": 100,
            });

            let args: Vec<serde_json::Value> = vec![json!(input)];
            let actual = encode_object(&args);
            assert!(actual.is_err());
        }

        #[test]
        fn test_decode_object() {
            let expected = json!(
            {
                "language": "español",
                "name": "Rafael Fernández López"
            });
            let input = json!("language=espa%C3%B1ol&name=Rafael%20Fern%C3%A1ndez%20L%C3%B3pez");

            let args: Vec<serde_json::Value> = vec![json!(input)];
            let actual = decode_object(&args);
            assert!(actual.is_ok());
            assert_json_eq!(expected, actual.unwrap());
        }
    }
}

pub mod json {
    use anyhow::{anyhow, Result};

    pub fn is_valid(args: &[serde_json::Value]) -> Result<serde_json::Value> {
        if args.len() != 1 {
            return Err(anyhow!("json.is_valid: wrong number of arguments"));
        }

        let input = args[0]
            .as_str()
            .ok_or_else(|| anyhow!("json.is_valid: 1st parameter is not a string"))?;

        let v: serde_json::Result<serde_json::Value> = serde_json::from_str(input);
        let res = v.is_ok();

        serde_json::to_value(res)
            .map_err(|e| anyhow!("json.is_valid: cannot convert value into JSON: {:?}", e))
    }

    #[cfg(test)]
    mod test {
        use super::*;
        use assert_json_diff::assert_json_eq;
        use serde_json::json;
        use std::collections::HashMap;

        #[test]
        fn test_is_valid() {
            let mut cases: HashMap<String, bool> = HashMap::new();
            cases.insert(String::from("[1,2]"), true);
            cases.insert(String::from("[1,2"), false);

            for (input, expected) in cases.iter() {
                let args: Vec<serde_json::Value> = vec![json!(input)];
                let actual = is_valid(&args);
                assert!(actual.is_ok());

                let actual = actual.unwrap();
                assert_json_eq!(json!(expected), actual);
            }
        }
    }
}

pub mod yaml {
    use anyhow::{anyhow, Result};

    pub fn marshal(args: &[serde_json::Value]) -> Result<serde_json::Value> {
        if args.len() != 1 {
            return Err(anyhow!("yaml.marshal: wrong number of arguments"));
        }

        let input: serde_json::Value = args[0].clone();

        // convert the generic input json value into a generic yaml value
        let value: serde_yaml::Value = serde_json::from_value(input).map_err(|e| {
            anyhow!(
                "yaml.marshal: cannot convert input object to yaml - {:?}",
                e
            )
        })?;

        // marshal from yaml to string
        let res = serde_yaml::to_string(&value)
            .map_err(|e| anyhow!("yaml.marshal: marshal error - {:?}", e))?;

        serde_json::to_value(res)
            .map_err(|e| anyhow!("yaml.marshal: cannot convert result into JSON: {:?}", e))
    }

    pub fn unmarshal(args: &[serde_json::Value]) -> Result<serde_json::Value> {
        if args.len() != 1 {
            return Err(anyhow!("yaml.unmarshal: wrong number of arguments"));
        }

        let input = args[0]
            .as_str()
            .ok_or_else(|| anyhow!("yaml.unmarshal: 1st parameter is not a string"))?;

        let res: serde_json::Value = serde_yaml::from_str(input).map_err(|e| {
            anyhow!(
                "yaml.unmarshal: cannot convert input object to json - {:?}",
                e
            )
        })?;

        serde_json::to_value(res)
            .map_err(|e| anyhow!("yaml.unmarshal: cannot convert result into JSON: {:?}", e))
    }

    #[cfg(test)]
    mod test {
        use super::*;
        use assert_json_diff::assert_json_eq;
        use serde_json::json;

        #[test]
        fn test_marshal() {
            let input = json!({
                "hello": "world",
                "number": 42,
                "list": [1,2,3]
            });

            let args: Vec<serde_json::Value> = vec![json!(input)];
            let actual = marshal(&args);
            assert!(actual.is_ok());

            let expected = r#"---
hello: world
number: 42
list:
  - 1
  - 2
  - 3
"#;

            let actual = actual.unwrap();
            assert_json_eq!(json!(expected), actual);
        }

        #[test]
        fn test_unmarshal() {
            let input_str = r#"---
hello: world
list:
  - 1
  - 2
  - 3
number: 42
"#;

            let input = json!(input_str);

            let expected = json!({
                "hello": "world",
                "number": 42,
                "list": [1,2,3]
            });

            let args: Vec<serde_json::Value> = vec![json!(input)];
            let actual = unmarshal(&args);
            assert!(actual.is_ok());

            let actual = actual.unwrap();
            assert_json_eq!(json!(expected), actual);
        }
    }
}

pub mod hex {
    use anyhow::{anyhow, Result};
    use core::num;

    pub fn encode(args: &[serde_json::Value]) -> Result<serde_json::Value> {
        if args.len() != 1 {
            return Err(anyhow!("hex.encode: wrong number of arguments"));
        }

        let input = args[0]
            .as_str()
            .ok_or_else(|| anyhow!("hex.encode: 1st parameter is not a string"))?;

        let res: Vec<String> = input
            .as_bytes()
            .iter()
            .map(|v| format!("{:x?}", v))
            .collect();
        let res = res.join("");

        serde_json::to_value(res)
            .map_err(|e| anyhow!("hex.encode: cannot convert value into JSON: {:?}", e))
    }

    pub fn decode(args: &[serde_json::Value]) -> Result<serde_json::Value> {
        if args.len() != 1 {
            return Err(anyhow!("hex.decode: wrong number of arguments"));
        }

        let input = args[0]
            .as_str()
            .ok_or_else(|| anyhow!("hex.decode: 1st parameter is not a string"))?;

        let value: std::result::Result<Vec<u8>, num::ParseIntError> = (0..input.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&input[i..i + 2], 16))
            .collect();
        let value = value.map_err(|e| anyhow!("hex.decode: cannot parse input - {:?}", e))?;

        let res = String::from_utf8(value)
            .map_err(|e| anyhow!("hex.decode: cannot parse string - {:?}", e))?;

        serde_json::to_value(res)
            .map_err(|e| anyhow!("hex.decode: cannot convert value into JSON: {:?}", e))
    }

    #[cfg(test)]
    mod test {
        use super::*;
        use serde_json::json;

        #[test]
        fn test_encode() {
            let input = "hello";

            let args: Vec<serde_json::Value> = vec![json!(input)];
            let actual = encode(&args);

            assert!(actual.is_ok());
            assert_eq!(json!("68656c6c6f"), actual.unwrap());
        }

        #[test]
        fn test_decode() {
            let input = "68656c6c6f";

            let args: Vec<serde_json::Value> = vec![json!(input)];
            let actual = decode(&args);

            assert!(actual.is_ok());
            assert_eq!(json!("hello"), actual.unwrap());
        }
    }
}
