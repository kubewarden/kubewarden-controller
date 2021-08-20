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
            .ok_or(anyhow!("urlquery.encode: internal error 2"))?;
        let res = res
            .strip_prefix("input=")
            .ok_or(anyhow!("urlquery.encode: internal error 3"))?;

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

        let pairs = url.query_pairs();
        if pairs.count() != 1 {
            return Err(anyhow!("urlquery.decode: internal error 2"));
        }
        for (_, value) in pairs {
            return serde_json::to_value(&value)
                .map_err(|e| anyhow!("urlquery.decode: Cannot convert value into JSON: {:?}", e));
        }

        Err(anyhow!("urlquery.decode: unreachable!"))
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
            .ok_or(anyhow!("urlquery.encode_object: internal error 2"))?;

        serde_json::to_value(res).map_err(|e| {
            anyhow!(
                "urlquery.encode_object: Cannot convert value into JSON: {:?}",
                e
            )
        })
    }

    #[cfg(test)]
    mod test {
        use super::*;
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

            assert_eq!(
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
    }
}
