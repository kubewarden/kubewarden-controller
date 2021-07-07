use anyhow::{anyhow, Result};

#[derive(Debug, serde::Serialize)]
pub(crate) struct AdmissionReview {
    pub request: serde_json::Value,
    pub uid: String,
}

impl AdmissionReview {
    pub(crate) fn new(raw: hyper::body::Bytes) -> Result<AdmissionReview> {
        let obj: serde_json::Value = match serde_json::from_slice(&raw) {
            Ok(obj) => obj,
            Err(e) => return Err(anyhow!("Error parsing request: {:?}", e)),
        };

        let req = match obj.get("request") {
            Some(req) => req,
            None => return Err(anyhow!("Cannot parse AdmissionReview: 'request' not found")),
        };

        let uid = match req.get("uid") {
            Some(u) => u
                .as_str()
                .ok_or_else(|| anyhow!("Cannot convert uid to string")),
            None => Err(anyhow!("Cannot parse AdmissionReview: 'uid' not found")),
        }?;

        Ok(AdmissionReview {
            request: req.clone(),
            uid: String::from(uid),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hyper::body::Bytes;

    #[test]
    fn invalid_input() {
        let input = Bytes::from("this is not the JSON you're looking for");

        let res = AdmissionReview::new(input);
        assert!(res.is_err());
    }

    #[test]
    fn missing_request() {
        let input = Bytes::from(
            r#"
            { "foo": "bar" }
        "#,
        );

        let res = AdmissionReview::new(input);
        assert!(res.is_err());
    }

    #[test]
    fn missing_uid() {
        let input = Bytes::from(
            r#"
            { 
                "request": {
                    "foo": "bar"
                }
            }
        "#,
        );

        let res = AdmissionReview::new(input);
        assert!(res.is_err());
    }

    #[test]
    fn good_input() {
        let input = Bytes::from(
            r#"
            { 
                "request": {
                    "uid": "hello",
                    "foo": "bar"
                }
            }
        "#,
        );

        let res = AdmissionReview::new(input);
        assert!(!res.is_err());

        let ar = res.unwrap();
        assert_eq!(ar.uid, "hello");
    }
}
