use anyhow::anyhow;

pub(crate) struct AdmissionReview {
    pub request: String,
    pub uid: String,
}

impl AdmissionReview {
    pub(crate) fn new(raw: hyper::body::Bytes) -> Result<AdmissionReview, anyhow::Error> {
        let obj: serde_json::Value = match serde_json::from_slice(&raw) {
            Ok(obj) => obj,
            Err(e) => return Err(anyhow!("Error parsing request: {:?}", e)),
        };

        let req = match obj.get("request") {
            Some(req) => req,
            None => return Err(anyhow!("Cannot parse AdmissionReview: 'request' not found")),
        };

        let request = serde_json::to_string(req)?;
        let uid = match req.get("uid") {
            Some(uid) => uid.as_str().unwrap().to_string(),
            None => return Err(anyhow!("Cannot parse AdmissionReview: 'uid' not found")),
        };

        Ok(AdmissionReview {
            request: request,
            uid: uid,
        })
    }
}
