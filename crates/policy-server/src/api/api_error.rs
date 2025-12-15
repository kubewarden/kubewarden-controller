use axum::{extract::rejection::JsonRejection, http::StatusCode, response::IntoResponse};
use serde_json::json;

#[derive(Debug)]
/// An error that can be returned by the API
/// and will be converted into a JSON response.
pub(crate) struct ApiError {
    pub(crate) status: StatusCode,
    pub(crate) message: String,
}

impl From<JsonRejection> for ApiError {
    fn from(rejection: JsonRejection) -> Self {
        Self {
            status: rejection.status(),
            message: rejection.body_text(),
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> axum::response::Response {
        let payload = json!({
            "message": self.message,
            "status": self.status.as_u16(),
        });

        (self.status, axum::Json(payload)).into_response()
    }
}
