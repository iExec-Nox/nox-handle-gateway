use axum::{
    Json,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use serde_json::json;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum AppError {
    #[error("Invalid type: {0}")]
    InvalidType(String),
}

impl AppError {
    fn error_code(&self) -> &'static str {
        match self {
            AppError::InvalidType(_) => "invalid_type",
        }
    }
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let status = StatusCode::BAD_REQUEST;
        let body = Json(json!({
            "error": self.error_code(),
            "message": self.to_string()
        }));
        (status, body).into_response()
    }
}
