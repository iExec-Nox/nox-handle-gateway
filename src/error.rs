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
    #[error("Signing error: {0}")]
    SigningError(String),
    #[error("KMS unavailable: {0}")]
    KmsUnavailable(String),
    #[error("Invalid KMS public key: {0}")]
    KmsInvalidKey(String),
}

impl AppError {
    fn error_code(&self) -> &'static str {
        match self {
            AppError::InvalidType(_) => "invalid_type",
            AppError::SigningError(_) => "signing_error",
            AppError::KmsUnavailable(_) => "kms_unavailable",
            AppError::KmsInvalidKey(_) => "kms_invalid_key",
        }
    }

    fn status_code(&self) -> StatusCode {
        match self {
            AppError::InvalidType(_) => StatusCode::BAD_REQUEST,
            AppError::SigningError(_) => StatusCode::INTERNAL_SERVER_ERROR,
            AppError::KmsUnavailable(_) => StatusCode::SERVICE_UNAVAILABLE,
            AppError::KmsInvalidKey(_) => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let status = self.status_code();
        let body = Json(json!({
            "error": self.error_code(),
            "message": self.to_string()
        }));
        (status, body).into_response()
    }
}
