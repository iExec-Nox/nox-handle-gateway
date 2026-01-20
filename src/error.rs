use axum::{
    Json,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use serde_json::json;
use thiserror::Error;

use crate::crypto;

#[derive(Debug, Error)]
pub enum AppError {
    #[error("Cryptographic error: {0}")]
    CryptoError(#[from] crypto::Error),
    #[error("Encryption error: {0}")]
    EncryptionError(String),
    #[error("Invalid type: {0}")]
    InvalidType(String),
    #[error("Invalid KMS public key: {0}")]
    KmsInvalidKey(String),
    #[error("Invalid KMS response: {0}")]
    KmsInvalidResponse(String),
    #[error("KMS unavailable: {0}")]
    KmsUnavailable(String),
    #[error("{0}")]
    RepositoryError(#[from] sqlx::error::Error),
    #[error("Signing error: {0}")]
    SigningError(String),
}

impl AppError {
    fn error_code(&self) -> &'static str {
        match self {
            AppError::CryptoError(_) => "crypto_error",
            AppError::EncryptionError(_) => "encryption_error",
            AppError::InvalidType(_) => "invalid_type",
            AppError::KmsInvalidKey(_) => "kms_invalid_key",
            AppError::KmsInvalidResponse(_) => "kms_invalid_response",
            AppError::KmsUnavailable(_) => "kms_unavailable",
            AppError::RepositoryError(_) => "repository",
            AppError::SigningError(_) => "signing_error",
        }
    }

    fn status_code(&self) -> StatusCode {
        match self {
            AppError::CryptoError(_) => StatusCode::INTERNAL_SERVER_ERROR,
            AppError::EncryptionError(_) => StatusCode::INTERNAL_SERVER_ERROR,
            AppError::InvalidType(_) => StatusCode::BAD_REQUEST,
            AppError::KmsInvalidKey(_) => StatusCode::INTERNAL_SERVER_ERROR,
            AppError::KmsInvalidResponse(_) => StatusCode::BAD_REQUEST,
            AppError::KmsUnavailable(_) => StatusCode::SERVICE_UNAVAILABLE,
            AppError::RepositoryError(_) => StatusCode::INTERNAL_SERVER_ERROR,
            AppError::SigningError(_) => StatusCode::INTERNAL_SERVER_ERROR,
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
