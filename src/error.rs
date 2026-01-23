use axum::{
    Json,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use serde_json::json;
use thiserror::Error;

use crate::crypto;
use crate::kms;

#[derive(Debug, Error)]
pub enum AppError {
    #[error("Cryptographic error: {0}")]
    CryptoError(#[from] crypto::Error),
    #[error("Invalid type: {0}")]
    InvalidType(String),
    #[error("Invalid value: {0}")]
    InvalidValue(String),
    #[error("KMS error: {0}")]
    KmsError(#[from] kms::Error),
    #[error("Database error: {0}")]
    RepositoryError(#[from] sqlx::error::Error),
    #[error("Signing error: {0}")]
    SigningError(String),
}

impl AppError {
    fn error_code(&self) -> &'static str {
        match self {
            AppError::CryptoError(_) => "crypto",
            AppError::InvalidType(_) => "invalid_type",
            AppError::InvalidValue(_) => "invalid_value",
            AppError::KmsError(_) => "kms",
            AppError::RepositoryError(_) => "repository",
            AppError::SigningError(_) => "signing",
        }
    }

    fn status_code(&self) -> StatusCode {
        match self {
            AppError::CryptoError(_) => StatusCode::INTERNAL_SERVER_ERROR,
            AppError::InvalidType(_) => StatusCode::BAD_REQUEST,
            AppError::InvalidValue(_) => StatusCode::BAD_REQUEST,
            AppError::KmsError(e) => match e {
                kms::Error::Unavailable(_) => StatusCode::SERVICE_UNAVAILABLE,
                kms::Error::InvalidResponse(_) => StatusCode::BAD_REQUEST,
                kms::Error::InvalidKey(_) => StatusCode::INTERNAL_SERVER_ERROR,
                kms::Error::ClientBuild(_) => StatusCode::INTERNAL_SERVER_ERROR,
            },
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
