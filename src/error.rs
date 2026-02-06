use axum::{
    Json,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use serde_json::json;
use thiserror::Error;

use crate::acl;
use crate::crypto;
use crate::kms;

#[derive(Debug, Error)]
pub enum AppError {
    #[error("ACL error: {0}")]
    AclError(#[from] acl::AclError),
    #[error("Bad request: {0}")]
    BadRequest(String),
    #[error("Cryptographic error: {0}")]
    CryptoError(#[from] crypto::Error),
    #[error("Some handle already exists and should not")]
    HandleConflict,
    #[error("Expected handle not found")]
    HandleNotFound,
    #[error("Handle not prepared for computation")]
    HandleNotPrepared,
    #[error("Invalid Solidity type: {0}")]
    InvalidSolidityType(String),
    #[error("Invalid Solidity value: {0}")]
    InvalidSolidityValue(String),
    #[error("KMS error: {0}")]
    KmsError(#[from] kms::Error),
    #[error("Database error: {0}")]
    RepositoryError(#[from] sqlx::error::Error),
    #[error("Signing error: {0}")]
    SigningError(String),
    #[error("Unauthorized: {0}")]
    Unauthorized(String),
}

impl AppError {
    fn error_code(&self) -> &'static str {
        match self {
            AppError::AclError(_) => "acl",
            AppError::BadRequest(_) => "bad_request",
            AppError::CryptoError(_) => "crypto",
            AppError::HandleConflict => "handle",
            AppError::HandleNotFound => "hadle",
            AppError::HandleNotPrepared => "handle",
            AppError::InvalidSolidityType(_) => "invalid_type",
            AppError::InvalidSolidityValue(_) => "invalid_value",
            AppError::KmsError(_) => "kms",
            AppError::RepositoryError(_) => "repository",
            AppError::SigningError(_) => "signing",
            AppError::Unauthorized(_) => "unauthorized",
        }
    }

    fn status_code(&self) -> StatusCode {
        match self {
            AppError::AclError(e) => match e {
                acl::AclError::AccessDenied => StatusCode::FORBIDDEN,
                _ => StatusCode::SERVICE_UNAVAILABLE,
            },
            AppError::BadRequest(_) => StatusCode::BAD_REQUEST,
            AppError::CryptoError(_) => StatusCode::INTERNAL_SERVER_ERROR,
            AppError::HandleConflict | AppError::HandleNotFound => StatusCode::BAD_REQUEST,
            AppError::HandleNotPrepared => StatusCode::INTERNAL_SERVER_ERROR,
            AppError::InvalidSolidityType(_) => StatusCode::BAD_REQUEST,
            AppError::InvalidSolidityValue(_) => StatusCode::BAD_REQUEST,
            AppError::KmsError(e) => match e {
                kms::Error::Unavailable(_) => StatusCode::SERVICE_UNAVAILABLE,
                kms::Error::InvalidResponse(_) => StatusCode::BAD_REQUEST,
                _ => StatusCode::INTERNAL_SERVER_ERROR,
            },
            AppError::RepositoryError(_) => StatusCode::INTERNAL_SERVER_ERROR,
            AppError::SigningError(_) => StatusCode::INTERNAL_SERVER_ERROR,
            AppError::Unauthorized(_) => StatusCode::UNAUTHORIZED,
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
