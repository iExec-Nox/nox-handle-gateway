use axum::{
    Json,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use serde_json::json;
use thiserror::Error;

use crate::crypto;
use crate::kms;
use crate::repository;
use crate::rpc;

#[derive(Debug, Error)]
pub enum AppError {
    #[error("Bad request: {0}")]
    BadRequest(String),
    #[error("Cryptographic error: {0}")]
    CryptoError(#[from] crypto::Error),
    #[error("Invalid Solidity type: {0}")]
    InvalidSolidityType(String),
    #[error("Invalid Solidity value: {0}")]
    InvalidSolidityValue(String),
    #[error("KMS error: {0}")]
    KmsError(#[from] kms::Error),
    #[error("Operands not prepared for computation")]
    OperandsNotPrepared,
    #[error("RPC error: {0}")]
    RpcError(#[from] rpc::RpcError),
    #[error("Signing error: {0}")]
    SigningError(String),
    #[error("Storage error: {0}")]
    StorageError(#[from] repository::S3Error),
    #[error("Unauthorized: {0}")]
    Unauthorized(String),
}

impl AppError {
    fn error_code(&self) -> &'static str {
        match self {
            AppError::BadRequest(_) => "bad_request",
            AppError::CryptoError(_) => "crypto",
            AppError::InvalidSolidityType(_) => "invalid_type",
            AppError::InvalidSolidityValue(_) => "invalid_value",
            AppError::KmsError(_) => "kms",
            AppError::OperandsNotPrepared => "operands",
            AppError::RpcError(_) => "rpc",
            AppError::SigningError(_) => "signing",
            AppError::StorageError(_) => "storage",
            AppError::Unauthorized(_) => "unauthorized",
        }
    }

    fn status_code(&self) -> StatusCode {
        match self {
            AppError::BadRequest(_) => StatusCode::BAD_REQUEST,
            AppError::CryptoError(_) => StatusCode::INTERNAL_SERVER_ERROR,
            AppError::InvalidSolidityType(_) => StatusCode::BAD_REQUEST,
            AppError::InvalidSolidityValue(_) => StatusCode::BAD_REQUEST,
            AppError::KmsError(e) => match e {
                kms::Error::InvalidResponse(_) => StatusCode::BAD_REQUEST,
                kms::Error::Unavailable(_) => StatusCode::SERVICE_UNAVAILABLE,
                _ => StatusCode::INTERNAL_SERVER_ERROR,
            },
            AppError::OperandsNotPrepared => StatusCode::INTERNAL_SERVER_ERROR,
            AppError::RpcError(e) => match e {
                rpc::RpcError::AccessDenied => StatusCode::FORBIDDEN,
                rpc::RpcError::InvalidSignature(_)
                | rpc::RpcError::SmartWalletSignatureNotVerified(_) => StatusCode::UNAUTHORIZED,
                _ => StatusCode::SERVICE_UNAVAILABLE,
            },
            AppError::SigningError(_) => StatusCode::INTERNAL_SERVER_ERROR,
            AppError::StorageError(e) => match e {
                repository::S3Error::AlreadyExists { .. } => StatusCode::CONFLICT,
                repository::S3Error::InvalidHandle { .. } => StatusCode::BAD_REQUEST,
                repository::S3Error::NotFound { .. } => StatusCode::NOT_FOUND,
                repository::S3Error::UnknownChain { .. } => StatusCode::BAD_REQUEST,
                _ => StatusCode::INTERNAL_SERVER_ERROR,
            },
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
