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
    #[error("Access denied: {0}")]
    AccessDenied(String),
    #[error("Bad request: {0}")]
    BadRequest(String),
    #[error("Batch too large: received {received}, limit {limit}")]
    BatchTooLarge { received: usize, limit: usize },
    #[error("Conflict: {0}")]
    Conflict(String),
    #[error("Cryptographic error: {0}")]
    CryptoError(#[from] crypto::Error),
    #[error("Invalid Solidity type: {0}")]
    InvalidSolidityType(String),
    #[error("Invalid Solidity value: {0}")]
    InvalidSolidityValue(String),
    #[error("KMS error: {0}")]
    KmsError(#[from] kms::Error),
    #[error("Not found: {0}")]
    NotFound(String),
    #[error("Operands not prepared for computation")]
    OperandsNotPrepared,
    #[error("RPC error: {0}")]
    RpcError(#[from] rpc::RpcError),
    #[error("Signing error: {0}")]
    SigningError(String),
    #[error("Storage error: {0}")]
    StorageError(#[from] repository::RepositoryError),
    #[error("Unauthorized: {0}")]
    Unauthorized(String),
    #[error("chain_id {0} not configured")]
    UnknownChain(u32),
}

impl AppError {
    fn error_code(&self) -> &'static str {
        match self {
            AppError::AccessDenied(_) => "access_denied",
            AppError::BadRequest(_) => "bad_request",
            AppError::BatchTooLarge { .. } => "batch_too_large",
            AppError::Conflict(_) => "conflict",
            AppError::CryptoError(_) => "crypto",
            AppError::InvalidSolidityType(_) => "invalid_type",
            AppError::InvalidSolidityValue(_) => "invalid_value",
            AppError::KmsError(_) => "kms",
            AppError::NotFound(_) => "not_found",
            AppError::OperandsNotPrepared => "operands",
            AppError::RpcError(_) => "rpc",
            AppError::SigningError(_) => "signing",
            AppError::StorageError(_) => "storage",
            AppError::Unauthorized(_) => "unauthorized",
            AppError::UnknownChain(_) => "unknown_chain",
        }
    }

    fn status_code(&self) -> StatusCode {
        match self {
            AppError::AccessDenied(_) => StatusCode::FORBIDDEN,
            AppError::BadRequest(_) => StatusCode::BAD_REQUEST,
            AppError::BatchTooLarge { .. } => StatusCode::BAD_REQUEST,
            AppError::Conflict(_) => StatusCode::CONFLICT,
            AppError::CryptoError(_) => StatusCode::INTERNAL_SERVER_ERROR,
            AppError::InvalidSolidityType(_) => StatusCode::BAD_REQUEST,
            AppError::InvalidSolidityValue(_) => StatusCode::BAD_REQUEST,
            AppError::KmsError(e) => match e {
                kms::Error::Unavailable(_) => StatusCode::SERVICE_UNAVAILABLE,
                _ => StatusCode::INTERNAL_SERVER_ERROR,
            },
            AppError::NotFound(_) => StatusCode::NOT_FOUND,
            AppError::OperandsNotPrepared => StatusCode::INTERNAL_SERVER_ERROR,
            AppError::RpcError(_) => StatusCode::SERVICE_UNAVAILABLE,
            AppError::SigningError(_) => StatusCode::INTERNAL_SERVER_ERROR,
            AppError::StorageError(_) => StatusCode::INTERNAL_SERVER_ERROR,
            AppError::Unauthorized(_) => StatusCode::UNAUTHORIZED,
            AppError::UnknownChain(_) => StatusCode::BAD_REQUEST,
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
