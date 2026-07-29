use axum::{
    Json,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use serde_json::json;
use thiserror::Error;
use tracing::{debug, error};

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
    /// The request exceeded its wall-clock ceiling and was abandoned.
    ///
    /// Raised by the timeout middleware in [`crate::application`], never by a handler:
    /// the handler future is dropped, so no partial work is reported.
    #[error("Request timed out")]
    Timeout,
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
            AppError::Timeout => "timeout",
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
                // Retryable: the KMS is unreachable, or our own concurrency budget ran out.
                kms::Error::Unavailable(_) | kms::Error::Saturated(_) => {
                    StatusCode::SERVICE_UNAVAILABLE
                }
                _ => StatusCode::INTERNAL_SERVER_ERROR,
            },
            AppError::NotFound(_) => StatusCode::NOT_FOUND,
            AppError::OperandsNotPrepared => StatusCode::INTERNAL_SERVER_ERROR,
            AppError::RpcError(_) => StatusCode::SERVICE_UNAVAILABLE,
            AppError::SigningError(_) => StatusCode::INTERNAL_SERVER_ERROR,
            AppError::StorageError(_) => StatusCode::INTERNAL_SERVER_ERROR,
            AppError::Timeout => StatusCode::REQUEST_TIMEOUT,
            AppError::Unauthorized(_) => StatusCode::UNAUTHORIZED,
            AppError::UnknownChain(_) => StatusCode::BAD_REQUEST,
        }
    }

    /// Sanitized message safe to return to any caller.
    ///
    /// Variants wrapping a foreign error type (KMS/RPC clients, crypto primitives,
    /// storage, the gateway's own EIP-712 signer) can carry upstream URLs, revert
    /// reasons, or padding/internal details in their `Display` output. Those are
    /// only ever logged (via `Debug`, in [`IntoResponse::into_response`]) and never
    /// forwarded here. Every other variant is already built from safe,
    /// caller-relevant text (handle IDs, chain IDs, parse failures).
    fn public_message(&self) -> String {
        match self {
            AppError::CryptoError(_) => "decryption delegation failed".to_string(),
            AppError::KmsError(_) => "kms unavailable".to_string(),
            AppError::RpcError(_) => "rpc call failed".to_string(),
            AppError::SigningError(_) => "signing failed".to_string(),
            AppError::StorageError(_) => "storage error".to_string(),
            other => other.to_string(),
        }
    }
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let status = self.status_code();
        if status.is_server_error() {
            error!(error = ?self, "request failed");
        } else {
            debug!(error = ?self, "request rejected");
        }
        let body = Json(json!({
            "error": self.error_code(),
            "message": self.public_message()
        }));
        (status, body).into_response()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kms_error_does_not_leak_internal_detail() {
        let err = AppError::KmsError(kms::Error::InvalidResponse(
            "leaked kms endpoint detail".to_string(),
        ));
        assert_eq!(err.public_message(), "kms unavailable");
        assert!(!err.public_message().contains("leaked kms endpoint detail"));
    }

    #[test]
    fn rpc_error_does_not_leak_internal_detail() {
        let err = AppError::RpcError(rpc::RpcError::ProviderError(
            "leaked rpc url detail".to_string(),
        ));
        assert_eq!(err.public_message(), "rpc call failed");
        assert!(!err.public_message().contains("leaked rpc url detail"));
    }

    #[test]
    fn crypto_error_does_not_leak_internal_detail() {
        let err = AppError::CryptoError(crypto::Error::EciesDecryptionError(
            "leaked padding detail".to_string(),
        ));
        assert_eq!(err.public_message(), "decryption delegation failed");
        assert!(!err.public_message().contains("leaked padding detail"));
    }

    #[test]
    fn storage_error_does_not_leak_internal_detail() {
        let err = AppError::StorageError(repository::RepositoryError::InvalidHandle {
            reason: "leaked storage detail".to_string(),
        });
        assert_eq!(err.public_message(), "storage error");
        assert!(!err.public_message().contains("leaked storage detail"));
    }

    #[test]
    fn signing_error_does_not_leak_internal_detail() {
        let err = AppError::SigningError("leaked signer detail".to_string());
        assert_eq!(err.public_message(), "signing failed");
        assert!(!err.public_message().contains("leaked signer detail"));
    }

    #[test]
    fn client_facing_variants_keep_their_message() {
        let err = AppError::NotFound("0xabc123".to_string());
        assert_eq!(err.public_message(), err.to_string());
    }
}
