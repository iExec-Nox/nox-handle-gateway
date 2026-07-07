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
    #[error("Unauthorized: {0}")]
    Unauthorized(String),
    #[error("chain_id {0} not configured")]
    UnknownChain(u32),
}

impl AppError {
    /// Returns the HTTP status, machine-readable error code, and the message
    /// safe to return to any caller for this error, in one place.
    ///
    /// Variants wrapping a foreign error type (KMS/RPC clients, crypto primitives,
    /// storage, the gateway's own EIP-712 signer) can carry upstream URLs, revert
    /// reasons, or padding/internal details in their `Display` output. Those are
    /// only ever logged (via `Debug`, in [`AppError::log`]) and never forwarded
    /// here. Every other variant is already built from safe, caller-relevant
    /// text (handle IDs, chain IDs, parse failures).
    pub(crate) fn parts(&self) -> (StatusCode, &'static str, String) {
        match self {
            AppError::AccessDenied(_) => (StatusCode::FORBIDDEN, "access_denied", self.to_string()),
            AppError::BadRequest(_) => (StatusCode::BAD_REQUEST, "bad_request", self.to_string()),
            AppError::BatchTooLarge { .. } => {
                (StatusCode::BAD_REQUEST, "batch_too_large", self.to_string())
            }
            AppError::Conflict(_) => (StatusCode::CONFLICT, "conflict", self.to_string()),
            AppError::CryptoError(_) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "crypto",
                "decryption delegation failed".to_string(),
            ),
            AppError::InvalidSolidityType(_) => {
                (StatusCode::BAD_REQUEST, "invalid_type", self.to_string())
            }
            AppError::InvalidSolidityValue(_) => {
                (StatusCode::BAD_REQUEST, "invalid_value", self.to_string())
            }
            AppError::KmsError(e) => (
                match e {
                    kms::Error::Unavailable(_) => StatusCode::SERVICE_UNAVAILABLE,
                    _ => StatusCode::INTERNAL_SERVER_ERROR,
                },
                "kms",
                "kms unavailable".to_string(),
            ),
            AppError::NotFound(_) => (StatusCode::NOT_FOUND, "not_found", self.to_string()),
            AppError::OperandsNotPrepared => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "operands",
                self.to_string(),
            ),
            AppError::RpcError(_) => (
                StatusCode::SERVICE_UNAVAILABLE,
                "rpc",
                "rpc call failed".to_string(),
            ),
            AppError::SigningError(_) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "signing",
                "signing failed".to_string(),
            ),
            AppError::StorageError(_) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "storage",
                "storage error".to_string(),
            ),
            AppError::Unauthorized(_) => {
                (StatusCode::UNAUTHORIZED, "unauthorized", self.to_string())
            }
            AppError::UnknownChain(_) => {
                (StatusCode::BAD_REQUEST, "unknown_chain", self.to_string())
            }
        }
    }

    /// Logs this error at a severity derived from its HTTP status.
    pub(crate) fn log(&self) {
        if self.parts().0.is_server_error() {
            error!(error = ?self, "request failed");
        } else {
            debug!(error = ?self, "request rejected");
        }
    }

    /// Builds the plain, unsigned JSON error body.
    ///
    /// Used directly for errors raised before a request's `chain_id` has
    /// resolved to a configured Handle Gateway signer (there is no key to
    /// authenticate the response with yet), and as a fallback if signing an
    /// otherwise-signable error fails.
    pub(crate) fn to_plain_response(&self) -> Response {
        let (status, code, message) = self.parts();
        let body = Json(json!({
            "error": code,
            "message": message
        }));
        (status, body).into_response()
    }
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        self.log();
        self.to_plain_response()
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
        let (_, _, message) = err.parts();
        assert_eq!(message, "kms unavailable");
        assert!(!message.contains("leaked kms endpoint detail"));
    }

    #[test]
    fn rpc_error_does_not_leak_internal_detail() {
        let err = AppError::RpcError(rpc::RpcError::ProviderError(
            "leaked rpc url detail".to_string(),
        ));
        let (_, _, message) = err.parts();
        assert_eq!(message, "rpc call failed");
        assert!(!message.contains("leaked rpc url detail"));
    }

    #[test]
    fn crypto_error_does_not_leak_internal_detail() {
        let err = AppError::CryptoError(crypto::Error::EciesDecryptionError(
            "leaked padding detail".to_string(),
        ));
        let (_, _, message) = err.parts();
        assert_eq!(message, "decryption delegation failed");
        assert!(!message.contains("leaked padding detail"));
    }

    #[test]
    fn storage_error_does_not_leak_internal_detail() {
        let err = AppError::StorageError(repository::RepositoryError::InvalidHandle {
            reason: "leaked storage detail".to_string(),
        });
        let (_, _, message) = err.parts();
        assert_eq!(message, "storage error");
        assert!(!message.contains("leaked storage detail"));
    }

    #[test]
    fn signing_error_does_not_leak_internal_detail() {
        let err = AppError::SigningError("leaked signer detail".to_string());
        let (_, _, message) = err.parts();
        assert_eq!(message, "signing failed");
        assert!(!message.contains("leaked signer detail"));
    }

    #[test]
    fn client_facing_variants_keep_their_message() {
        let err = AppError::NotFound("0xabc123".to_string());
        let (_, _, message) = err.parts();
        assert_eq!(message, err.to_string());
    }
}
