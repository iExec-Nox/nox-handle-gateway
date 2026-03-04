use alloy_primitives::hex;

use crate::error::AppError;
use crate::types::SolidityType;
use crate::utils::strip_0x_prefix;

/// Decode hex value and validate size matches type.
pub fn decode_and_validate_value(
    value: &str,
    solidity_type: &SolidityType,
) -> Result<Vec<u8>, AppError> {
    let bytes = decode_hex(value)?;
    validate_size(&bytes, solidity_type)?;
    Ok(bytes)
}

/// Decode hex string (with or without 0x prefix).
fn decode_hex(value: &str) -> Result<Vec<u8>, AppError> {
    let trimmed = strip_0x_prefix(value);

    if trimmed.is_empty() {
        return Err(AppError::InvalidSolidityValue(
            "empty hex value".to_string(),
        ));
    }

    if !trimmed.len().is_multiple_of(2) {
        return Err(AppError::InvalidSolidityValue(
            "hex length must be even".to_string(),
        ));
    }

    hex::decode(trimmed).map_err(|e| AppError::InvalidSolidityValue(format!("invalid hex: {e}")))
}

/// Validate byte count matches expected size for type.
fn validate_size(bytes: &[u8], solidity_type: &SolidityType) -> Result<(), AppError> {
    let len = bytes.len();

    match solidity_type {
        SolidityType::Bool => {
            if len != 1 {
                return Err(AppError::InvalidSolidityValue(format!(
                    "bool must be 1 byte, got {len}"
                )));
            }
            if bytes[0] > 1 {
                return Err(AppError::InvalidSolidityValue(format!(
                    "bool must be 0x00 or 0x01, got 0x{:02x}",
                    bytes[0]
                )));
            }
        }
        SolidityType::Address => {
            if len != 20 {
                return Err(AppError::InvalidSolidityValue(format!(
                    "address must be 20 bytes, got {len}"
                )));
            }
        }
        SolidityType::Uint(bits) => {
            let max_bytes = (*bits / 8) as usize;
            if len > max_bytes {
                return Err(AppError::InvalidSolidityValue(format!(
                    "uint{bits} must be <= {max_bytes} bytes, got {len}"
                )));
            }
        }
        SolidityType::Int(bits) => {
            let max_bytes = (*bits / 8) as usize;
            if len > max_bytes {
                return Err(AppError::InvalidSolidityValue(format!(
                    "int{bits} must be <= {max_bytes} bytes, got {len}"
                )));
            }
        }
        SolidityType::FixedBytes(size) => {
            let expected = *size as usize;
            if len != expected {
                return Err(AppError::InvalidSolidityValue(format!(
                    "bytes{size} must be exactly {expected} bytes, got {len}"
                )));
            }
        }
        SolidityType::Bytes | SolidityType::String => {}
    }

    Ok(())
}
