use alloy_primitives::hex;

use crate::error::AppError;
use crate::types::SolidityType;

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
    let trimmed = value.strip_prefix("0x").unwrap_or(value);

    if trimmed.is_empty() {
        return Err(AppError::InvalidValue("empty hex value".to_string()));
    }

    let len = trimmed.len();
    let normalized = if len % 2 == 1 {
        if len == 1 {
            format!("0{trimmed}")
        } else {
            return Err(AppError::InvalidValue(
                "hex length must be even".to_string(),
            ));
        }
    } else {
        trimmed.to_string()
    };

    hex::decode(normalized).map_err(|e| AppError::InvalidValue(format!("invalid hex: {e}")))
}

/// Validate byte count matches expected size for type.
fn validate_size(bytes: &[u8], solidity_type: &SolidityType) -> Result<(), AppError> {
    let len = bytes.len();

    match solidity_type {
        SolidityType::Bool => {
            if len != 1 {
                return Err(AppError::InvalidValue(format!(
                    "bool must be 1 byte, got {len}"
                )));
            }
            if bytes[0] > 1 {
                return Err(AppError::InvalidValue(format!(
                    "bool must be 0x00 or 0x01, got 0x{:02x}",
                    bytes[0]
                )));
            }
        }
        SolidityType::Address => {
            if len != 20 {
                return Err(AppError::InvalidValue(format!(
                    "address must be 20 bytes, got {len}"
                )));
            }
        }
        SolidityType::Uint(bits) => {
            let max_bytes = (*bits / 8) as usize;
            if len > max_bytes {
                return Err(AppError::InvalidValue(format!(
                    "uint{bits} must be <= {max_bytes} bytes, got {len}"
                )));
            }
        }
        SolidityType::Int(bits) => {
            let expected = (*bits / 8) as usize;
            if len != expected {
                return Err(AppError::InvalidValue(format!(
                    "int{bits} must be exactly {expected} bytes, got {len}"
                )));
            }
        }
        SolidityType::FixedBytes(size) => {
            let expected = *size as usize;
            if len != expected {
                return Err(AppError::InvalidValue(format!(
                    "bytes{size} must be exactly {expected} bytes, got {len}"
                )));
            }
        }
        SolidityType::Bytes | SolidityType::String => {}
    }

    Ok(())
}
