use std::str::FromStr;

use alloy_primitives::hex;
use alloy_sol_types::sol;
use k256::elliptic_curve::rand_core::{OsRng, RngCore};
use serde::Deserialize;

use crate::error::AppError;

/// Current handle version encoded in byte 0.
const HANDLE_VERSION: u8 = 0x00; // V0
/// Handle attribute: handle is guaranteed unique on this chain.
///
/// All gateway-created handles carry this flag because the prehandle is
/// cryptographically random (OsRng), making collisions astronomically unlikely.
pub const ATTR_IS_UNIQUE_HANDLE: u8 = 0x01;
/// EIP-712 domain version shared across all domains in this service.
pub const EIP_712_DOMAIN_VERSION: &str = "1";
/// EIP-712 domain name used for `DelegateAuthorization` and `DelegateResponseProof`.
pub const PROTOCOL_DELEGATE_EIP712_DOMAIN_NAME: &str = "ProtocolDelegate";

/// Solidity value type for an encrypted handle.
///
/// Encoded as a single byte in position 5 of the handle:
/// - `0-3`: special types (bool, address, bytes, string)
/// - `4-35`: uint8..uint256
/// - `36-67`: int8..int256
/// - `68-99`: bytes1..bytes32
/// - `100-255`: reserved
#[derive(Debug, Clone, PartialEq)]
pub enum SolidityType {
    // Special types (0-3)
    Bool,
    Address,
    Bytes,
    String,
    // Unsigned integers (4-35)
    Uint(u16),
    // Signed integers (36-67)
    Int(u16),
    // Fixed-size bytes (68-99)
    FixedBytes(u8),
}

impl SolidityType {
    /// Returns the single-byte encoding of this type for use in a handle.
    pub fn to_byte(&self) -> u8 {
        match self {
            SolidityType::Bool => 0,
            SolidityType::Address => 1,
            SolidityType::Bytes => 2,
            SolidityType::String => 3,
            SolidityType::Uint(bits) => {
                // uint8 = 4, uint16 = 5, ..., uint256 = 35
                // Formula: 4 + (bits / 8 - 1)
                4 + (bits / 8 - 1) as u8
            }
            SolidityType::Int(bits) => {
                // int8 = 36, int16 = 37, ..., int256 = 67
                // Formula: 36 + (bits / 8 - 1)
                36 + (bits / 8 - 1) as u8
            }
            SolidityType::FixedBytes(size) => {
                // bytes1 = 68, bytes2 = 69, ..., bytes32 = 99
                // Formula: 68 + size
                67 + size
            }
        }
    }
}

impl FromStr for SolidityType {
    type Err = AppError;

    /// Parses a Solidity type string (e.g. `"uint256"`, `"bool"`, `"bytes32"`).
    ///
    /// Returns [`AppError::InvalidSolidityType`] for unknown types or
    /// out-of-range bit/byte widths.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "bool" => Ok(SolidityType::Bool),
            "address" => Ok(SolidityType::Address),
            "bytes" => Ok(SolidityType::Bytes),
            "string" => Ok(SolidityType::String),
            s if s.starts_with("uint") => {
                let bits: u16 = s[4..].parse().map_err(|_| {
                    AppError::InvalidSolidityType(format!("invalid uint size: {s}"))
                })?;
                if !(8..=256).contains(&bits) || !bits.is_multiple_of(8) {
                    return Err(AppError::InvalidSolidityType(format!(
                        "uint size must be 8-256 and multiple of 8, got {bits}"
                    )));
                }
                Ok(SolidityType::Uint(bits))
            }
            s if s.starts_with("int") => {
                let bits: u16 = s[3..]
                    .parse()
                    .map_err(|_| AppError::InvalidSolidityType(format!("invalid int size: {s}")))?;
                if !(8..=256).contains(&bits) || !bits.is_multiple_of(8) {
                    return Err(AppError::InvalidSolidityType(format!(
                        "int size must be 8-256 and multiple of 8, got {bits}"
                    )));
                }
                Ok(SolidityType::Int(bits))
            }
            s if s.starts_with("bytes") && s.len() > 5 => {
                let size: u8 = s[5..].parse().map_err(|_| {
                    AppError::InvalidSolidityType(format!("invalid bytes size: {s}"))
                })?;
                if !(1..=32).contains(&size) {
                    return Err(AppError::InvalidSolidityType(format!(
                        "bytes size must be 1-32, got {size}"
                    )));
                }
                Ok(SolidityType::FixedBytes(size))
            }
            _ => Err(AppError::InvalidSolidityType(format!("unknown type: {s}"))),
        }
    }
}

impl TryFrom<u8> for SolidityType {
    type Error = AppError;

    /// Decodes the single-byte encoding from a handle back into a [`SolidityType`].
    ///
    /// This is the inverse of [`SolidityType::to_byte`]. Returns
    /// [`AppError::BadRequest`] for bytes outside the defined ranges.
    fn try_from(byte: u8) -> Result<Self, AppError> {
        match byte {
            0 => Ok(SolidityType::Bool),
            1 => Ok(SolidityType::Address),
            2 => Ok(SolidityType::Bytes),
            3 => Ok(SolidityType::String),
            // uint8-uint256: byte = 3 + bits/8  →  bits = (byte − 3) × 8
            4..=35 => Ok(SolidityType::Uint((byte - 3) as u16 * 8)),
            // int8-int256: byte = 35 + bits/8  →  bits = (byte − 35) × 8
            36..=67 => Ok(SolidityType::Int((byte - 35) as u16 * 8)),
            // bytes1-bytes32: byte = 67 + size  →  size = byte − 67
            68..=99 => Ok(SolidityType::FixedBytes(byte - 67)),
            _ => Err(AppError::BadRequest(format!(
                "unknown SolidityType byte: {byte:#02x} = {byte}"
            ))),
        }
    }
}

impl<'de> Deserialize<'de> for SolidityType {
    /// Deserializes a `SolidityType` from its string representation.
    ///
    /// Delegates to [`FromStr`]; invalid strings produce a serde error.
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        SolidityType::from_str(&s).map_err(|e| serde::de::Error::custom(e.to_string()))
    }
}

/// 32-byte opaque handle identifying an encrypted value.
///
/// Layout:
/// - `[0]`     version (currently `0x00`)
/// - `[1-4]`   chain_id (big-endian u32)
/// - `[5]`     solidity_type byte (see [`SolidityType::to_byte`])
/// - `[6]`     attrs (see [`ATTR_IS_UNIQUE_HANDLE`])
/// - `[7-31]`  prehandle: 25 random bytes (OsRng)
#[derive(Debug)]
pub struct Handle {
    pub version: u8,
    pub chain_id: [u8; 4],
    pub solidity_type: u8,
    pub attrs: u8,
    pub prehandle: [u8; 25],
}

impl Handle {
    /// Creates a new handle with a cryptographically random prehandle.
    pub fn new(chain_id: u32, solidity_type: SolidityType) -> Self {
        let mut prehandle = [0u8; 25];
        OsRng.fill_bytes(&mut prehandle);

        Handle {
            version: HANDLE_VERSION,
            chain_id: chain_id.to_be_bytes(),
            solidity_type: solidity_type.to_byte(),
            attrs: ATTR_IS_UNIQUE_HANDLE,
            prehandle,
        }
    }

    /// Serializes the handle into its canonical 32-byte form.
    pub fn to_bytes(&self) -> [u8; 32] {
        let mut bytes = [0u8; 32];
        bytes[0] = self.version;
        bytes[1..5].copy_from_slice(&self.chain_id);
        bytes[5] = self.solidity_type;
        bytes[6] = self.attrs;
        bytes[7..32].copy_from_slice(&self.prehandle);
        bytes
    }
}

sol! {
    /// EIP-712 struct signed by the gateway to prove handle creation.
    #[derive(Debug)]
    struct HandleProof {
        bytes32 handle;
        address owner;
        address app;
        uint256 createdAt;
    }

    /// EIP-712 struct signed by the user to authorize decryption of a handle.
    #[derive(Debug, Deserialize)]
    struct DataAccessAuthorization {
        address userAddress;
        string encryptionPubKey;
        uint256 notBefore;
        uint256 expiresAt;
    }

    /// EIP-712 struct signed by the KMS to authorize key delegation.
    #[derive(Debug)]
    struct DelegateAuthorization {
        string ephemeralPubKey;
        string targetPubKey;
    }

    /// EIP-712 struct signed by the KMS over the re-encrypted shared secret.
    #[derive(Debug)]
    struct DelegateResponseProof {
        string encryptedSharedSecret;
    }

    /// EIP-712 struct signed by the gateway to certify public decryption of a handle.
    ///
    /// Signed under the NoxCompute domain (same as [`HandleProof`]).
    #[derive(Debug)]
    struct DecryptionProof {
        bytes32 handle;
        bytes decryptedResult;
    }
}

impl HandleProof {
    /// Serializes the proof to its canonical 137-byte hex-encoded form.
    ///
    /// Layout:
    /// - `[0-19]`   owner (20 bytes)
    /// - `[20-39]`  app (20 bytes)
    /// - `[40-71]`  createdAt (uint256 BE)
    /// - `[72-136]` signature (r: 32 + s: 32 + v: 1)
    pub fn to_serialized_bytes(&self, signature: [u8; 65]) -> String {
        let mut bytes = [0u8; 137];
        bytes[0..20].copy_from_slice(self.owner.as_slice());
        bytes[20..40].copy_from_slice(self.app.as_slice());
        bytes[40..72].copy_from_slice(&self.createdAt.to_be_bytes::<32>());
        bytes[72..137].copy_from_slice(&signature);
        hex::encode_prefixed(bytes)
    }
}
