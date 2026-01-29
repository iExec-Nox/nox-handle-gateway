use alloy_primitives::{Address, hex};
use alloy_sol_types::sol;
use serde::{Deserialize, Serialize, Serializer};
use sha3::{Digest, Keccak256};
use std::str::FromStr;

use crate::error::AppError;

const HANDLE_VERSION: u8 = 0x00; // V0
pub const EIP_712_DOMAIN_VERSION: &str = "1";
pub const KMS_PUBLIC_KEY_EIP712_DOMAIN_NAME: &str = "ProtocolPublicKey";
pub const PROTOCOL_DELEGATE_EIP712_DOMAIN_NAME: &str = "ProtocolDelegate";

/// Value type for encrypted data
///
/// Encoding (byte 30 of handle):
/// - 0-3: Special types (bool, address, bytes, string)
/// - 4-35: uint8..uint256 (32 types)
/// - 36-67: int8..int256 (32 types)
/// - 68-99: bytes1..bytes32 (32 types)
/// - 100-255: Reserved
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

// TODO: remove this if serialization is still unused for SolidityType
impl Serialize for SolidityType {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let s = match self {
            SolidityType::Bool => "bool".to_string(),
            SolidityType::Address => "address".to_string(),
            SolidityType::Bytes => "bytes".to_string(),
            SolidityType::String => "string".to_string(),
            SolidityType::Uint(bits) => format!("uint{bits}"),
            SolidityType::Int(bits) => format!("int{bits}"),
            SolidityType::FixedBytes(size) => format!("bytes{size}"),
        };
        serializer.serialize_str(&s)
    }
}

impl<'de> Deserialize<'de> for SolidityType {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        SolidityType::from_str(&s).map_err(|e| serde::de::Error::custom(e.to_string()))
    }
}

/// 32-byte handle
///
/// Layout:
/// - [0-25]  prehandle: keccak256(ciphertext, acl_contract)[0..26]
/// - [26-29] chain_id (big-endian)
/// - [30]    solidity_type
/// - [31]    version
#[derive(Debug)]
pub struct Handle {
    pub prehandle: [u8; 26],
    pub chain_id: [u8; 4],
    pub solidity_type: u8,
    pub version: u8,
}

impl Handle {
    pub fn new(
        ciphertext: &[u8],
        acl_contract: Address,
        chain_id: u32,
        solidity_type: SolidityType,
    ) -> Self {
        // prehandle
        let mut hasher = Keccak256::default();
        hasher.update(ciphertext);
        hasher.update(acl_contract.as_slice());
        let hash = hasher.finalize();

        let mut prehandle = [0u8; 26];
        prehandle.copy_from_slice(&hash[0..26]);

        // chain_id
        let chain_id = chain_id.to_be_bytes();

        // solidity_type
        let solidity_type = solidity_type.to_byte();

        // version
        let version = HANDLE_VERSION;

        Handle {
            prehandle,
            chain_id,
            solidity_type,
            version,
        }
    }

    pub fn to_bytes(&self) -> [u8; 32] {
        let mut bytes = [0u8; 32];
        bytes[0..26].copy_from_slice(&self.prehandle);
        bytes[26..30].copy_from_slice(&self.chain_id);
        bytes[30] = self.solidity_type;
        bytes[31] = self.version;
        bytes
    }
}

sol! {
    #[derive(Debug)]
    struct HandleProof {
        bytes32 handle;
        address owner;
        address acl;
        uint256 createdAt;
    }

    #[derive(Debug, Deserialize)]
    struct DataAccessAuthorization {
        address userAddress;
        string encryptionPubKey;
        uint256 notBefore;
        uint256 expiresAt;
    }

    #[derive(Debug)]
    struct PublicKeyProof {
        string publicKey;
    }

    #[derive(Debug)]
    struct DelegateAuthorization {
        string ephemeralPubKey;
        string targetPubKey;
    }
}

impl HandleProof {
    /// Create a new 137 bytes HandleProof for EIP-712 signing.
    ///
    /// Layout:
    /// - [0-19]   owner (20 bytes)
    /// - [20-39]  acl (20 bytes)
    /// - [40-71]  createdAt (uint256 BE)
    /// - [72-136] signature (r: 32 + s: 32 + v: 1)
    pub fn to_serialized_bytes(&self, signature: [u8; 65]) -> String {
        let mut bytes = [0u8; 137];
        bytes[0..20].copy_from_slice(self.owner.as_slice());
        bytes[20..40].copy_from_slice(self.acl.as_slice());
        bytes[40..72].copy_from_slice(&self.createdAt.to_be_bytes::<32>());
        bytes[72..137].copy_from_slice(&signature);
        serialize_bytes(&bytes)
    }
}

pub fn serialize_bytes(bytes: &[u8]) -> String {
    format!("0x{}", hex::encode(bytes))
}

pub fn strip_0x_prefix(s: &str) -> &str {
    s.strip_prefix("0x").unwrap_or(s)
}
