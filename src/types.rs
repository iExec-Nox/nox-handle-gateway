use alloy_primitives::Address;
use serde::{Deserialize, Serialize};
use std::str::FromStr;

use crate::error::AppError;

#[derive(Debug, Deserialize)]
pub struct HandleRequest {
    pub value: serde_json::Value,
    #[serde(rename = "type")]
    pub value_type: ValueType,
    pub owner: Address,
}

#[derive(Debug, Serialize)]
pub struct HandleResponse {
    pub handle: String,
    #[serde(rename = "inputProof")]
    pub input_proof: String,
}

#[derive(Debug)]
pub enum ValueType {
    Bool,
    Uint(u16),
}

impl FromStr for ValueType {
    type Err = AppError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "bool" => Ok(ValueType::Bool),
            s if s.starts_with("uint") => {
                let bits_str = &s[4..]; // Remove "uint" prefix
                let bits: u16 = bits_str
                    .parse()
                    .map_err(|_| AppError::InvalidType(format!("Invalid uint size: {s}")))?;

                // Validate: must be multiple of 8, between 8 and 256 and not be 24
                if bits < 8 {
                    return Err(AppError::InvalidType(format!(
                        "Uint size must be at least 8 bits, got {bits}"
                    )));
                } else if bits > 256 {
                    return Err(AppError::InvalidType(format!(
                        "Uint size must be at most 256 bits, got {bits}"
                    )));
                } else if !bits.is_multiple_of(8) || bits == 24 {
                    return Err(AppError::InvalidType(format!(
                        "Uint size must be a multiple of 8 and not be 24, got {bits} bits"
                    )));
                }

                Ok(ValueType::Uint(bits))
            }
            _ => Err(AppError::InvalidType(format!("Unknown secret type: {s}"))),
        }
    }
}

impl Serialize for ValueType {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        match self {
            ValueType::Bool => serializer.serialize_str("bool"),
            ValueType::Uint(bits) => serializer.serialize_str(&format!("uint{bits}")),
        }
    }
}

impl<'de> Deserialize<'de> for ValueType {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        ValueType::from_str(&s).map_err(serde::de::Error::custom)
    }
}
