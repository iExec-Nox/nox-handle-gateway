use alloy_primitives::hex;

pub fn serialize_bytes(bytes: &[u8]) -> String {
    format!("0x{}", hex::encode(bytes))
}

pub fn strip_0x_prefix(s: &str) -> &str {
    s.strip_prefix("0x").unwrap_or(s)
}
