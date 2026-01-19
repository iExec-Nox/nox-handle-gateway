use alloy_primitives::hex;
use reqwest::Client;
use serde::Deserialize;
use tracing::debug;

use crate::error::AppError;

#[derive(Debug, Clone)]
pub struct KmsPublicKey([u8; 33]);

impl KmsPublicKey {
    pub fn from_hex(value: &str) -> Result<Self, String> {
        let trimmed = value.strip_prefix("0x").unwrap_or(value);
        let bytes = hex::decode(trimmed).map_err(|e| format!("invalid hex: {e}"))?;
        if bytes.len() != 33 {
            return Err(format!("expected 33 bytes, got {}", bytes.len()));
        }
        let mut key = [0u8; 33];
        key.copy_from_slice(&bytes);
        Ok(Self(key))
    }

    pub fn as_bytes(&self) -> &[u8; 33] {
        &self.0
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct KmsPublicKeyResponse {
    public_key: String,
}

#[derive(Debug, Clone)]
pub struct KmsClient {
    base_url: String,
    client: Client,
}

impl KmsClient {
    pub fn new(base_url: String) -> Self {
        Self {
            base_url,
            client: Client::new(),
        }
    }

    pub async fn get_public_key(&self) -> Result<KmsPublicKey, AppError> {
        let base = self.base_url.trim_end_matches('/');
        let url = format!("{base}/v0/public-key");
        debug!("Fetching KMS public key from {}", url);

        let response = self
            .client
            .get(url)
            .send()
            .await
            .map_err(|e| AppError::KmsUnavailable(e.to_string()))?;

        if !response.status().is_success() {
            return Err(AppError::KmsUnavailable(format!(
                "status {}",
                response.status()
            )));
        }

        let body: KmsPublicKeyResponse = response
            .json()
            .await
            .map_err(|e| AppError::KmsUnavailable(e.to_string()))?;

        KmsPublicKey::from_hex(&body.public_key).map_err(AppError::KmsInvalidKey)
    }
}
