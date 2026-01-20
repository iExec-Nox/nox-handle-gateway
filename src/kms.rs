use alloy_primitives::hex;
use anyhow::{Error, anyhow};
use reqwest::Client;
use serde::Deserialize;
use tracing::{debug, error};

use crate::error::AppError;

pub type KmsPublicKey = [u8; 33];

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct KmsPublicKeyResponse {
    public_key: String,
}

pub struct KmsClient {
    pub public_key: KmsPublicKey,
}

impl KmsClient {
    pub async fn new(base_url: String) -> Result<Self, Error> {
        let client = Client::builder().build().map_err(|e| {
            error!("Failed to build HTTP client");
            anyhow!(e)
        })?;
        let public_key = Self::get_public_key(&base_url, &client)
            .await
            .map_err(|e| {
                error!("Failed to fetch KMS public key: {e}");
                anyhow!(e)
            })?;
        Ok(Self { public_key })
    }

    async fn get_public_key(base_url: &str, client: &Client) -> Result<KmsPublicKey, AppError> {
        let base = base_url.trim_end_matches('/');
        let url = format!("{base}/v0/public-key");
        debug!("Fetching KMS public key from {}", url);

        let response = client
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
            .map_err(|e| AppError::KmsInvalidResponse(e.to_string()))?;

        Self::decode_public_key(&body.public_key).map_err(AppError::KmsInvalidKey)
    }

    fn decode_public_key(value: &str) -> Result<KmsPublicKey, String> {
        let trimmed = value.strip_prefix("0x").unwrap_or(value);
        let bytes = hex::decode(trimmed).map_err(|e| format!("invalid hex: {e}"))?;
        if bytes.len() != 33 {
            return Err(format!("expected 33 bytes, got {}", bytes.len()));
        }
        let mut key = [0u8; 33];
        key.copy_from_slice(&bytes);
        Ok(key)
    }
}
