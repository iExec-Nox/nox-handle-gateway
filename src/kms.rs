use alloy_primitives::hex;
use reqwest::Client;
use serde::Deserialize;
use thiserror::Error;
use tracing::debug;

#[derive(Debug, Error)]
pub enum Error {
    #[error("Failed to build HTTP client: {0}")]
    ClientBuild(reqwest::Error),
    #[error("Invalid KMS public key: {0}")]
    InvalidKey(String),
    #[error("Invalid KMS response: {0}")]
    InvalidResponse(String),
    #[error("KMS unavailable: {0}")]
    Unavailable(String),
}

impl From<reqwest::Error> for Error {
    fn from(err: reqwest::Error) -> Self {
        if err.is_status() {
            let status = err.status().map(|s| s.as_u16()).unwrap_or(0);
            Error::Unavailable(format!("HTTP {status}: {err}"))
        } else {
            Error::Unavailable(err.to_string())
        }
    }
}

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
        let client = Client::builder().build().map_err(Error::ClientBuild)?;
        let public_key = Self::get_public_key(&base_url, &client).await?;
        Ok(Self { public_key })
    }

    async fn get_public_key(base_url: &str, client: &Client) -> Result<KmsPublicKey, Error> {
        let base = base_url.trim_end_matches('/');
        let url = format!("{base}/v0/public-key");
        debug!("Fetching KMS public key from {url}");

        let response = client.get(&url).send().await?.error_for_status()?;

        let body: KmsPublicKeyResponse = response
            .json()
            .await
            .map_err(|e| Error::InvalidResponse(e.to_string()))?;

        Self::decode_public_key(&body.public_key)
    }

    fn decode_public_key(value: &str) -> Result<KmsPublicKey, Error> {
        let trimmed = value.strip_prefix("0x").unwrap_or(value);
        let bytes =
            hex::decode(trimmed).map_err(|e| Error::InvalidKey(format!("invalid hex: {e}")))?;
        if bytes.len() != 33 {
            return Err(Error::InvalidKey(format!(
                "expected 33 bytes, got {}",
                bytes.len()
            )));
        }
        let mut key = [0u8; 33];
        key.copy_from_slice(&bytes);
        Ok(key)
    }
}
