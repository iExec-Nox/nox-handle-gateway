use alloy_primitives::{Address, hex};
use alloy_signer::Signature;
use alloy_sol_types::{SolStruct, eip712_domain};
use k256::PublicKey;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tracing::{debug, info};

use crate::types::{KMS_PUBLIC_KEY_EIP712_DOMAIN_NAME, PublicKeyProof};

#[derive(Debug, Error)]
pub enum Error {
    #[error("Failed to build KMS HTTP client: {0}")]
    ClientBuild(reqwest::Error),
    #[error("Invalid KMS public key: {0}")]
    InvalidKey(String),
    #[error("Invalid KMS proof: {0}")]
    InvalidProof(String),
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

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct KmsDelegateRequest {
    ephemeral_pub_key: String,
    target_pub_key: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct KmsDelegateResponse {
    pub encrypted_shared_secret: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct KmsPublicKeyResponse {
    public_key: String,
    proof: String,
}

#[derive(Clone)]
pub struct KmsClient {
    pub client: Client,
    pub base_url: String,
    pub public_key: PublicKey,
    pub kms_signer_address: Address,
}

impl KmsClient {
    pub async fn new(base_url: String, chain_id: u32) -> Result<Self, Error> {
        let client = Client::builder().build().map_err(Error::ClientBuild)?;
        let (public_key, kms_signer_address) =
            Self::fetch_and_verify_public_key(&base_url, &client, chain_id).await?;
        Ok(Self {
            client,
            base_url: base_url.trim_end_matches('/').to_string(),
            public_key,
            kms_signer_address,
        })
    }

    async fn fetch_and_verify_public_key(
        base_url: &str,
        client: &Client,
        chain_id: u32,
    ) -> Result<(PublicKey, Address), Error> {
        let base = base_url.trim_end_matches('/');
        let url = format!("{base}/v0/public-key");
        debug!("Fetching KMS public key from {url}");

        let response = client.get(&url).send().await?.error_for_status()?;

        let body: KmsPublicKeyResponse = response
            .json()
            .await
            .map_err(|e| Error::InvalidResponse(e.to_string()))?;

        let public_key = Self::decode_public_key(&body.public_key)?;
        let kms_signer_address =
            Self::verify_public_key_proof(&body.public_key, &body.proof, chain_id)?;

        info!(
            kms_public_key = %body.public_key,
            kms_signer_address = %kms_signer_address,
            "KMS public key verified"
        );

        Ok((public_key, kms_signer_address))
    }

    fn verify_public_key_proof(
        public_key: &str,
        proof: &str,
        chain_id: u32,
    ) -> Result<Address, Error> {
        let domain = eip712_domain! {
            name: KMS_PUBLIC_KEY_EIP712_DOMAIN_NAME,
            version: "1",
            chain_id: u64::from(chain_id),
        };

        let public_key_without_prefix = public_key.strip_prefix("0x").unwrap_or(public_key);
        let proof_struct = PublicKeyProof {
            publicKey: public_key_without_prefix.to_string(),
        };

        let signing_hash = proof_struct.eip712_signing_hash(&domain);
        let signature_bytes = hex::decode(proof.strip_prefix("0x").unwrap_or(proof))
            .map_err(|e| Error::InvalidProof(format!("invalid hex: {e}")))?;
        let signature = Signature::from_raw(&signature_bytes)
            .map_err(|e| Error::InvalidProof(format!("invalid signature: {e}")))?;

        let recovered = signature
            .recover_address_from_prehash(&signing_hash)
            .map_err(|e| Error::InvalidProof(format!("failed to recover address: {e}")))?;
        Ok(recovered)
    }

    fn decode_public_key(value: &str) -> Result<PublicKey, Error> {
        let trimmed = value.strip_prefix("0x").unwrap_or(value);
        let bytes =
            hex::decode(trimmed).map_err(|e| Error::InvalidKey(format!("invalid hex: {e}")))?;
        PublicKey::from_sec1_bytes(&bytes)
            .map_err(|e| Error::InvalidKey(format!("invalid SEC1 public key: {e}")))
    }

    pub async fn get_encrypted_shared_secret(
        &self,
        handle_public_key: String,
        rsa_public_key: String,
    ) -> Result<String, Error> {
        let url = format!("{}/v0/delegate", self.base_url);
        info!(
            ephemeral_pub_key = handle_public_key,
            target_pub_key = rsa_public_key,
            "KMS delegate request"
        );
        let request_body = KmsDelegateRequest {
            ephemeral_pub_key: handle_public_key,
            target_pub_key: rsa_public_key,
        };
        let response = self
            .client
            .post(&url)
            .json(&request_body)
            .send()
            .await?
            .error_for_status()?;
        let data = response
            .json::<KmsDelegateResponse>()
            .await
            .map_err(|e| Error::InvalidResponse(e.to_string()))?;
        Ok(data.encrypted_shared_secret)
    }
}
