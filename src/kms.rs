use alloy_primitives::{Address, hex};
use alloy_signer::{Signature, SignerSync};
use alloy_signer_local::PrivateKeySigner;
use alloy_sol_types::{SolStruct, eip712_domain};
use k256::PublicKey;
use reqwest::{Client, header::AUTHORIZATION};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tracing::{debug, info};

use crate::types::{
    DelegateAuthorization, DelegateResponseProof, EIP_712_DOMAIN_VERSION,
    KMS_PUBLIC_KEY_EIP712_DOMAIN_NAME, PROTOCOL_DELEGATE_EIP712_DOMAIN_NAME, PublicKeyProof,
};
use crate::utils::{serialize_bytes, strip_0x_prefix};

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
    #[error("Invalid KMS response signature: {0}")]
    InvalidResponseSignature(String),
    #[error("KMS unavailable: {0}")]
    Unavailable(String),
    #[error("Signing error: {0}")]
    Signing(String),
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
struct KmsDelegateRequestBody {
    ephemeral_pub_key: String,
    target_pub_key: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct KmsDelegateResponse {
    pub encrypted_shared_secret: String,
    pub proof: String,
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

        let (public_key, kms_signer_address) =
            Self::parse_and_verify_public_key(&body.public_key, &body.proof, chain_id)?;

        info!(
            kms_public_key = %body.public_key,
            kms_signer_address = %kms_signer_address,
            "KMS public key verified"
        );

        Ok((public_key, kms_signer_address))
    }

    fn parse_and_verify_public_key(
        public_key_hex: &str,
        proof_hex: &str,
        chain_id: u32,
    ) -> Result<(PublicKey, Address), Error> {
        let public_key_raw = strip_0x_prefix(public_key_hex);

        let domain = eip712_domain! {
            name: KMS_PUBLIC_KEY_EIP712_DOMAIN_NAME,
            version: EIP_712_DOMAIN_VERSION,
            chain_id: u64::from(chain_id),
        };
        let proof_struct = PublicKeyProof {
            publicKey: public_key_raw.to_string(),
        };
        let signing_hash = proof_struct.eip712_signing_hash(&domain);

        let signature_bytes = hex::decode(strip_0x_prefix(proof_hex))
            .map_err(|e| Error::InvalidProof(format!("invalid hex: {e}")))?;
        let signature = Signature::from_raw(&signature_bytes)
            .map_err(|e| Error::InvalidProof(format!("invalid signature: {e}")))?;

        // TODO: Validate recovered address against a pre-configured or on-chain source.
        // Currently we only verify that recovery succeeds; address validation deferred to future PR.
        let signer_address = signature
            .recover_address_from_prehash(&signing_hash)
            .map_err(|e| Error::InvalidProof(format!("failed to recover address: {e}")))?;

        let public_key_bytes = hex::decode(public_key_raw)
            .map_err(|e| Error::InvalidKey(format!("invalid hex: {e}")))?;
        let public_key = PublicKey::from_sec1_bytes(&public_key_bytes)
            .map_err(|e| Error::InvalidKey(format!("invalid SEC1 public key: {e}")))?;

        Ok((public_key, signer_address))
    }

    pub async fn get_encrypted_shared_secret(
        &self,
        ephemeral_pub_key: &str,
        target_pub_key: &str,
        signer: &PrivateKeySigner,
        chain_id: u32,
    ) -> Result<String, Error> {
        let url = format!("{}/v0/delegate", self.base_url);

        let authorization =
            self.build_delegate_authorization(ephemeral_pub_key, target_pub_key, signer, chain_id)?;

        info!(
            ephemeral_pub_key = %ephemeral_pub_key,
            target_pub_key = %target_pub_key,
            "KMS delegate request (signed)"
        );

        let request_body = KmsDelegateRequestBody {
            ephemeral_pub_key: ephemeral_pub_key.to_string(),
            target_pub_key: target_pub_key.to_string(),
        };

        let response = self
            .client
            .post(&url)
            .header(AUTHORIZATION, format!("Bearer {authorization}"))
            .json(&request_body)
            .send()
            .await?
            .error_for_status()?;

        let data = response
            .json::<KmsDelegateResponse>()
            .await
            .map_err(|e| Error::InvalidResponse(e.to_string()))?;

        self.verify_delegate_response(&data, chain_id)?;

        Ok(data.encrypted_shared_secret)
    }

    fn verify_delegate_response(
        &self,
        response: &KmsDelegateResponse,
        chain_id: u32,
    ) -> Result<(), Error> {
        let response_struct = DelegateResponseProof {
            encryptedSharedSecret: strip_0x_prefix(&response.encrypted_shared_secret).to_string(),
        };

        let domain = eip712_domain! {
            name: PROTOCOL_DELEGATE_EIP712_DOMAIN_NAME,
            version: EIP_712_DOMAIN_VERSION,
            chain_id: u64::from(chain_id),
        };

        let signing_hash = response_struct.eip712_signing_hash(&domain);

        let signature_bytes = hex::decode(strip_0x_prefix(&response.proof))
            .map_err(|e| Error::InvalidResponseSignature(format!("invalid hex: {e}")))?;
        let proof = Signature::from_raw(&signature_bytes)
            .map_err(|e| Error::InvalidResponseSignature(format!("invalid proof: {e}")))?;
        let recovered = proof
            .recover_address_from_prehash(&signing_hash)
            .map_err(|e| Error::InvalidResponseSignature(format!("failed to recover: {e}")))?;

        if recovered != self.kms_signer_address {
            return Err(Error::InvalidResponseSignature(format!(
                "signer mismatch: expected {}, got {}",
                self.kms_signer_address, recovered
            )));
        }

        debug!("KMS delegate response signature verified");
        Ok(())
    }

    fn build_delegate_authorization(
        &self,
        ephemeral_pub_key: &str,
        target_pub_key: &str,
        signer: &PrivateKeySigner,
        chain_id: u32,
    ) -> Result<String, Error> {
        let auth = DelegateAuthorization {
            ephemeralPubKey: strip_0x_prefix(ephemeral_pub_key).to_string(),
            targetPubKey: strip_0x_prefix(target_pub_key).to_string(),
        };

        let domain = eip712_domain! {
            name: PROTOCOL_DELEGATE_EIP712_DOMAIN_NAME,
            version: EIP_712_DOMAIN_VERSION,
            chain_id: u64::from(chain_id),
        };

        let signature = signer
            .sign_typed_data_sync(&auth, &domain)
            .map_err(|e| Error::Signing(e.to_string()))?;

        Ok(serialize_bytes(&signature.as_bytes()))
    }
}
