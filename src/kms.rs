use alloy_primitives::{
    Address,
    hex::{self, encode_prefixed},
};
use alloy_signer::{Signature, SignerSync};
use alloy_signer_local::PrivateKeySigner;
use alloy_sol_types::{SolStruct, eip712_domain};
use k256::PublicKey;
use reqwest::{Client, header::AUTHORIZATION};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tracing::{debug, error, info};

use crate::types::{
    DelegateAuthorization, DelegateResponseProof, EIP_712_DOMAIN_VERSION,
    PROTOCOL_DELEGATE_EIP712_DOMAIN_NAME,
};
use crate::utils::strip_0x_prefix;

/// Errors returned by [`KmsClient`] operations.
#[derive(Debug, Error)]
pub enum Error {
    #[error("Failed to build KMS HTTP client: {0}")]
    ClientBuild(reqwest::Error),
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

/// Request body sent to `POST /v0/delegate` on the KMS.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct KmsDelegateRequestBody {
    ephemeral_pub_key: String,
    target_pub_key: String,
}

/// Response body received from `POST /v0/delegate` on the KMS.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct KmsDelegateResponse {
    pub encrypted_shared_secret: String,
    pub proof: String,
}

/// HTTP client for the KMS `POST /v0/delegate` endpoint.
///
/// Holds the KMS EC public key (used for ECIES encryption) and the expected
/// signer address (used to verify EIP-712 proofs on every delegate response).
#[derive(Clone)]
pub struct KmsClient {
    pub client: Client,
    pub base_url: String,
    pub public_key: PublicKey,
    pub kms_signer_address: Address,
}

impl KmsClient {
    /// Creates a new KMS client.
    ///
    /// `public_key` is the KMS EC public key fetched on-chain from NoxCompute.
    /// `kms_signer_address` is the Ethereum address whose EIP-712 signature must
    /// appear on every delegate response.
    pub fn new(
        base_url: String,
        public_key: PublicKey,
        kms_signer_address: Address,
    ) -> Result<Self, Error> {
        let client = Client::builder().build().map_err(Error::ClientBuild)?;

        info!(
            kms_public_key = %hex::encode(public_key.to_sec1_bytes()),
            kms_signer_address = %kms_signer_address,
            "KMS client initialized"
        );

        Ok(Self {
            client,
            base_url: base_url.trim_end_matches('/').to_string(),
            public_key,
            kms_signer_address,
        })
    }

    /// Calls `POST /v0/delegate` and returns the encrypted shared secret.
    ///
    /// Signs the request with an EIP-712 [`DelegateAuthorization`] and verifies
    /// the KMS response carries a valid [`DelegateResponseProof`] from the
    /// expected signer address.
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
            .await?;

        if let Err(err) = response.error_for_status_ref() {
            let status = response.status();
            let error_body = response.text().await?;
            error!("KMS delegate error {status}: {error_body}");
            return Err(Error::InvalidResponse(err.to_string()));
        }

        let data = response
            .json::<KmsDelegateResponse>()
            .await
            .map_err(|e| Error::InvalidResponse(e.to_string()))?;

        self.verify_delegate_response(&data, chain_id)?;

        Ok(data.encrypted_shared_secret)
    }

    /// Verifies the EIP-712 [`DelegateResponseProof`] in a KMS delegate response.
    ///
    /// Returns an error if the recovered signer does not match [`Self::kms_signer_address`].
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

        let signature_bytes = hex::decode(&response.proof)
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

    /// Builds and signs an EIP-712 [`DelegateAuthorization`] for a delegate request.
    ///
    /// Returns the hex-encoded signature to be sent as the `Authorization: Bearer` header.
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

        Ok(encode_prefixed(signature.as_bytes()))
    }
}
