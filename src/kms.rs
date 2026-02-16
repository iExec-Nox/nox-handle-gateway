use alloy_primitives::{Address, hex};
use alloy_signer::{Signature, SignerSync};
use alloy_signer_local::PrivateKeySigner;
use alloy_sol_types::{SolCall, SolStruct, eip712_domain, sol};
use k256::PublicKey;
use reqwest::{Client, header::AUTHORIZATION};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tracing::{debug, info};

use crate::rpc::{self, RpcError};
use crate::types::{
    DelegateAuthorization, DelegateResponseProof, EIP_712_DOMAIN_VERSION,
    PROTOCOL_DELEGATE_EIP712_DOMAIN_NAME,
};
use crate::utils::{serialize_bytes, strip_0x_prefix};

sol! {
    function kmsPublicKey() external view returns (bytes memory);
}

#[derive(Debug, Error)]
pub enum Error {
    #[error("Failed to build KMS HTTP client: {0}")]
    ClientBuild(reqwest::Error),
    #[error("Invalid KMS public key: {0}")]
    InvalidKey(String),
    #[error("Invalid KMS response: {0}")]
    InvalidResponse(String),
    #[error("Invalid KMS response signature: {0}")]
    InvalidResponseSignature(String),
    #[error("KMS unavailable: {0}")]
    Unavailable(String),
    #[error("RPC call failed: {0}")]
    Rpc(#[from] RpcError),
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

#[derive(Clone)]
pub struct KmsClient {
    pub client: Client,
    pub base_url: String,
    pub public_key: PublicKey,
    pub kms_signer_address: Address,
}

impl KmsClient {
    pub async fn new(
        base_url: String,
        rpc_url: &str,
        contract_address: Address,
        kms_signer_address: Address,
    ) -> Result<Self, Error> {
        let client = Client::builder().build().map_err(Error::ClientBuild)?;
        let public_key =
            Self::fetch_public_key_from_chain(rpc_url, contract_address, &client).await?;

        info!(
            kms_public_key = %hex::encode(public_key.to_sec1_bytes()),
            kms_signer_address = %kms_signer_address,
            "KMS public key fetched from chain"
        );

        Ok(Self {
            client,
            base_url: base_url.trim_end_matches('/').to_string(),
            public_key,
            kms_signer_address,
        })
    }

    async fn fetch_public_key_from_chain(
        rpc_url: &str,
        contract_address: Address,
        client: &Client,
    ) -> Result<PublicKey, Error> {
        let call = kmsPublicKeyCall {};
        let contract = contract_address.to_string();

        debug!("Fetching KMS public key from chain via eth_call to {contract}");

        let result = rpc::eth_call(client, rpc_url, &contract, &call.abi_encode()).await?;

        let result_bytes = hex::decode(strip_0x_prefix(&result))
            .map_err(|e| Error::InvalidKey(format!("invalid hex in RPC result: {e}")))?;

        let return_data = kmsPublicKeyCall::abi_decode_returns(&result_bytes)
            .map_err(|e| Error::InvalidKey(format!("ABI decode failed: {e}")))?;

        PublicKey::from_sec1_bytes(&return_data.0)
            .map_err(|e| Error::InvalidKey(format!("invalid SEC1 public key: {e}")))
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
