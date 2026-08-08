//! Module implementing interactions with a NoxCompute Smart Contract instance.

use std::time::Duration;

use alloy::{
    primitives::{Address, B256, Bytes, FixedBytes},
    providers::RootProvider,
    rpc::client::RpcClient,
    sol,
};
use k256::PublicKey;
use reqwest::{Client, Url};
use thiserror::Error;
use tracing::error;

sol! {
    /// On-chain interface for ACL checks and KMS public key retrieval.
    #[sol(rpc)]
    interface INoxCompute {
        function isViewer(bytes32 handle, address viewer) external view returns (bool);
        function isPubliclyDecryptable(bytes32 handle) external view returns (bool);
        function kmsPublicKey() external view returns (bytes memory);
        function gateway() external view returns (address);
    }

    /// ERC-1271 standard interface for Smart Account signature verification.
    #[sol(rpc)]
    interface IERC1271 {
        function isValidSignature(bytes32 hash, bytes memory signature)
            external view returns (bytes4);
    }
}

/// Errors returned by [`NoxClient`] operations.
#[derive(Debug, Error)]
pub enum RpcError {
    #[error("ACL call failure: {0}")]
    AclCallFailure(String),
    #[error(transparent)]
    CallFailure(alloy::contract::Error),
    #[error("Invalid KMS public key: {0}")]
    InvalidKey(String),
    #[error("RPC provider error: {0}")]
    ProviderError(String),
}

/// Ethereum RPC client for on-chain reads against the NoxCompute contract.
///
/// Wraps an `INoxCompute` contract instance to verify ACL access and fetch the
/// KMS public key. Also provides ERC-1271 signature verification for Smart
/// Account callers via a separate `IERC1271` contract instance created on demand.
#[derive(Clone, Debug)]
pub struct NoxClient {
    contract: INoxCompute::INoxComputeInstance<RootProvider>,
}

impl NoxClient {
    /// Build a [`NoxClient`] connected to `rpc_url`.
    ///
    /// Connects to the Ethereum node at `rpc_url` and wraps the `INoxCompute`
    /// contract at `contract_address`. Returns [`RpcError::ProviderError`] if
    /// the connection fails.
    pub async fn new(
        rpc_url: &str,
        call_timeout: Duration,
        connect_timeout: Duration,
        contract_address: Address,
    ) -> Result<Self, RpcError> {
        let rpc_url = Url::parse(rpc_url.trim_end_matches('/'))
            .map_err(|e| RpcError::ProviderError(e.to_string()))?;
        let client = Client::builder()
            .connect_timeout(connect_timeout)
            .timeout(call_timeout)
            .build()
            .map_err(|e| RpcError::ProviderError(e.to_string()))?;
        let rpc_client = RpcClient::new_http_with_client(client, rpc_url);
        let provider = RootProvider::new(rpc_client);
        let contract = INoxCompute::new(contract_address, provider);
        Ok(Self { contract })
    }

    /// Fetch the KMS public key from the NoxCompute contract.
    ///
    /// Calls `kmsPublicKey()` on-chain and parses the returned bytes as a
    /// compressed SEC1 public key. Called once at startup to initialise
    /// [`KmsClient`](crate::kms::KmsClient).
    pub async fn kms_public_key(&self) -> Result<PublicKey, RpcError> {
        let result = self
            .contract
            .kmsPublicKey()
            .call()
            .await
            .map_err(RpcError::CallFailure)?;
        PublicKey::from_sec1_bytes(&result).map_err(|e| RpcError::InvalidKey(e.to_string()))
    }

    /// Fetch the on-chain gateway address from the NoxCompute contract.
    ///
    /// Calls `gateway()` on-chain. Used at startup to cross-check the configured
    /// `wallet_key` derives the same address as registered on-chain.
    pub async fn gateway_address(&self) -> Result<Address, RpcError> {
        self.contract
            .gateway()
            .call()
            .await
            .map_err(RpcError::CallFailure)
    }

    /// Verify that `viewer` has read access to `handle` on-chain.
    ///
    /// Calls `isViewer(handle, viewer)` on the NoxCompute contract.
    /// Returns `Ok(true)` when access is granted, `Ok(false)` when it is not.
    /// Returns [`RpcError::AclCallFailure`] if the RPC node is unreachable or
    /// the call fails for any transport reason.
    pub async fn check_access(&self, handle: B256, viewer: Address) -> Result<bool, RpcError> {
        let is_viewer = self
            .contract
            .isViewer(handle, viewer)
            .call()
            .await
            .inspect_err(|e| {
                error!("isViewer RPC call failed for handle {handle} and viewer {viewer}: {e}")
            })
            .map_err(|_| {
                RpcError::AclCallFailure(format!(
                    "isViewer RPC call failed for handle {handle} and viewer {viewer}"
                ))
            })?;
        Ok(is_viewer)
    }

    /// Verify that `handle` is marked as publicly decryptable on-chain.
    ///
    /// Calls `isPubliclyDecryptable(handle)` on the NoxCompute contract.
    /// Returns `Ok(true)` when the handle is publicly decryptable, `Ok(false)` when it is not.
    /// Returns [`RpcError::AclCallFailure`] if the RPC node is unreachable or
    /// the call fails for any transport reason.
    pub async fn is_publicly_decryptable(&self, handle: B256) -> Result<bool, RpcError> {
        let is_public = self
            .contract
            .isPubliclyDecryptable(handle)
            .call()
            .await
            .inspect_err(|e| {
                error!("isPubliclyDecryptable RPC call failed for handle {handle}: {e}")
            })
            .map_err(|_| {
                RpcError::AclCallFailure(format!(
                    "isPubliclyDecryptable RPC call failed for handle {handle}"
                ))
            })?;
        Ok(is_public)
    }

    /// Verify an ERC-1271 signature against a Smart Account contract at `address`.
    ///
    /// Calls `isValidSignature(hash, signature)` on the contract deployed at `address`.
    /// Returns `Ok(true)` if the contract returns the ERC-1271 magic value (`0x1626ba7e`).
    /// Returns `Ok(false)` if the contract returns any other value.
    /// Returns [`RpcError::AclCallFailure`] if the call itself fails
    /// for any reason (transport error, revert, ABI mismatch, contract not deployed, …).
    pub async fn verify_erc1271(
        &self,
        hash: B256,
        signature: &[u8],
        address: Address,
    ) -> Result<bool, RpcError> {
        const MAGIC_VALUE: FixedBytes<4> = FixedBytes([0x16, 0x26, 0xba, 0x7e]);

        let provider = self.contract.provider().clone();
        let contract = IERC1271::new(address, provider);

        match contract
            .isValidSignature(hash, Bytes::from(signature.to_vec()))
            .call()
            .await
        {
            Ok(MAGIC_VALUE) => Ok(true), // valid ERC-1271 signature
            Ok(_) => Ok(false),          // call succeeded but signature is invalid
            Err(alloy::contract::Error::ZeroData(_, _)) => Ok(false), // when called address is not an ERC-1271 contract
            Err(alloy::contract::Error::TransportError(
                alloy::transports::RpcError::ErrorResp(_),
            )) => Ok(false), // when called contract reverts (e.g. due to invalid signature)
            Err(e) => {
                error!("ERC-1271 isValidSignature RPC call failed for address {address}: {e}");
                Err(RpcError::AclCallFailure(format!(
                    "ERC-1271 isValidSignature RPC call failed for address {address}"
                )))
            }
        }
    }
}
