use alloy_primitives::{Address, B256, Bytes, FixedBytes};
use alloy_provider::RootProvider;
use alloy_sol_types::sol;
use k256::PublicKey;
use thiserror::Error;

sol! {
    /// On-chain interface for ACL checks and KMS public key retrieval.
    #[sol(rpc)]
    interface INoxCompute {
        function isViewer(bytes32 handle, address viewer) external view returns (bool);
        function kmsPublicKey() external view returns (bytes memory);
    }

    /// ERC-1271 standard interface for Smart Account signature verification.
    #[sol(rpc)]
    interface IERC1271 {
        function isValidSignature(bytes32 hash, bytes calldata signature)
            external view returns (bytes4);
    }
}

/// Errors returned by [`NoxClient`] operations.
#[derive(Debug, Error)]
pub enum RpcError {
    #[error("Access denied: not a viewer")]
    AccessDenied,
    #[error("RPC call failed: {0}")]
    CallFailure(#[from] alloy_contract::Error),
    #[error("ERC-1271: invalid signature")]
    InvalidSignature,
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
#[derive(Clone)]
pub struct NoxClient {
    contract: INoxCompute::INoxComputeInstance<RootProvider>,
}

impl NoxClient {
    /// Build a [`NoxClient`] connected to `rpc_url`.
    ///
    /// Connects to the Ethereum node at `rpc_url` and wraps the `INoxCompute`
    /// contract at `contract_address`. Returns [`RpcError::ProviderError`] if
    /// the connection fails.
    pub async fn new(rpc_url: &str, contract_address: Address) -> Result<Self, RpcError> {
        let trimmed_rpc_url = rpc_url.trim_end_matches('/');
        let provider = RootProvider::connect(trimmed_rpc_url)
            .await
            .map_err(|e| RpcError::ProviderError(e.to_string()))?;
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

    /// Verify that `viewer` has read access to `handle` on-chain.
    ///
    /// Calls `isViewer(handle, viewer)` on the NoxCompute contract. Returns
    /// `Ok(())` when access is granted, [`RpcError::AccessDenied`] when it is
    /// not.
    pub async fn check_access(&self, handle: B256, viewer: Address) -> Result<(), RpcError> {
        let is_viewer = self
            .contract
            .isViewer(handle, viewer)
            .call()
            .await
            .map_err(RpcError::CallFailure)?;
        if is_viewer {
            Ok(())
        } else {
            Err(RpcError::AccessDenied)
        }
    }

    /// Verify an ERC-1271 signature against a Smart Account contract at `address`.
    ///
    /// Calls `isValidSignature(hash, signature)` on the contract deployed at
    /// `address`. Returns `Ok(())` if the contract returns the ERC-1271 magic
    /// value (`0x1626ba7e`). Returns [`RpcError::InvalidSignature`] if the
    /// contract returns any other value or reverts. Returns
    /// [`RpcError::CallFailure`] only for genuine network-level transport
    /// failures — contract execution errors (reverts, wrong return value) are
    /// always treated as signature failures, not infrastructure errors.
    pub async fn verify_erc1271(
        &self,
        hash: B256,
        signature: &[u8],
        address: Address,
    ) -> Result<(), RpcError> {
        const MAGIC_VALUE: FixedBytes<4> = FixedBytes([0x16, 0x26, 0xba, 0x7e]);

        let provider = self.contract.provider().clone();
        let contract = IERC1271::new(address, provider);

        let result = contract
            .isValidSignature(hash, Bytes::from(signature.to_vec()))
            .call()
            .await
            .map_err(|e| match &e {
                alloy_contract::Error::TransportError(te) if te.is_transport_error() => {
                    RpcError::CallFailure(e)
                }
                _ => RpcError::InvalidSignature,
            })?;

        if result == MAGIC_VALUE {
            Ok(())
        } else {
            Err(RpcError::InvalidSignature)
        }
    }
}
