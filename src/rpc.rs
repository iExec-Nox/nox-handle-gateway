use alloy_primitives::{Address, B256};
use alloy_provider::RootProvider;
use alloy_sol_types::sol;
use k256::PublicKey;
use thiserror::Error;

sol! {
    #[sol(rpc)]
    interface INoxCompute {
        function isViewer(bytes32 handle, address viewer) external view returns (bool);
        function kmsPublicKey() external view returns (bytes memory);
    }

    #[sol(rpc)]
    interface IERC1271 {
        function isValidSignature(bytes32 hash, bytes calldata signature)
            external view returns (bytes4);
    }
}

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

#[derive(Clone)]
pub struct NoxClient {
    contract: INoxCompute::INoxComputeInstance<RootProvider>,
}

impl NoxClient {
    pub async fn new(rpc_url: &str, contract_address: Address) -> Result<Self, RpcError> {
        let trimmed_rpc_url = rpc_url.trim_end_matches('/');
        let provider = RootProvider::connect(trimmed_rpc_url)
            .await
            .map_err(|e| RpcError::ProviderError(e.to_string()))?;
        let contract = INoxCompute::new(contract_address, provider);
        Ok(Self { contract })
    }

    pub async fn kms_public_key(&self) -> Result<PublicKey, RpcError> {
        let result = self
            .contract
            .kmsPublicKey()
            .call()
            .await
            .map_err(RpcError::CallFailure)?;
        PublicKey::from_sec1_bytes(&result).map_err(|e| RpcError::InvalidKey(e.to_string()))
    }

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

    /// Verify an ERC-1271 signature on a Smart Account contract.
    pub async fn verify_erc1271(
        &self,
        hash: B256,
        signature: &[u8],
        address: Address,
    ) -> Result<(), RpcError> {
        use alloy_primitives::{Bytes, FixedBytes};

        const MAGIC_VALUE: FixedBytes<4> = FixedBytes([0x16, 0x26, 0xba, 0x7e]);

        let provider = self.contract.provider().clone();
        let contract = IERC1271::new(address, provider);

        let result = contract
            .isValidSignature(hash, Bytes::from(signature.to_vec()))
            .call()
            .await
            .map_err(|e| match e {
                alloy_contract::Error::TransportError(_) => RpcError::CallFailure(e),
                _ => RpcError::InvalidSignature,
            })?;

        if result == MAGIC_VALUE {
            Ok(())
        } else {
            Err(RpcError::InvalidSignature)
        }
    }
}
