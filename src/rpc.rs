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
}

#[derive(Debug, Error)]
pub enum RpcError {
    #[error("Access denied: not a viewer")]
    AccessDenied,
    #[error("RPC call failed: {0}")]
    CallFailure(String),
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
            .map_err(|e| RpcError::CallFailure(e.to_string()))?;
        PublicKey::from_sec1_bytes(&result).map_err(|e| RpcError::InvalidKey(e.to_string()))
    }

    pub async fn check_access(&self, handle: B256, viewer: Address) -> Result<(), RpcError> {
        let is_viewer = self
            .contract
            .isViewer(handle, viewer)
            .call()
            .await
            .map_err(|e| RpcError::CallFailure(e.to_string()))?;
        if is_viewer {
            Ok(())
        } else {
            Err(RpcError::AccessDenied)
        }
    }
}
