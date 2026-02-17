use alloy_primitives::{Address, B256};
use alloy_provider::ProviderBuilder;
use alloy_sol_types::sol;
use k256::PublicKey;
use thiserror::Error;

sol! {
    #[sol(rpc)]
    contract NoxCompute {
        function isViewer(bytes32 handle, address viewer) external view returns (bool);
        function kmsPublicKey() external view returns (bytes memory);
    }
}

#[derive(Debug, Error)]
pub enum RpcError {
    #[error("RPC transport: {0}")]
    Transport(String),
    #[error("RPC call failed: {0}")]
    Call(String),
    #[error("Invalid KMS public key: {0}")]
    InvalidKey(String),
    #[error("Access denied: not a viewer")]
    AccessDenied,
}

#[derive(Clone)]
pub struct ChainClient {
    rpc_url: String,
    contract_address: Address,
}

impl ChainClient {
    pub fn new(rpc_url: &str, contract_address: Address) -> Result<Self, RpcError> {
        let rpc_url = rpc_url.trim();
        if rpc_url.is_empty() {
            return Err(RpcError::Transport("RPC URL is required".to_string()));
        }
        Ok(Self {
            rpc_url: rpc_url.to_string(),
            contract_address,
        })
    }

    pub async fn kms_public_key(&self) -> Result<PublicKey, RpcError> {
        let provider = ProviderBuilder::new()
            .connect(&self.rpc_url)
            .await
            .map_err(|e| RpcError::Transport(e.to_string()))?;
        let contract = NoxCompute::new(self.contract_address, &provider);
        let result = contract
            .kmsPublicKey()
            .call()
            .await
            .map_err(|e| RpcError::Call(e.to_string()))?;
        PublicKey::from_sec1_bytes(&result).map_err(|e| RpcError::InvalidKey(e.to_string()))
    }

    pub async fn check_access(&self, handle: B256, viewer: Address) -> Result<(), RpcError> {
        let provider = ProviderBuilder::new()
            .connect(&self.rpc_url)
            .await
            .map_err(|e| RpcError::Transport(e.to_string()))?;
        let contract = NoxCompute::new(self.contract_address, &provider);
        let is_viewer = contract
            .isViewer(handle, viewer)
            .call()
            .await
            .map_err(|e| RpcError::Call(e.to_string()))?;
        if is_viewer {
            Ok(())
        } else {
            Err(RpcError::AccessDenied)
        }
    }
}
