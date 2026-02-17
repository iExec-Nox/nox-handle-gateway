use alloy_primitives::{Address, B256};
use alloy_provider::RootProvider;
use alloy_sol_types::sol;
use k256::PublicKey;
use thiserror::Error;
use url::Url;

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
    contract: NoxCompute::NoxComputeInstance<RootProvider>,
}

impl ChainClient {
    pub fn new(rpc_url: &str, contract_address: Address) -> Result<Self, RpcError> {
        let rpc_url = rpc_url.trim();
        if rpc_url.is_empty() {
            return Err(RpcError::Transport("RPC URL is required".to_string()));
        }
        let url: Url = rpc_url
            .parse()
            .map_err(|e| RpcError::Transport(format!("invalid RPC URL: {e}")))?;
        let contract = NoxCompute::new(contract_address, RootProvider::new_http(url));
        Ok(Self { contract })
    }

    pub async fn kms_public_key(&self) -> Result<PublicKey, RpcError> {
        let result = self
            .contract
            .kmsPublicKey()
            .call()
            .await
            .map_err(|e| RpcError::Call(e.to_string()))?;
        PublicKey::from_sec1_bytes(&result).map_err(|e| RpcError::InvalidKey(e.to_string()))
    }

    pub async fn check_access(&self, handle: B256, viewer: Address) -> Result<(), RpcError> {
        let is_viewer = self
            .contract
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
